use clap::{Parser, Subcommand};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::signal;
use tracing_subscriber::EnvFilter;

use cyphera_secure_send::api::management::{self, ManagementState};
use cyphera_secure_send::api::{public_router, ratelimit::Limiters};
use cyphera_secure_send::audit::{AuditEvent, AuditEventType};
use cyphera_secure_send::config::Settings;

#[derive(Parser)]
#[command(
    name = "cyphera-secure-send",
    version,
    about = "One-time secret handoff for controlled environments."
)]
struct Cli {
    /// Path to a YAML configuration file.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the service (the default).
    Serve,
    /// Load and validate configuration, then print the effective settings.
    CheckConfig,
}

fn main() {
    let cli = Cli::parse();
    let settings = match Settings::load(cli.config.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };

    match cli.command.unwrap_or(Command::Serve) {
        Command::CheckConfig => match serde_json::to_string_pretty(&settings) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("could not render configuration: {e}");
                std::process::exit(2);
            }
        },
        Command::Serve => {
            if let Err(e) = serve(settings) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}

fn serve(settings: Settings) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .json()
        .init();

    let prometheus = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| format!("metrics: {e}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    runtime.block_on(async move {
        let state = cyphera_secure_send::build_state(settings, None).map_err(|e| e.to_string())?;
        let ready = Arc::new(AtomicBool::new(false));

        let public_addr = state.settings.server.bind;
        let management_addr = state.settings.server.management_bind;
        let shutdown_timeout = Duration::from_secs(state.settings.server.shutdown_timeout_seconds);
        let tls = state.settings.server.tls.clone();

        let mgmt_state = Arc::new(ManagementState {
            app: state.clone(),
            ready: ready.clone(),
            prometheus,
        });
        let mgmt_router = management::router(mgmt_state);
        let mgmt_listener = tokio::net::TcpListener::bind(management_addr)
            .await
            .map_err(|e| format!("bind management listener {management_addr}: {e}"))?;

        let handle = axum_server::Handle::new();
        let app = public_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();

        let public_task = {
            let handle = handle.clone();
            match (tls.cert_path, tls.key_path) {
                (Some(cert), Some(key)) => {
                    let tls_config =
                        axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                            .await
                            .map_err(|e| format!("tls: {e}"))?;
                    tokio::spawn(async move {
                        axum_server::bind_rustls(public_addr, tls_config)
                            .handle(handle)
                            .serve(app)
                            .await
                    })
                }
                _ => tokio::spawn(async move {
                    axum_server::bind(public_addr)
                        .handle(handle)
                        .serve(app)
                        .await
                }),
            }
        };

        let mgmt_task = tokio::spawn(async move { axum::serve(mgmt_listener, mgmt_router).await });

        let maintenance = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Limiters::MAINTENANCE_INTERVAL);
                loop {
                    tick.tick().await;
                    state.limiters.retain_recent();
                }
            })
        };

        let bound = handle
            .listening()
            .await
            .ok_or_else(|| format!("public listener {public_addr} did not start"))?;
        ready.store(true, Ordering::SeqCst);
        state
            .audit
            .emit(AuditEvent::success(AuditEventType::ServerStarted));
        tracing::info!(public = %bound, management = %management_addr, "listening");

        shutdown_signal().await;
        ready.store(false, Ordering::SeqCst);
        let stats = state.service.store().stats();
        let mut event = AuditEvent::success(AuditEventType::ServerStopping);
        event.active_messages = Some(stats.active_messages);
        state.audit.emit(event);
        tracing::info!(
            active_messages = stats.active_messages,
            "shutting down; pending messages are discarded"
        );

        handle.graceful_shutdown(Some(shutdown_timeout));
        let _ = public_task.await;
        maintenance.abort();
        mgmt_task.abort();
        Ok::<(), String>(())
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
