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
        let state = cyphera_secure_send::build_state(settings, None)
            .await
            .map_err(|e| e.to_string())?;
        let ready = Arc::new(AtomicBool::new(false));

        let public_addr = state.settings.server.bind;
        let management_addr = state.settings.server.management_bind;
        let shutdown_timeout = Duration::from_secs(state.settings.server.shutdown_timeout_seconds);
        let tls = state.settings.server.tls.clone();

        let mgmt_state = Arc::new(ManagementState::new(
            state.clone(),
            ready.clone(),
            prometheus,
        ));
        let mgmt_router = management::router(mgmt_state);
        let mgmt_listener = tokio::net::TcpListener::bind(management_addr)
            .await
            .map_err(|e| format!("bind management listener {management_addr}: {e}"))?;

        let handle = axum_server::Handle::new();
        let app = public_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let request_timeout = Duration::from_secs(state.settings.server.request_timeout_seconds);

        // A connection that opens and sends nothing, or trickles its headers,
        // is holding a slot for no one. The protocol layer drops it at the
        // same timeout the request body gets; and a multiplexed connection
        // gets a modest number of streams, since each is a request's worth
        // of buffering.
        fn bound_connections(
            builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
            request_timeout: Duration,
        ) {
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(request_timeout);
            builder
                .http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(32);
        }

        let mut public_task = {
            let handle = handle.clone();
            match (tls.cert_path, tls.key_path) {
                (Some(cert), Some(key)) => {
                    let tls_config =
                        axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                            .await
                            .map_err(|e| format!("tls: {e}"))?;
                    let mut server = axum_server::bind_rustls(public_addr, tls_config);
                    bound_connections(server.http_builder(), request_timeout);
                    tokio::spawn(async move { server.handle(handle).serve(app).await })
                }
                _ => {
                    let mut server = axum_server::bind(public_addr);
                    bound_connections(server.http_builder(), request_timeout);
                    tokio::spawn(async move { server.handle(handle).serve(app).await })
                }
            }
        };

        let mut mgmt_task =
            tokio::spawn(async move { axum::serve(mgmt_listener, mgmt_router).await });

        let maintenance = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Limiters::MAINTENANCE_INTERVAL);
                loop {
                    tick.tick().await;
                    state.limiters.retain_recent();
                    // Expiry is settled as a side effect of traffic; on a
                    // quiet server nothing else would settle it, and an
                    // expired message should be audited when it expires,
                    // not when someone next asks for statistics.
                    let _ = state.service.store().stats().await;
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

        // A listener that dies is a process that should die with it, not one
        // that keeps answering the readiness probe while serving nothing.
        tokio::select! {
            _ = shutdown_signal() => {}
            exited = &mut public_task => {
                return Err(format!("public listener stopped unexpectedly: {exited:?}"));
            }
            exited = &mut mgmt_task => {
                return Err(format!("management listener stopped unexpectedly: {exited:?}"));
            }
        }
        ready.store(false, Ordering::SeqCst);
        let active = state
            .service
            .store()
            .stats()
            .await
            .ok()
            .map(|s| s.active_messages);
        let mut event = AuditEvent::success(AuditEventType::ServerStopping);
        event.active_messages = active;
        state.audit.emit(event);
        tracing::info!(active_messages = ?active, "shutting down");

        handle.graceful_shutdown(Some(shutdown_timeout));
        let _ = public_task.await;
        maintenance.abort();
        mgmt_task.abort();
        // The stopping event and whatever preceded it are queued for the
        // writer; give it a moment to land them before the process ends.
        let audit = state.audit.clone();
        let _ = tokio::task::spawn_blocking(move || audit.flush(Duration::from_secs(5))).await;
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
