//! The interface, embedded at build time from `web/dist`. The three page
//! routes all serve the shell; the client reads the path and the fragment.

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rust_embed::Embed;

use super::SharedState;

#[derive(Embed)]
#[folder = "web/dist/"]
#[include = "*.html"]
#[include = "assets/*"]
struct WebAssets;

fn file(path: &str) -> Option<Response> {
    let content = WebAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut res = content.data.into_owned().into_response();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        res.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    Some(res)
}

async fn shell() -> Response {
    match file("index.html") {
        Some(mut res) => {
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            res
        }
        None => (StatusCode::INTERNAL_SERVER_ERROR, "interface not built").into_response(),
    }
}

async fn asset(Path(path): Path<String>) -> Response {
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    file(&format!("assets/{path}")).unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

pub async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(shell))
        .route("/m/{id}", get(shell))
        .route("/r/{id}", get(shell))
        .route("/assets/{*path}", get(asset))
}
