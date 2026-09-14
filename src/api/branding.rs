//! Branding and the non-secret settings the interface needs. Logo and favicon
//! are read once at startup from operator-supplied paths and served from
//! memory; nothing else on disk is reachable.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::path::Path;

use super::SharedState;
use crate::config::{BrandColors, BrandingSettings};

const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct Asset {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct BrandingAssets {
    pub logo: Option<Asset>,
    pub favicon: Option<Asset>,
}

#[derive(Debug, thiserror::Error)]
pub enum AssetError {
    #[error("branding asset {0}: unsupported file type (svg, png, jpg, webp, ico)")]
    Type(String),
    #[error("branding asset {0}: {1}")]
    Read(String, std::io::Error),
    #[error("branding asset {0}: larger than 2 MiB")]
    Size(String),
}

fn content_type_for(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("svg") => Some("image/svg+xml"),
        Some("png") => Some("image/png"),
        Some("jpg") | Some("jpeg") => Some("image/jpeg"),
        Some("webp") => Some("image/webp"),
        Some("ico") => Some("image/x-icon"),
        _ => None,
    }
}

fn load(path: &Path) -> Result<Asset, AssetError> {
    let shown = path.display().to_string();
    let content_type = content_type_for(path).ok_or_else(|| AssetError::Type(shown.clone()))?;
    let meta = std::fs::metadata(path).map_err(|e| AssetError::Read(shown.clone(), e))?;
    if meta.len() > MAX_ASSET_BYTES {
        return Err(AssetError::Size(shown));
    }
    let bytes = std::fs::read(path).map_err(|e| AssetError::Read(shown, e))?;
    Ok(Asset {
        content_type,
        bytes,
    })
}

impl BrandingAssets {
    pub fn load(settings: &BrandingSettings) -> Result<Self, AssetError> {
        Ok(Self {
            logo: settings.logo_path.as_deref().map(load).transpose()?,
            favicon: settings.favicon_path.as_deref().map(load).transpose()?,
        })
    }
}

fn serve(asset: &Option<Asset>) -> Response {
    match asset {
        Some(a) => {
            let mut res = a.bytes.clone().into_response();
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(a.content_type),
            );
            res
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn logo(State(state): State<SharedState>) -> Response {
    serve(&state.branding.logo)
}

pub async fn favicon(State(state): State<SharedState>) -> Response {
    serve(&state.branding.favicon)
}

#[derive(Serialize)]
pub struct UiConfig {
    pub product_name: String,
    pub company_name: String,
    pub tagline: String,
    pub support_url: String,
    pub footer_text: String,
    pub show_powered_by: bool,
    pub has_logo: bool,
    pub has_favicon: bool,
    pub colors: BrandColors,
    pub ttl_options_seconds: Vec<u64>,
    pub default_ttl_seconds: u64,
    pub max_plaintext_bytes: usize,
    pub kdf_iterations: u32,
    pub max_failed_proofs: u32,
    pub auth_mode: crate::config::AuthMode,
    pub version: &'static str,
}

pub async fn ui_config(State(state): State<SharedState>) -> Json<UiConfig> {
    let s = &state.settings;
    let b = &s.branding;
    Json(UiConfig {
        product_name: b.product_name.clone(),
        company_name: b.company_name.clone(),
        tagline: b.tagline.clone(),
        support_url: b.support_url.clone(),
        footer_text: b.footer_text.clone(),
        show_powered_by: b.show_powered_by,
        has_logo: state.branding.logo.is_some(),
        has_favicon: state.branding.favicon.is_some(),
        colors: b.colors.clone(),
        ttl_options_seconds: s.messages.ttl_options_seconds.clone(),
        default_ttl_seconds: s.messages.default_ttl_seconds,
        max_plaintext_bytes: s.messages.max_plaintext_bytes,
        kdf_iterations: s.messages.kdf.recommended_iterations,
        max_failed_proofs: s.messages.max_failed_proofs,
        auth_mode: s.auth.mode,
        version: env!("CARGO_PKG_VERSION"),
    })
}
