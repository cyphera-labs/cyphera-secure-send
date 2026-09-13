//! Configuration: defaults, then an optional YAML file, then environment
//! variables. Every key can be set as `CYPHERA_SECURESEND__SECTION__KEY`.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const ENV_PREFIX: &str = "CYPHERA_SECURESEND";
pub const ENV_CONFIG_PATH: &str = "CYPHERA_SECURESEND_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "cyphera-secure-send.yaml";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read configuration: {0}")]
    Load(#[from] config::ConfigError),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub server: ServerSettings,
    pub messages: MessageSettings,
    pub rate_limits: RateLimitSettings,
    pub storage: StorageSettings,
    pub audit: AuditSettings,
    pub auth: AuthSettings,
    pub branding: BrandingSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Address the public listener binds.
    pub bind: SocketAddr,
    /// Address the management listener binds (health, readiness, metrics).
    /// Keep it off the public network.
    pub management_bind: SocketAddr,
    /// Networks whose `X-Forwarded-For` is trusted. Empty means the peer
    /// address is always the client address.
    pub trusted_proxies: Vec<IpNet>,
    /// Emit `Strict-Transport-Security`. Enable only when the service is
    /// reached over HTTPS, in-process or via a proxy.
    pub hsts: bool,
    /// Seconds to let in-flight requests finish on shutdown.
    pub shutdown_timeout_seconds: u64,
    pub tls: TlsSettings,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSettings {
    /// PEM certificate chain. When both paths are set, the public listener
    /// serves TLS in-process.
    pub cert_path: Option<PathBuf>,
    /// PEM private key.
    pub key_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MessageSettings {
    /// Choices offered in the interface, in seconds.
    pub ttl_options_seconds: Vec<u64>,
    pub default_ttl_seconds: u64,
    /// Hard ceiling accepted by the API regardless of the options above.
    pub max_ttl_seconds: u64,
    pub min_ttl_seconds: u64,
    /// Largest plaintext the interface will encrypt; also bounds the
    /// ciphertext the API accepts.
    pub max_plaintext_bytes: usize,
    /// Total bytes of messages held in memory before eviction starts.
    pub memory_budget_bytes: u64,
    /// Wrong proofs tolerated before the message is destroyed.
    pub max_failed_proofs: u32,
    pub kdf: KdfSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KdfSettings {
    /// What the interface uses when creating a message.
    pub recommended_iterations: u32,
    /// Bounds enforced on what the API will store.
    pub min_iterations: u32,
    pub max_iterations: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSettings {
    pub create_per_minute: u32,
    pub consume_per_minute: u32,
    pub revoke_per_minute: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageSettings {
    pub backend: StorageBackend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Memory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditSettings {
    pub sink: AuditSinkKind,
    pub include_client_ip: bool,
    pub include_user_agent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSinkKind {
    /// One JSON object per line on standard output. Application logs go to
    /// standard error, so the two streams can be routed separately.
    Stdout,
    /// Drop events. For tests only.
    Discard,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSettings {
    pub mode: AuthMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Anonymous,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandingSettings {
    pub product_name: String,
    pub company_name: String,
    pub tagline: String,
    pub logo_path: Option<PathBuf>,
    pub favicon_path: Option<PathBuf>,
    pub support_url: String,
    pub footer_text: String,
    pub show_powered_by: bool,
    pub colors: BrandColors,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandColors {
    pub primary: String,
    pub on_primary: String,
    pub secondary: String,
    pub surface: String,
    pub on_surface: String,
    pub surface_variant: String,
    pub error: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().expect("static address"),
            management_bind: "127.0.0.1:9090".parse().expect("static address"),
            trusted_proxies: Vec::new(),
            hsts: false,
            shutdown_timeout_seconds: 10,
            tls: TlsSettings::default(),
        }
    }
}

impl Default for MessageSettings {
    fn default() -> Self {
        Self {
            ttl_options_seconds: vec![300, 900, 3600, 28_800, 86_400],
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            min_ttl_seconds: 60,
            max_plaintext_bytes: 65_536,
            memory_budget_bytes: 256 * 1024 * 1024,
            max_failed_proofs: 5,
            kdf: KdfSettings::default(),
        }
    }
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            recommended_iterations: 600_000,
            min_iterations: 100_000,
            max_iterations: 5_000_000,
        }
    }
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            create_per_minute: 10,
            consume_per_minute: 30,
            revoke_per_minute: 30,
        }
    }
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Memory,
        }
    }
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            sink: AuditSinkKind::Stdout,
            include_client_ip: false,
            include_user_agent: false,
        }
    }
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            mode: AuthMode::Anonymous,
        }
    }
}

impl Default for BrandingSettings {
    fn default() -> Self {
        Self {
            product_name: "Cyphera SecureSend".to_owned(),
            company_name: String::new(),
            tagline: "Share sensitive information securely.".to_owned(),
            logo_path: None,
            favicon_path: None,
            support_url: String::new(),
            footer_text: String::new(),
            show_powered_by: true,
            colors: BrandColors::default(),
        }
    }
}

impl Default for BrandColors {
    fn default() -> Self {
        Self {
            primary: "#1f4e79".to_owned(),
            on_primary: "#ffffff".to_owned(),
            secondary: "#4f6d8a".to_owned(),
            surface: "#fbfcfe".to_owned(),
            on_surface: "#191c1e".to_owned(),
            surface_variant: "#e1e5ea".to_owned(),
            error: "#ba1a1a".to_owned(),
        }
    }
}

impl Settings {
    /// Loads defaults, then the YAML file if one is found, then the
    /// environment. `explicit_path` wins over the env var, which wins over
    /// the conventional file name in the working directory. A missing file
    /// is only an error when it was named explicitly.
    pub fn load(explicit_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut builder =
            config::Config::builder().add_source(config::Config::try_from(&Settings::default())?);

        let path = explicit_path
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os(ENV_CONFIG_PATH).map(PathBuf::from));
        match path {
            Some(p) => {
                builder = builder.add_source(config::File::from(p).required(true));
            }
            None => {
                builder = builder
                    .add_source(config::File::with_name(DEFAULT_CONFIG_PATH).required(false));
            }
        }

        builder = builder.add_source(
            config::Environment::with_prefix(ENV_PREFIX)
                .separator("__")
                .try_parsing(true)
                .list_separator(",")
                .with_list_parse_key("messages.ttl_options_seconds")
                .with_list_parse_key("server.trusted_proxies"),
        );

        let settings: Settings = builder.build()?.try_deserialize()?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let m = &self.messages;
        if m.ttl_options_seconds.is_empty() {
            return Err(ConfigError::Invalid(
                "messages.ttl_options_seconds must not be empty".into(),
            ));
        }
        if m.min_ttl_seconds == 0 || m.min_ttl_seconds > m.max_ttl_seconds {
            return Err(ConfigError::Invalid(
                "messages.min_ttl_seconds must be between 1 and max_ttl_seconds".into(),
            ));
        }
        for ttl in &m.ttl_options_seconds {
            if *ttl < m.min_ttl_seconds || *ttl > m.max_ttl_seconds {
                return Err(ConfigError::Invalid(format!(
                    "messages.ttl_options_seconds entry {ttl} is outside min/max ttl"
                )));
            }
        }
        if !m.ttl_options_seconds.contains(&m.default_ttl_seconds) {
            return Err(ConfigError::Invalid(
                "messages.default_ttl_seconds must be one of ttl_options_seconds".into(),
            ));
        }
        if m.max_plaintext_bytes < 16 {
            return Err(ConfigError::Invalid(
                "messages.max_plaintext_bytes is too small".into(),
            ));
        }
        let largest = (m.max_plaintext_bytes as u64) + 1024;
        if m.memory_budget_bytes < largest * 16 {
            return Err(ConfigError::Invalid(
                "messages.memory_budget_bytes must hold at least sixteen maximum-size messages"
                    .into(),
            ));
        }
        if m.max_failed_proofs == 0 {
            return Err(ConfigError::Invalid(
                "messages.max_failed_proofs must be at least 1".into(),
            ));
        }
        let k = &m.kdf;
        if k.min_iterations == 0 || k.min_iterations > k.max_iterations {
            return Err(ConfigError::Invalid(
                "messages.kdf iteration bounds are inconsistent".into(),
            ));
        }
        if k.recommended_iterations < k.min_iterations
            || k.recommended_iterations > k.max_iterations
        {
            return Err(ConfigError::Invalid(
                "messages.kdf.recommended_iterations is outside the accepted bounds".into(),
            ));
        }
        let r = &self.rate_limits;
        if r.create_per_minute == 0 || r.consume_per_minute == 0 || r.revoke_per_minute == 0 {
            return Err(ConfigError::Invalid(
                "rate_limits must be at least 1 per minute".into(),
            ));
        }
        let t = &self.server.tls;
        if t.cert_path.is_some() != t.key_path.is_some() {
            return Err(ConfigError::Invalid(
                "server.tls needs both cert_path and key_path, or neither".into(),
            ));
        }
        for (name, value) in [
            ("primary", &self.branding.colors.primary),
            ("on_primary", &self.branding.colors.on_primary),
            ("secondary", &self.branding.colors.secondary),
            ("surface", &self.branding.colors.surface),
            ("on_surface", &self.branding.colors.on_surface),
            ("surface_variant", &self.branding.colors.surface_variant),
            ("error", &self.branding.colors.error),
        ] {
            if !is_hex_color(value) {
                return Err(ConfigError::Invalid(format!(
                    "branding.colors.{name} must be a hex color like #1f4e79"
                )));
            }
        }
        if !self.branding.support_url.is_empty()
            && !(self.branding.support_url.starts_with("https://")
                || self.branding.support_url.starts_with("http://"))
        {
            return Err(ConfigError::Invalid(
                "branding.support_url must be an http(s) URL".into(),
            ));
        }
        for text in [
            &self.branding.product_name,
            &self.branding.company_name,
            &self.branding.tagline,
            &self.branding.footer_text,
        ] {
            if text.len() > 200 {
                return Err(ConfigError::Invalid(
                    "branding text fields are limited to 200 bytes".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn tls_enabled(&self) -> bool {
        self.server.tls.cert_path.is_some()
    }
}

/// `#rgb` or `#rrggbb`. Anything else is refused so branding values can be
/// emitted into CSS custom properties without escaping concerns.
pub fn is_hex_color(s: &str) -> bool {
    let Some(hex) = s.strip_prefix('#') else {
        return false;
    };
    (hex.len() == 3 || hex.len() == 6) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn default_ttl_must_be_an_option() {
        let mut s = Settings::default();
        s.messages.default_ttl_seconds = 1234;
        assert!(s.validate().is_err());
    }

    #[test]
    fn budget_must_hold_sixteen_messages() {
        let mut s = Settings::default();
        s.messages.memory_budget_bytes = 1024;
        assert!(s.validate().is_err());
    }

    #[test]
    fn tls_needs_both_paths() {
        let mut s = Settings::default();
        s.server.tls.cert_path = Some("cert.pem".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn colors_are_hex_only() {
        assert!(is_hex_color("#abc"));
        assert!(is_hex_color("#1F4E79"));
        assert!(!is_hex_color("red"));
        assert!(!is_hex_color("#12345"));
        assert!(!is_hex_color("#1f4e79;}"));
        let mut s = Settings::default();
        s.branding.colors.primary = "url(x)".into();
        assert!(s.validate().is_err());
    }
}
