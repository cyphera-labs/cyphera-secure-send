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
    /// The product mode. `eval` records who users say they are; `enterprise`
    /// verifies who they are through the identity provider in `auth.oidc`.
    pub mode: Mode,
    pub server: ServerSettings,
    pub messages: MessageSettings,
    pub rate_limits: RateLimitSettings,
    pub storage: StorageSettings,
    pub audit: AuditSettings,
    pub enterprise: EnterpriseSettings,
    pub branding: BrandingSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Address the public listener binds.
    pub bind: SocketAddr,
    /// The URL users reach the service at, for example
    /// `https://send.example.com`. Required in OIDC mode, where it forms the
    /// redirect URL and decides whether cookies are marked Secure.
    pub public_base_url: Option<String>,
    /// Address the management listener binds (health, readiness, metrics).
    /// Keep it off the public network.
    pub management_bind: SocketAddr,
    /// Networks whose `X-Forwarded-For` is trusted. Empty means the peer
    /// address is always the client address.
    pub trusted_proxies: Vec<IpNet>,
    /// How many proxies stand between the client and this service, when
    /// their addresses are not knowable in advance. A proxy appends the
    /// address it received from, so with one in front the client is the last
    /// entry in `X-Forwarded-For`, with two it is the second from the right,
    /// and so on. Reading from the right is what makes it safe: anything the
    /// client writes in front of itself shifts the chain without moving the
    /// position read.
    ///
    /// Mutually exclusive with `trusted_proxies`, and unsafe anywhere the
    /// service can also be reached directly, since then nothing appended the
    /// entry being trusted.
    pub trusted_hops: u8,
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
    /// Per client address.
    pub create_per_minute: u32,
    pub consume_per_minute: u32,
    pub revoke_per_minute: u32,
    /// Per signed-in identity, enterprise mode only. Bounds a signed-in
    /// caller regardless of how many addresses they come from.
    pub identity_create_per_minute: u32,
    pub identity_consume_per_minute: u32,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Capability-based access: possession of the link and the password is
    /// the authority to retrieve. Sender and recipient addresses are recorded
    /// but not verified. A supported mode, not a trial; recommended where
    /// reaching the service is itself controlled, such as an internal
    /// network, a VPN, or a trusted team.
    #[default]
    Standard,
    /// Identity-bound access: users sign in at an OpenID Connect provider.
    /// Two independent questions, configured separately below: who may create
    /// a handoff, and what the recipient must prove to consume one.
    Enterprise,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnterpriseSettings {
    /// The identity provider.
    pub oidc: OidcSettings,
    /// Who may create a handoff.
    pub creation: CreationSettings,
    /// What the recipient must prove to consume one.
    pub recipient: RecipientSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CreationSettings {
    /// Creating requires a signed-in user, and the sender is that identity
    /// rather than a typed field. Turning this off allows anonymous creation,
    /// which is the shape the abuse model exists to prevent.
    pub require_oidc: bool,
    /// The organization's own domains. When non-empty, the signed-in sender
    /// must belong to one of them. Empty allows any.
    pub allowed_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecipientSettings {
    /// Consuming requires a signed-in user. Turn this off for the handoff to
    /// someone outside the directory, who then presents the link and the
    /// password like any standard-mode recipient.
    pub require_oidc: bool,
    /// The signed-in reader's address must equal the message's recipient.
    /// Meaningless without `require_oidc`.
    pub require_identity_match: bool,
    /// Allow a recipient outside `creation.allowed_domains`. Only bites when
    /// that list is non-empty; with no list every address is acceptable.
    pub external_recipients: bool,
}

impl Default for CreationSettings {
    fn default() -> Self {
        Self {
            require_oidc: true,
            allowed_domains: Vec::new(),
        }
    }
}

impl Default for RecipientSettings {
    fn default() -> Self {
        Self {
            require_oidc: true,
            require_identity_match: true,
            external_recipients: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSettings {
    /// The provider's issuer URL, exactly as it appears in its discovery
    /// document. For Entra ID: `https://login.microsoftonline.com/<tenant-id>/v2.0`.
    pub issuer: String,
    pub client_id: String,
    /// Set through the environment
    /// (`CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET`) or
    /// `client_secret_file`; never printed back.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    pub client_secret_file: Option<PathBuf>,
    pub scopes: Vec<String>,
    /// Which claim carries the address. There is no fallback between them:
    /// they mean different things, and quietly substituting one for the other
    /// would let a provider that does not verify usernames decide who counts
    /// as an employee.
    pub email_claim: EmailClaim,
    /// What to do when the token does not say the address has been verified.
    /// Signing in proves control of an account, not of every address attached
    /// to it, so this is a deliberate statement about what the provider
    /// guarantees rather than a default anyone should inherit silently.
    pub unverified_email: UnverifiedEmail,
    pub session_ttl_seconds: u64,
    /// How long a started login may take before it is forgotten.
    pub login_ttl_seconds: u64,
    /// PEM bundle of additional certificate authorities trusted when talking
    /// to the provider, for private or intercepting CAs.
    pub trust_ca_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailClaim {
    /// The `email` claim, which carries `email_verified` alongside it.
    Email,
    /// The `preferred_username` claim. It has no companion verification and
    /// providers describe it as mutable, so choosing it is a statement that
    /// your provider controls what it contains.
    PreferredUsername,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnverifiedEmail {
    /// Refuse the sign-in unless the token says the address is verified.
    Refuse,
    /// Accept it. Choose this when the provider is authoritative for the
    /// address even though it does not send `email_verified`, which is common
    /// for a single-tenant directory. It is a statement about your provider,
    /// not a convenience setting.
    Accept,
}

impl Default for OidcSettings {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: None,
            client_secret_file: None,
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            email_claim: EmailClaim::Email,
            unverified_email: UnverifiedEmail::Refuse,
            session_ttl_seconds: 8 * 3600,
            login_ttl_seconds: 600,
            trust_ca_path: None,
        }
    }
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
            public_base_url: None,
            management_bind: "127.0.0.1:9090".parse().expect("static address"),
            trusted_proxies: Vec::new(),
            trusted_hops: 0,
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
            identity_create_per_minute: 30,
            identity_consume_per_minute: 60,
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
                .with_list_parse_key("server.trusted_proxies")
                .with_list_parse_key("enterprise.creation.allowed_domains")
                .with_list_parse_key("enterprise.oidc.scopes"),
        );

        let mut settings: Settings = builder.build()?.try_deserialize()?;
        settings.normalize();
        settings.validate()?;
        Ok(settings)
    }

    /// Tidies what an operator can reasonably write. A list supplied through
    /// the environment arrives as one string split on commas, so an unset
    /// variable that is still present, `KEY=`, becomes a single empty entry
    /// rather than an empty list; the templates would then fail to start over
    /// a value the operator did not set.
    fn normalize(&mut self) {
        fn tidy(list: &mut Vec<String>) {
            for item in list.iter_mut() {
                *item = item.trim().to_owned();
            }
            list.retain(|item| !item.is_empty());
        }
        tidy(&mut self.enterprise.creation.allowed_domains);
        tidy(&mut self.enterprise.oidc.scopes);
        if self.enterprise.oidc.scopes.is_empty() {
            self.enterprise.oidc.scopes = OidcSettings::default().scopes;
        }
        if self
            .server
            .public_base_url
            .as_deref()
            .map(str::trim)
            .is_some_and(str::is_empty)
        {
            self.server.public_base_url = None;
        }
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
        if let Some(base) = &self.server.public_base_url {
            let parsed = url::Url::parse(base).map_err(|_| {
                ConfigError::Invalid("server.public_base_url must be an absolute URL".into())
            })?;
            if parsed.scheme() != "https" && parsed.scheme() != "http" {
                return Err(ConfigError::Invalid(
                    "server.public_base_url must be http(s)".into(),
                ));
            }
            if parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(ConfigError::Invalid(
                    "server.public_base_url must not carry a query or fragment".into(),
                ));
            }
        }
        if self.mode == Mode::Enterprise {
            let o = &self.enterprise.oidc;
            if self.server.public_base_url.is_none() {
                return Err(ConfigError::Invalid(
                    "mode enterprise requires server.public_base_url".into(),
                ));
            }
            let issuer = url::Url::parse(&o.issuer).map_err(|_| {
                ConfigError::Invalid(
                    "mode enterprise requires enterprise.oidc.issuer, an absolute URL".into(),
                )
            })?;
            let local = matches!(
                issuer.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1")
            );
            if issuer.scheme() != "https" && !(issuer.scheme() == "http" && local) {
                return Err(ConfigError::Invalid(
                    "enterprise.oidc.issuer must use https (http is allowed for localhost only)"
                        .into(),
                ));
            }
            if o.client_id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "enterprise.oidc.client_id is required".into(),
                ));
            }
            if o.client_secret
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
                && o.client_secret_file.is_none()
            {
                return Err(ConfigError::Invalid(
                    "enterprise.oidc needs client_secret (via CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET) or client_secret_file".into(),
                ));
            }
            if !o.scopes.iter().any(|s| s == "openid") {
                return Err(ConfigError::Invalid(
                    "enterprise.oidc.scopes must include openid".into(),
                ));
            }
            if o.session_ttl_seconds < 60 || o.login_ttl_seconds < 30 {
                return Err(ConfigError::Invalid(
                    "enterprise.oidc session and login lifetimes are too short".into(),
                ));
            }
            for d in &self.enterprise.creation.allowed_domains {
                if d.is_empty()
                    || d.contains('@')
                    || d.contains(char::is_whitespace)
                    || d != &d.to_ascii_lowercase()
                {
                    return Err(ConfigError::Invalid(format!(
                        "enterprise.creation.allowed_domains entry {d:?} must be a lowercase domain"
                    )));
                }
            }
            let r = &self.enterprise.recipient;
            if r.require_identity_match && !r.require_oidc {
                return Err(ConfigError::Invalid(
                    "enterprise.recipient.require_identity_match needs require_oidc: a reader who does not sign in has no identity to match".into(),
                ));
            }
            if !self.enterprise.creation.require_oidc && !self.public_https() {
                return Err(ConfigError::Invalid(
                    "enterprise.creation.require_oidc is off, which allows anonymous creation; serve over https before opening that".into(),
                ));
            }
        }
        if self.server.trusted_hops > 0 && !self.server.trusted_proxies.is_empty() {
            return Err(ConfigError::Invalid(
                "server.trusted_hops and server.trusted_proxies cannot both be set: choose known proxy networks, or a count of hops you control".into(),
            ));
        }
        if self.server.trusted_hops > 8 {
            return Err(ConfigError::Invalid(
                "server.trusted_hops is implausibly large".into(),
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

    /// The public base URL is served over HTTPS, so cookies carry Secure.
    pub fn public_https(&self) -> bool {
        self.server
            .public_base_url
            .as_deref()
            .map(|u| u.starts_with("https://"))
            .unwrap_or(false)
    }
}

impl OidcSettings {
    /// The client secret from configuration or from the named file, trimmed.
    pub fn resolve_client_secret(&self) -> Result<String, ConfigError> {
        if let Some(s) = self
            .client_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(s.to_owned());
        }
        let path = self.client_secret_file.as_ref().ok_or_else(|| {
            ConfigError::Invalid("auth.oidc client secret is not configured".into())
        })?;
        let raw = std::fs::read_to_string(path).map_err(|e| {
            ConfigError::Invalid(format!(
                "auth.oidc.client_secret_file {}: {e}",
                path.display()
            ))
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::Invalid(
                "auth.oidc.client_secret_file is empty".into(),
            ));
        }
        Ok(trimmed.to_owned())
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
    fn an_unset_list_variable_is_not_a_one_entry_list() {
        let mut s = Settings {
            mode: Mode::Enterprise,
            ..Default::default()
        };
        s.server.public_base_url = Some("   ".into());
        s.enterprise.creation.allowed_domains = vec!["".into(), " example.com ".into()];
        s.enterprise.oidc.scopes = vec!["".into()];
        s.normalize();
        assert_eq!(s.server.public_base_url, None);
        assert_eq!(s.enterprise.creation.allowed_domains, vec!["example.com"]);
        assert!(s.enterprise.oidc.scopes.iter().any(|x| x == "openid"));
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
    fn enterprise_mode_demands_its_inputs() {
        let mut s = Settings {
            mode: Mode::Enterprise,
            ..Default::default()
        };
        assert!(s.validate().is_err());
        s.server.public_base_url = Some("https://send.example.com".into());
        assert!(s.validate().is_err());
        s.enterprise.oidc.issuer = "https://login.microsoftonline.com/tenant/v2.0".into();
        s.enterprise.oidc.client_id = "app".into();
        assert!(s.validate().is_err());
        s.enterprise.oidc.client_secret = Some("x".into());
        s.validate().unwrap();
        s.enterprise.oidc.issuer = "http://idp.example.com".into();
        assert!(s.validate().is_err());
        s.enterprise.oidc.issuer = "http://127.0.0.1:9999".into();
        s.validate().unwrap();
        s.enterprise.creation.allowed_domains = vec!["Acme.com".into()];
        assert!(s.validate().is_err());
    }

    #[test]
    fn client_secret_is_never_serialized() {
        let mut s = Settings::default();
        s.enterprise.oidc.client_secret = Some("hunter2".into());
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("hunter2"));
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
