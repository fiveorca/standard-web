//! 配置模型与加载逻辑。
//!
//! 配置来源优先级（后者覆盖前者）：
//! 1. `config/default.toml`
//! 2. `config/<profile>.toml`（由 `AUTH_PROFILE` 或 `--profile` 指定）
//! 3. 环境变量，形如 `AUTH__SERVER__BIND=0.0.0.0:8080`（`__` 表示层级）

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_bind() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_public_base_url() -> String {
    "http://localhost:8080".to_string()
}

fn default_true() -> bool {
    true
}

fn default_body_bytes() -> i64 {
    2 * 1024 * 1024
}

fn default_pg_max() -> u32 {
    16
}

fn default_pg_min() -> u32 {
    1
}

fn default_redis_prefix() -> String {
    "auth".to_string()
}

fn default_access_ttl() -> u64 {
    900
}

fn default_refresh_ttl() -> u64 {
    1_209_600
}

fn default_id_token_ttl() -> u64 {
    900
}

fn default_code_ttl() -> u64 {
    300
}

fn default_session_ttl() -> u64 {
    43_200
}

fn default_signing_alg() -> String {
    "RS256".to_string()
}

fn default_key_rotation_days() -> u64 {
    90
}

fn default_key_retain_days() -> u64 {
    30
}

fn default_cookie_name() -> String {
    "auth_session".to_string()
}

fn default_same_site() -> String {
    "Lax".to_string()
}

fn default_password_min() -> usize {
    10
}

fn default_password_max() -> usize {
    128
}

fn default_password_history() -> usize {
    5
}

fn default_password_expiry_days() -> u64 {
    0
}

fn default_max_failed_attempts() -> u32 {
    5
}

fn default_lockout_secs() -> u64 {
    900
}

fn default_argon_memory() -> u32 {
    19_456
}

fn default_argon_iterations() -> u32 {
    2
}

fn default_argon_parallelism() -> u32 {
    1
}

fn default_totp_issuer() -> String {
    "Auth Center".to_string()
}

fn default_otp_ttl() -> u64 {
    600
}

fn default_otp_attempts() -> u32 {
    5
}

fn default_otp_length() -> usize {
    6
}

fn default_otp_cooldown() -> u64 {
    60
}

fn default_rate_attempts() -> u32 {
    10
}

fn default_rate_window() -> u64 {
    60
}

fn default_default_scope() -> String {
    "openid profile email".to_string()
}

fn default_saml_assertion_ttl() -> u64 {
    300
}

fn default_clock_skew() -> u64 {
    60
}

fn default_state_ttl() -> u64 {
    600
}

fn default_poll_interval() -> u64 {
    5
}

fn default_batch_size() -> i64 {
    50
}

fn default_max_attempts() -> i32 {
    10
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_notification_provider() -> String {
    "log".to_string()
}

fn default_http_timeout() -> u64 {
    15
}

/// 顶层配置。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub saml: SamlConfig,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub events: EventsConfig,
    #[serde(default)]
    pub federation: FederationConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            security: SecurityConfig::default(),
            oauth: OAuthConfig::default(),
            saml: SamlConfig::default(),
            notifications: NotificationConfig::default(),
            events: EventsConfig::default(),
            federation: FederationConfig::default(),
            logging: LoggingConfig::default(),
            bootstrap: BootstrapConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_public_base_url")]
    pub public_base_url: String,
    #[serde(default = "default_http_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_body_bytes")]
    pub max_body_bytes: i64,
    #[serde(default = "default_true")]
    pub enable_cors: bool,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default = "default_true")]
    pub trust_proxy_headers: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            public_base_url: default_public_base_url(),
            request_timeout_secs: 30,
            max_body_bytes: 2 * 1024 * 1024,
            enable_cors: true,
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_pg_max")]
    pub max_connections: u32,
    #[serde(default = "default_pg_min")]
    pub min_connections: u32,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub auto_migrate: bool,
    #[serde(default)]
    pub acquire_timeout_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            max_connections: default_pg_max(),
            min_connections: default_pg_min(),
            url: String::new(),
            auto_migrate: true,
            acquire_timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            key_prefix: default_redis_prefix(),
            required: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub master_key: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub access_token_audience: String,
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_secs: u64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_secs: u64,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl_secs: u64,
    #[serde(default = "default_code_ttl")]
    pub authorization_code_ttl_secs: u64,
    #[serde(default = "default_signing_alg")]
    pub signing_algorithm: String,
    #[serde(default = "default_key_rotation_days")]
    pub key_rotation_days: u64,
    #[serde(default = "default_key_retain_days")]
    pub key_retain_days: u64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    #[serde(default)]
    pub cookie_domain: Option<String>,
    #[serde(default = "default_same_site")]
    pub cookie_same_site: String,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default)]
    pub password: PasswordConfig,
    #[serde(default)]
    pub mfa: MfaConfig,
    #[serde(default)]
    pub login_rate_limit: RateLimitRule,
    #[serde(default)]
    pub otp_rate_limit: RateLimitRule,
    #[serde(default)]
    pub otp: OtpConfig,
    #[serde(default = "default_true")]
    pub registration_enabled: bool,
    #[serde(default)]
    pub require_email_verification: bool,
    #[serde(default)]
    pub require_phone_verification: bool,
    #[serde(default)]
    pub internal_token: String,
    #[serde(default = "default_true")]
    pub enforce_csrf_for_cookie_auth: bool,
    #[serde(default)]
    pub allowed_redirect_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordConfig {
    #[serde(default = "default_password_min")]
    pub min_length: usize,
    #[serde(default = "default_password_max")]
    pub max_length: usize,
    #[serde(default = "default_true")]
    pub require_upper: bool,
    #[serde(default = "default_true")]
    pub require_lower: bool,
    #[serde(default = "default_true")]
    pub require_digit: bool,
    #[serde(default)]
    pub require_symbol: bool,
    #[serde(default = "default_password_history")]
    pub history_size: usize,
    #[serde(default = "default_password_expiry_days")]
    pub expiry_days: u64,
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    #[serde(default = "default_lockout_secs")]
    pub lockout_secs: u64,
    #[serde(default = "default_argon_memory")]
    pub argon2_memory_kib: u32,
    #[serde(default = "default_argon_iterations")]
    pub argon2_iterations: u32,
    #[serde(default = "default_argon_parallelism")]
    pub argon2_parallelism: u32,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: default_password_min(),
            max_length: default_password_max(),
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_symbol: false,
            history_size: default_password_history(),
            expiry_days: 0,
            max_failed_attempts: default_max_failed_attempts(),
            lockout_secs: default_lockout_secs(),
            argon2_memory_kib: default_argon_memory(),
            argon2_iterations: default_argon_iterations(),
            argon2_parallelism: default_argon_parallelism(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MfaConfig {
    #[serde(default)]
    pub enforce_for_admins: bool,
    #[serde(default = "default_totp_issuer")]
    pub totp_issuer: String,
    #[serde(default)]
    pub webauthn: WebauthnConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct WebauthnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub rp_id: String,
    #[serde(default)]
    pub rp_origin: String,
    #[serde(default)]
    pub rp_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitRule {
    #[serde(default = "default_rate_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_rate_window")]
    pub window_secs: u64,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            max_attempts: default_rate_attempts(),
            window_secs: default_rate_window(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtpConfig {
    #[serde(default = "default_otp_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_otp_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_otp_length")]
    pub length: usize,
    #[serde(default = "default_otp_cooldown")]
    pub resend_cooldown_secs: u64,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_otp_ttl(),
            max_attempts: default_otp_attempts(),
            length: default_otp_length(),
            resend_cooldown_secs: default_otp_cooldown(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub require_consent: bool,
    #[serde(default = "default_true")]
    pub allow_client_credentials: bool,
    #[serde(default = "default_default_scope")]
    pub default_scope: String,
    #[serde(default)]
    pub allow_http_redirect_uri: bool,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_consent: true,
            allow_client_credentials: true,
            default_scope: default_default_scope(),
            allow_http_redirect_uri: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SamlConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub idp_entity_id: String,
    #[serde(default = "default_totp_issuer")]
    pub idp_name: String,
    #[serde(default = "default_saml_assertion_ttl")]
    pub assertion_lifetime_secs: u64,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,
    #[serde(default = "default_true")]
    pub want_authn_requests_signed: bool,
    #[serde(default)]
    pub sp_metadata_urls: Vec<String>,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idp_entity_id: String::new(),
            idp_name: default_totp_issuer(),
            assertion_lifetime_secs: default_saml_assertion_ttl(),
            clock_skew_secs: default_clock_skew(),
            want_authn_requests_signed: true,
            sp_metadata_urls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotificationConfig {
    /// `log` 或 `webhook`
    #[serde(default = "default_notification_provider")]
    pub provider: String,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub from_email: String,
    #[serde(default)]
    pub from_name: String,
}

impl NotificationConfig {
    fn default_provider() -> String {
        "log".to_string()
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            provider: Self::default_provider(),
            webhook_url: String::new(),
            webhook_token: String::new(),
            from_email: "no-reply@example.com".to_string(),
            from_name: "Auth Center".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventsConfig {
    #[serde(default)]
    pub publish_urls: Vec<String>,
    #[serde(default)]
    pub service_token: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: i64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: i32,
    #[serde(default)]
    pub allow_http_targets: bool,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            publish_urls: Vec::new(),
            service_token: String::new(),
            poll_interval_secs: default_poll_interval(),
            batch_size: default_batch_size(),
            max_attempts: default_max_attempts(),
            allow_http_targets: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FederationConfig {
    #[serde(default = "default_state_ttl")]
    pub state_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub allow_auto_register: bool,
    #[serde(default)]
    pub allow_http_providers: bool,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            state_ttl_secs: default_state_ttl(),
            allow_auto_register: true,
            allow_http_providers: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BootstrapConfig {
    #[serde(default)]
    pub admin_username: String,
    #[serde(default)]
    pub admin_password: String,
    #[serde(default)]
    pub admin_email: String,
    #[serde(default)]
    pub tenant_code: String,
    #[serde(default)]
    pub tenant_name: String,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            admin_username: "admin".to_string(),
            admin_password: String::new(),
            admin_email: String::new(),
            tenant_code: "default".to_string(),
            tenant_name: "Default Tenant".to_string(),
        }
    }
}

impl Settings {
    /// 从配置目录加载配置。
    pub fn load(config_dir: Option<PathBuf>, profile: Option<String>) -> Result<Self> {
        let dir = config_dir.unwrap_or_else(|| {
            std::env::var("AUTH_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("config"))
        });
        let profile = profile.or_else(|| std::env::var("AUTH_PROFILE").ok());

        let mut root = read_toml(&dir.join("default.toml"))?;
        if let Some(profile) = profile.as_deref() {
            let path = dir.join(format!("{profile}.toml"));
            if path.exists() {
                merge_json(&mut root, read_toml(&path)?);
            }
        }

        let env_root = std::env::var("AUTH_CONFIG_ROOT").ok();
        let base = env_root
            .or_else(|| std::env::var("AUTH_PUBLIC_BASE_URL").ok())
            .unwrap_or_default();
        if !base.is_empty() {
            set_path(
                &mut root,
                &["server", "public_base_url"],
                Value::String(base),
            );
        }

        let mut settings: Settings =
            serde_json::from_value(root).context("failed to deserialize configuration")?;
        settings.apply_env_overrides();
        settings.validate()?;
        Ok(settings)
    }

    fn apply_env_overrides(&mut self) {
        for (key, value) in std::env::vars() {
            let Some(rest) = key.strip_prefix("AUTH__") else {
                continue;
            };
            let parts: Vec<String> = rest
                .split("__")
                .map(|part| part.to_ascii_lowercase())
                .collect();
            if parts.is_empty() {
                continue;
            }
            let mut root = serde_json::to_value(&*self).unwrap_or(Value::Null);
            set_path(
                &mut root,
                &parts.iter().map(String::as_str).collect::<Vec<_>>(),
                parse_env_value(&value),
            );
            if let Ok(parsed) = serde_json::from_value::<Settings>(root) {
                *self = parsed;
            }
        }
    }

    fn validate(&mut self) -> Result<()> {
        if self.database.url.trim().is_empty() {
            return Err(anyhow!(
                "database.url 未配置，请设置 AUTH__DATABASE__URL 或 config/default.toml"
            ));
        }
        if self.redis.url.trim().is_empty() {
            return Err(anyhow!(
                "redis.url 未配置，请设置 AUTH__REDIS__URL 或 config/default.toml"
            ));
        }
        let key = decode_master_key(&self.security.master_key)?;
        if key.len() != 32 {
            return Err(anyhow!(
                "security.master_key 必须是 32 字节的 Base64 编码密钥"
            ));
        }
        if self.security.issuer.trim().is_empty() {
            self.security.issuer = self.server.public_base_url.clone();
        }
        if self.security.access_token_audience.trim().is_empty() {
            self.security.access_token_audience = format!("{}/api", self.base_url());
        }
        if self.saml.idp_entity_id.trim().is_empty() {
            self.saml.idp_entity_id = format!("{}/saml/metadata", self.base_url());
        }
        match self.security.signing_algorithm.as_str() {
            "RS256" | "RS384" | "RS512" | "ES256" => {}
            other => return Err(anyhow!("不支持的签名算法: {other}")),
        }
        if !matches!(
            self.security.cookie_same_site.as_str(),
            "Lax" | "Strict" | "None"
        ) {
            return Err(anyhow!("cookie_same_site 只能是 Lax/Strict/None"));
        }
        if self.security.cookie_same_site == "None" && !self.security.cookie_secure {
            return Err(anyhow!("SameSite=None 时必须启用 cookie_secure"));
        }
        if self.security.internal_token.len() < 24 {
            return Err(anyhow!("security.internal_token 长度至少 24 字符"));
        }
        if self.security.master_key.len() < 32 {
            return Err(anyhow!("security.master_key 无效"));
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.server
            .public_base_url
            .trim_end_matches('/')
            .to_string()
    }

    pub fn issuer(&self) -> String {
        self.security.issuer.trim_end_matches('/').to_string()
    }

    pub fn cookie_secure(&self) -> bool {
        self.security.cookie_secure
    }

    pub fn is_production(&self) -> bool {
        self.server.public_base_url.starts_with("https://")
    }
}

pub fn decode_master_key(value: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.trim()))
        .context("security.master_key 不是合法的 Base64")
}

fn read_toml(path: &Path) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("无法读取配置文件 {}", path.display()))?;
    let value: toml::Value = toml::from_str(&content)
        .with_context(|| format!("配置文件 {} 格式错误", path.display()))?;
    serde_json::to_value(value).context("配置转换为 JSON 失败")
}

fn parse_env_value(value: &str) -> Value {
    if value.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if let Ok(number) = value.parse::<i64>() {
        return Value::Number(number.into());
    }
    if let Ok(number) = value.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(number) {
            return Value::Number(number);
        }
    }
    Value::String(value.to_string())
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, value) in overlay_map {
                match base_map.get_mut(&key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn set_path(root: &mut Value, path: &[&str], value: Value) {
    if path.is_empty() {
        *root = value;
        return;
    }
    if !root.is_object() {
        *root = Value::Object(serde_json::Map::new());
    }
    let map = match root.as_object_mut() {
        Some(map) => map,
        None => return,
    };
    if path.len() == 1 {
        map.insert(path[0].to_string(), value);
        return;
    }
    let entry = map
        .entry(path[0].to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    set_path(entry, &path[1..], value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_overrides_nested_values() {
        let mut base = serde_json::json!({"server": {"bind": "a", "cors": []}});
        merge_json(&mut base, serde_json::json!({"server": {"bind": "b"}}));
        assert_eq!(base["server"]["bind"], "b");
        assert_eq!(base["server"]["cors"], serde_json::json!([]));
    }

    #[test]
    fn set_path_creates_nested_objects() {
        let mut root = serde_json::json!({});
        set_path(&mut root, &["server", "bind"], Value::String("x".into()));
        assert_eq!(root["server"]["bind"], "x");
    }
}
