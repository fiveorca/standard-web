//! 配置加载：TOML + profile + `USER__SECTION__KEY` 环境变量覆盖。

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub auth: AuthCenterConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub batch: BatchConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            required: false,
            key_prefix: "user-center".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrationConfig {
    /// 注册后是否需要人工审核。
    #[serde(default)]
    pub require_review: bool,
    /// 是否开放自助注册。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 单个 IP 每分钟最大注册次数。
    #[serde(default = "default_registration_rate")]
    pub rate_limit_per_minute: u32,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            require_review: false,
            enabled: true,
            rate_limit_per_minute: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_base")]
    pub public_base_url: String,
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_body")]
    pub max_body_bytes: i64,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default = "default_true")]
    pub trust_proxy_headers: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            public_base_url: default_base(),
            request_timeout_secs: 30,
            max_body_bytes: 8 * 1024 * 1024,
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_acquire_timeout")]
    pub acquire_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub auto_migrate: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: 20,
            min_connections: 2,
            acquire_timeout_secs: 10,
            auto_migrate: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthCenterConfig {
    #[serde(default = "default_auth_base")]
    pub base_url: String,
    #[serde(default)]
    pub internal_token: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_service_client")]
    pub service_client_id: String,
    #[serde(default)]
    pub service_client_secret: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default = "default_auth_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cache_ttl")]
    pub jwks_cache_secs: u64,
}

impl Default for AuthCenterConfig {
    fn default() -> Self {
        Self {
            base_url: default_auth_base(),
            internal_token: String::new(),
            issuer: String::new(),
            audience: String::new(),
            service_client_id: default_service_client(),
            service_client_secret: String::new(),
            jwks_uri: None,
            timeout_secs: 10,
            jwks_cache_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BatchConfig {
    #[serde(default = "default_batch")]
    pub max_items: usize,
    #[serde(default = "default_poll")]
    pub outbox_poll_interval_secs: u64,
    #[serde(default = "default_attempts")]
    pub outbox_max_attempts: i32,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_items: 500,
            outbox_poll_interval_secs: 5,
            outbox_max_attempts: 10,
        }
    }
}

impl Settings {
    pub fn load(config_dir: Option<PathBuf>, profile: Option<String>) -> Result<Self> {
        let dir = config_dir.unwrap_or_else(|| {
            std::env::var("USER_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("config"))
        });
        let profile = profile.or_else(|| std::env::var("USER_PROFILE").ok());
        let mut root = read_toml(&dir.join("default.toml"))?;
        if let Some(profile) = profile.as_deref() {
            let path = dir.join(format!("{profile}.toml"));
            if path.exists() {
                merge_json(&mut root, read_toml(&path)?);
            }
        }
        if let Ok(base) = std::env::var("USER_PUBLIC_BASE_URL") {
            if !base.is_empty() {
                set_path(
                    &mut root,
                    &["server", "public_base_url"],
                    Value::String(base),
                );
            }
        }
        let mut settings: Settings =
            serde_json::from_value(root).context("failed to deserialize configuration")?;
        settings.apply_env_overrides();
        settings.validate()?;
        Ok(settings)
    }

    fn apply_env_overrides(&mut self) {
        for (key, value) in std::env::vars() {
            let Some(rest) = key.strip_prefix("USER__") else {
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
            return Err(anyhow::anyhow!(
                "database.url 未配置，请设置 USER__DATABASE__URL 或 config/default.toml"
            ));
        }
        if self.auth.base_url.trim().is_empty() {
            return Err(anyhow::anyhow!("auth.base_url 未配置"));
        }
        if self.auth.internal_token.len() < 24 {
            return Err(anyhow::anyhow!("auth.internal_token 长度至少 24 字符"));
        }
        if self.auth.issuer.trim().is_empty() {
            self.auth.issuer = self.auth.base_url.trim_end_matches('/').to_string();
        }
        if self.auth.audience.trim().is_empty() {
            self.auth.audience = format!("{}/api", self.auth.base_url.trim_end_matches('/'));
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.server
            .public_base_url
            .trim_end_matches('/')
            .to_string()
    }

    pub fn auth_base_url(&self) -> String {
        self.auth.base_url.trim_end_matches('/').to_string()
    }

    pub fn jwks_uri(&self) -> String {
        self.auth
            .jwks_uri
            .clone()
            .unwrap_or_else(|| format!("{}/oauth2/jwks", self.auth_base_url()))
    }
}

fn default_bind() -> String {
    "0.0.0.0:8081".to_string()
}
fn default_base() -> String {
    "http://localhost:8081".to_string()
}
fn default_timeout() -> u64 {
    30
}
fn default_body() -> i64 {
    8 * 1024 * 1024
}
fn default_true() -> bool {
    true
}
fn default_database_url() -> String {
    "postgres://user_center:user_center@localhost:5432/user_center".to_string()
}
fn default_max_connections() -> u32 {
    20
}
fn default_min_connections() -> u32 {
    2
}
fn default_acquire_timeout() -> u64 {
    10
}
fn default_auth_base() -> String {
    "http://localhost:8080".to_string()
}
fn default_service_client() -> String {
    "user-center".to_string()
}
fn default_auth_timeout() -> u64 {
    10
}
fn default_cache_ttl() -> u64 {
    300
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_batch() -> usize {
    500
}
fn default_poll() -> u64 {
    5
}
fn default_attempts() -> i32 {
    10
}
fn default_redis_url() -> String {
    "redis://localhost:6379/1".to_string()
}
fn default_key_prefix() -> String {
    "user-center".to_string()
}
fn default_registration_rate() -> u32 {
    10
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
        set_path(
            &mut root,
            &["server", "bind"],
            Value::String("0.0.0.0:9".into()),
        );
        assert_eq!(root["server"]["bind"], "0.0.0.0:9");
    }

    #[test]
    fn env_values_keep_types() {
        assert_eq!(parse_env_value("true"), Value::Bool(true));
        assert_eq!(parse_env_value("false"), Value::Bool(false));
        assert_eq!(parse_env_value("42"), serde_json::json!(42));
        assert_eq!(parse_env_value("hello"), serde_json::json!("hello"));
    }
}

fn read_toml(path: &std::path::Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("解析配置文件失败: {}", path.display()))?;
    serde_json::to_value(value).context("转换配置失败")
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                merge_json(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn set_path(root: &mut Value, parts: &[&str], value: Value) {
    if parts.is_empty() {
        *root = value;
        return;
    }
    if !root.is_object() {
        *root = Value::Object(serde_json::Map::new());
    }
    let object = root.as_object_mut().unwrap_or_else(|| unreachable!());
    if parts.len() == 1 {
        object.insert(parts[0].to_string(), value);
    } else {
        let entry = object
            .entry(parts[0].to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        set_path(entry, &parts[1..], value);
    }
}

fn parse_env_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}
