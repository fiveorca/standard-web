// ! 配置加载

use serde::Deserialize;
use std::path::Path;
use tracing::info;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub http: HttpConfig,
    pub grpc: GrpcConfig,
    pub grpc_limits: GrpcLimits,
    pub kafka: KafkaConfig,
    pub clickhouse: ClickHouseConfig,
    pub batch: BatchConfig,
    pub retention: RetentionConfig,
    pub query: QueryConfig,
    pub security: SecurityConfig,
    pub auth: AuthConfig,
    pub observability: ObservabilityConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            http: HttpConfig::default(),
            grpc: GrpcConfig::default(),
            grpc_limits: GrpcLimits::default(),
            kafka: KafkaConfig::default(),
            clickhouse: ClickHouseConfig::default(),
            batch: BatchConfig::default(),
            retention: RetentionConfig::default(),
            query: QueryConfig::default(),
            security: SecurityConfig::default(),
            auth: AuthConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub mode: String, // api | worker | all
    pub graceful_shutdown_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: "all".to_string(),
            graceful_shutdown_ms: 10000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpConfig {
    pub host: String,
    pub port: u16,
    pub max_request_mb: usize,
    pub request_timeout_ms: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            max_request_mb: 4,
            request_timeout_ms: 30000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GrpcConfig {
    pub host: String,
    pub port: u16,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 9090,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GrpcLimits {
    pub max_batch_events: usize,
    pub max_event_kb: usize,
    pub max_batch_mb: usize,
    pub concurrency_limit: usize,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            max_batch_events: 500,
            max_event_kb: 256,
            max_batch_mb: 4,
            concurrency_limit: 256,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaConfig {
    pub brokers: String,
    pub raw_topic: String,
    pub dlq_topic: String,
    pub producer_acks: String,
    pub producer_idempotence: bool,
    pub producer_retries: u32,
    pub producer_request_timeout_ms: u32,
    pub producer_max_in_flight: u32,
    pub consumer_group: String,
    pub consumer_auto_offset_reset: String,
    pub consumer_poll_timeout_ms: u64,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".to_string(),
            raw_topic: "logs.raw.v1".to_string(),
            dlq_topic: "logs.dlq.v1".to_string(),
            producer_acks: "all".to_string(),
            producer_idempotence: true,
            producer_retries: 3,
            producer_request_timeout_ms: 5000,
            producer_max_in_flight: 5,
            consumer_group: "log-service-writer".to_string(),
            consumer_auto_offset_reset: "latest".to_string(),
            consumer_poll_timeout_ms: 1000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClickHouseConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub database: String,
    pub insert_timeout_ms: u64,
    pub query_timeout_ms: u64,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            user: "default".to_string(),
            password: String::new(),
            database: "log_center".to_string(),
            insert_timeout_ms: 30000,
            query_timeout_ms: 60000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct BatchConfig {
    pub max_rows: usize,
    pub max_bytes_mb: usize,
    pub flush_interval_ms: u64,
    pub max_concurrent_inserts: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_rows: 5000,
            max_bytes_mb: 16,
            flush_interval_ms: 1000,
            max_concurrent_inserts: 4,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RetentionConfig {
    pub default_retention_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            default_retention_days: 30,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct QueryConfig {
    pub max_time_range_hours: u64,
    pub max_result_rows: u64,
    pub sql_timeout_ms: u64,
    pub default_page_size: usize,
    pub max_page_size: usize,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            max_time_range_hours: 168,
            max_result_rows: 10000,
            sql_timeout_ms: 30000,
            default_page_size: 100,
            max_page_size: 1000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub sanitize_enabled: bool,
    pub sanitize_mask: String,
    pub sensitive_fields: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_enabled: true,
            sanitize_mask: "***REDACTED***".to_string(),
            sensitive_fields: vec![
                "password".into(),
                "passwd".into(),
                "pwd".into(),
                "accessToken".into(),
                "refreshToken".into(),
                "authorization".into(),
                "cookie".into(),
                "secret".into(),
                "apiKey".into(),
                "api_secret".into(),
                "creditCard".into(),
                "ssn".into(),
            ],
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub api_token_header: String,
    pub service_name_header: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_token_header: "X-API-Token".to_string(),
            service_name_header: "X-Service-Name".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    pub tracing_enabled: bool,
    pub otlp_endpoint: String,
    pub metrics_enabled: bool,
    pub metrics_path: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            tracing_enabled: false,
            otlp_endpoint: "http://localhost:4317".to_string(),
            metrics_enabled: true,
            metrics_path: "/metrics".to_string(),
        }
    }
}

impl AppConfig {
    /// 从文件加载配置。不存在则使用默认配置。
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg = match path {
            Some(p) if p.exists() => {
                let content = std::fs::read_to_string(p)?;
                info!(config_path = %p.display(), "加载配置文件");
                toml::from_str(&content)?
            }
            _ => {
                info!("使用默认配置");
                Self::default()
            }
        };

        // 环境变量覆盖
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("LOGSERVER_MODE") {
            self.server.mode = v;
        }
        if let Ok(v) = std::env::var("KAFKA_BROKERS") {
            self.kafka.brokers = v;
        }
        if let Ok(v) = std::env::var("KAFKA_RAW_TOPIC") {
            self.kafka.raw_topic = v;
        }
        if let Ok(v) = std::env::var("KAFKA_DLQ_TOPIC") {
            self.kafka.dlq_topic = v;
        }
        if let Ok(v) = std::env::var("KAFKA_CONSUMER_GROUP") {
            self.kafka.consumer_group = v;
        }
        if let Ok(v) = std::env::var("CLICKHOUSE_URL") {
            self.clickhouse.url = v;
        }
        if let Ok(v) = std::env::var("CLICKHOUSE_USER") {
            self.clickhouse.user = v;
        }
        if let Ok(v) = std::env::var("CLICKHOUSE_PASSWORD") {
            self.clickhouse.password = v;
        }
        if let Ok(v) = std::env::var("CLICKHOUSE_DATABASE") {
            self.clickhouse.database = v;
        }
        if let Ok(v) = std::env::var("HTTP_PORT") {
            if let Ok(p) = v.parse() {
                self.http.port = p;
            }
        }
        if let Ok(v) = std::env::var("GRPC_PORT") {
            if let Ok(p) = v.parse() {
                self.grpc.port = p;
            }
        }
    }

    pub fn is_api_mode(&self) -> bool {
        self.server.mode == "api" || self.server.mode == "all"
    }

    pub fn is_worker_mode(&self) -> bool {
        self.server.mode == "worker" || self.server.mode == "all"
    }
}

// ---- 便捷 builder ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = AppConfig::load(None).unwrap();
        assert_eq!(cfg.http.port, 8080);
        assert_eq!(cfg.grpc.port, 9090);
        assert_eq!(cfg.kafka.raw_topic, "logs.raw.v1");
    }
}
