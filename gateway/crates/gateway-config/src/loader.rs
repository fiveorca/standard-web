//! 配置加载：文件读取 + Figment 环境变量覆盖 + YAML 反序列化。
//!
//! # Figment 0.10 API 说明
//!
//! figment 0.10 中：
//! - `figment::providers::Format` trait 提供 `Yaml::string()` 方法
//! - `figment::providers::Env` 有 `prefixed()` 方法，但没有 `ignore_case()`
//! - Figment::merge 顺序：后 merge 的覆盖先 merge 的
//!
//! Provider 层级：
//!   1. YAML 文件（底层）
//!   2. 环境变量（顶层）—— 用 `GATEWAY_` 前缀，例如
//!      `GATEWAY_SERVER_HTTP_PORT=9090` 覆盖 `server.http.port`

use std::path::Path;

use figment::providers::Format;

use crate::{ConfigError, GatewayConfig};

/// 从文件加载 GatewayConfig，并用 `GATEWAY_` 前缀的环境变量覆盖。
pub fn load_from_path(path: impl AsRef<Path>) -> Result<GatewayConfig, ConfigError> {
    let path = path.as_ref();

    let yaml_text = std::fs::read_to_string(path).map_err(|e| ConfigError {
        path: path.display().to_string(),
        message: format!("failed to read config file: {e}"),
    })?;

    build_figment(&yaml_text).extract::<GatewayConfig>().map_err(|e| ConfigError {
        path: path.display().to_string(),
        message: format!("config parsing failed: {e}"),
    })
}

/// 从字符串直接解析（主要用于测试）。
pub fn load_from_str(yaml_text: &str) -> Result<GatewayConfig, ConfigError> {
    build_figment(yaml_text).extract::<GatewayConfig>().map_err(|e| ConfigError {
        path: "<inline yaml>".to_string(),
        message: format!("config parsing failed: {e}"),
    })
}

/// 构造 Figment 对象：YAML 底层 + ENV 顶层。
fn build_figment(yaml_text: &str) -> figment::Figment {
    figment::Figment::default()
        // Yaml::string() 来自 Format trait，需要 use figment::providers::Format
        .merge(figment::providers::Yaml::string(yaml_text))
        // Env::prefixed() —— 匹配 GATEWAY_ 前缀的环境变量，去掉前缀后映射到嵌套字段
        // figment 0.10 中 Env 没有 ignore_case()，所以只匹配大写字段名
        .merge(figment::providers::Env::prefixed("GATEWAY_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_YAML: &str = r#"
gateway:
  id: test-gw
  instance_name: test-node
  environment: test

server:
  http:
    enabled: true
    address: 127.0.0.1
    port: 18080
  admin:
    enabled: true
    address: 127.0.0.1
    port: 18081

upstreams:
  - id: upstream-1
    endpoints:
      - host: 127.0.0.1
        port: 9090

services:
  - id: service-1
    upstream_id: upstream-1

routes:
  - id: route-1
    path_value: /api
    service_id: service-1
"#;

    #[test]
    fn load_minimal_yaml() {
        let cfg = load_from_str(MINIMAL_YAML).expect("should parse");
        assert_eq!(cfg.gateway.id, "test-gw");
        assert_eq!(cfg.server.http.port, 18080);
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.services.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
    }

    #[test]
    fn load_invalid_yaml_returns_error() {
        let bad = "not: valid: yaml: [";
        let err = load_from_str(bad).expect_err("should fail");
        assert!(!err.message.is_empty());
    }
}
