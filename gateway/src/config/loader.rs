//! 配置文件加载：支持主配置、路由配置、环境 profile 覆盖以及 `${ENV_VAR}` 占位符。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_yaml::Value;
use sha2::{Digest, Sha256};

use crate::config::model::{GatewayConfig, RouteConfig};

static ENV_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("valid env pattern")
});

/// 加载结果。
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: GatewayConfig,
    pub root_dir: PathBuf,
    pub config_path: PathBuf,
    pub routes_path: PathBuf,
    /// 合并后配置内容的 SHA-256，用于检测文件变化。
    pub hash: String,
}

/// 从目录加载配置。
///
/// 加载顺序：
/// 1. `gateway.yaml`（主配置）
/// 2. `routes.yaml`（路由配置，可与主配置中的 routes 合并）
/// 3. `{profile}.yaml`（环境覆盖，profile 来自参数或 `GATEWAY_PROFILE` 环境变量）
pub async fn load(root: &Path, profile: Option<&str>) -> Result<LoadedConfig> {
    let config_path = root.join("gateway.yaml");
    let routes_path = root.join("routes.yaml");

    let mut merged = Value::Mapping(Default::default());

    for (path, required) in [(&config_path, true), (&routes_path, false)] {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                let value: Value = serde_yaml::from_str(&content)
                    .with_context(|| format!("failed to parse YAML file {}", path.display()))?;
                merge(&mut merged, &value);
            }
            Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()))
            }
        }
    }

    if let Some(profile) = profile {
        let profile_path = root.join(format!("{profile}.yaml"));
        if profile_path.exists() {
            let content = tokio::fs::read_to_string(&profile_path)
                .await
                .with_context(|| format!("failed to read {}", profile_path.display()))?;
            let value: Value = serde_yaml::from_str(&content)
                .with_context(|| format!("failed to parse YAML file {}", profile_path.display()))?;
            merge(&mut merged, &value);
        }
    }

    substitute_env(&mut merged);

    // routes.yaml 可能只包含 `routes:` 列表；这里把主配置与路由配置的 routes 做合并。
    let rendered = serde_yaml::to_string(&merged)?;
    let hash = sha256_hex(rendered.as_bytes());

    let mut config: GatewayConfig =
        serde_yaml::from_value(merged).context("failed to deserialize gateway configuration")?;

    if config.routes.is_empty() {
        // 允许 routes.yaml 直接是数组形式。
        let raw_config = tokio::fs::read_to_string(&config_path)
            .await
            .unwrap_or_default();
        let raw_routes = tokio::fs::read_to_string(&routes_path)
            .await
            .unwrap_or_default();
        for raw in [raw_config, raw_routes] {
            if let Ok(Value::Sequence(_)) = serde_yaml::from_str::<Value>(&raw) {
                if let Ok(routes) = serde_yaml::from_str::<Vec<RouteConfig>>(&raw) {
                    config.routes = routes;
                }
            }
        }
    }

    Ok(LoadedConfig {
        config,
        root_dir: root.to_path_buf(),
        config_path,
        routes_path,
        hash,
    })
}

/// 递归合并 YAML，overlay 覆盖 base。
fn merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Mapping(base_map), Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                match base_map.get_mut(key) {
                    Some(existing) => merge(existing, value),
                    None => {
                        base_map.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base_slot, overlay_value) => {
            *base_slot = overlay_value.clone();
        }
    }
}

/// 递归替换字符串中的 `${VAR}` / `${VAR:-default}`。
///
/// 若整个字符串恰好是一个占位符，且替换结果是数字或布尔值，则保留其类型，
/// 这样 `port: ${PORT:-8080}` 这类数值配置也能正常工作。
fn substitute_env(value: &mut Value) {
    match value {
        Value::String(s) => {
            if !s.contains("${") {
                return;
            }
            if let Some(caps) = ENV_PATTERN.captures(s) {
                if caps.get(0).map(|m| m.range()) == Some(0..s.len()) {
                    let resolved = resolve_env(&caps);
                    if let Some(typed) = typed_scalar(&resolved) {
                        *value = typed;
                        return;
                    }
                    *s = resolved;
                    return;
                }
            }
            let replaced = ENV_PATTERN.replace_all(s, |caps: &regex::Captures| resolve_env(caps));
            *s = replaced.to_string();
        }
        Value::Sequence(seq) => {
            for item in seq {
                substitute_env(item);
            }
        }
        Value::Mapping(map) => {
            for (_, v) in map.iter_mut() {
                substitute_env(v);
            }
        }
        _ => {}
    }
}

fn resolve_env(caps: &regex::Captures) -> String {
    let name = &caps[1];
    std::env::var(name).unwrap_or_else(|_| {
        caps.get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    })
}

fn typed_scalar(raw: &str) -> Option<Value> {
    if let Ok(value) = raw.parse::<bool>() {
        return Some(Value::Bool(value));
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Some(Value::Number(value.into()));
    }
    if let Ok(value) = raw.parse::<f64>() {
        if value.is_finite() {
            return Some(Value::Number(serde_yaml::Number::from(value)));
        }
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 原子写入路由配置文件。
pub async fn save_routes(path: &Path, routes: &[RouteConfig]) -> Result<()> {
    let payload = serde_yaml::to_string(&serde_json::json!({ "routes": routes }))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, payload.as_bytes()).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_nested_mappings() {
        let mut base: Value = serde_yaml::from_str("a: 1\nb:\n  c: 2\n  d: 3\n").unwrap();
        let overlay: Value = serde_yaml::from_str("b:\n  c: 20\n  e: 4\n").unwrap();
        merge(&mut base, &overlay);
        let b = base.get("b").unwrap();
        assert_eq!(b.get("c").unwrap().as_u64(), Some(20));
        assert_eq!(b.get("d").unwrap().as_u64(), Some(3));
        assert_eq!(b.get("e").unwrap().as_u64(), Some(4));
    }

    #[test]
    fn env_substitution() {
        std::env::set_var("GATEWAY_TEST_ENV", "hello");
        let mut value: Value =
            serde_yaml::from_str("k: \"${GATEWAY_TEST_ENV}-${MISSING_VAR:-world}\"").unwrap();
        substitute_env(&mut value);
        assert_eq!(value.get("k").unwrap().as_str(), Some("hello-world"));
        std::env::remove_var("GATEWAY_TEST_ENV");
    }

    #[test]
    fn whole_placeholder_keeps_scalar_type() {
        std::env::set_var("GATEWAY_TEST_PORT", "9000");
        let mut value: Value = serde_yaml::from_str("port: ${GATEWAY_TEST_PORT:-8080}").unwrap();
        substitute_env(&mut value);
        assert_eq!(value.get("port").unwrap().as_u64(), Some(9000));
        std::env::remove_var("GATEWAY_TEST_PORT");
    }

    #[tokio::test]
    async fn bundled_configuration_is_valid() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let loaded = load(&root, None).await.expect("bundled config loads");
        let report = crate::config::validate::validate(
            &loaded.config,
            &crate::core::filter::FilterRegistry::builtin(),
        );
        let errors: Vec<_> = report
            .errors()
            .map(|issue| format!("{}: {}", issue.field, issue.message))
            .collect();
        assert!(errors.is_empty(), "config errors: {errors:?}");
        assert!(!loaded.config.routes.is_empty());
    }
}
