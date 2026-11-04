//! 配置快照（CompiledSnapshot）。
//!
//! # 快照是什么
//!
//! 快照 = **校验通过的资源集合** + **版本号** + **checksum**。
//! 它是控制面与数据面之间传递配置的最小单元：
//!
//!   - 控制面发布时：资源集合 → 校验 → 快照 → 存库（JSONB）
//!   - 数据面应用时：快照 → 构建 RouteTable / UpstreamRegistry → 原子替换
//!   - 回滚时：读取历史快照 → 重新走一遍发布流程（版本号继续递增）
//!
//! # 为什么快照要带 checksum
//!
//! `checksum` 是资源集合规范化后的 SHA-256。它有两个用途：
//!   1. 版本比对：控制面可以判断"当前资源是否已经发布过"
//!   2. 完整性校验：从数据库读取历史快照时重新计算并比对，
//!      防止人工改库或迁移错误导致应用了被篡改的配置

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compile::{ResourceBundle, SCHEMA_VERSION};
use crate::config::GatewayConfig;
use crate::ConfigError;

/// 校验通过、可直接下发给数据面的配置快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledSnapshot {
    /// 配置 schema 版本（当前固定 `"v1"`）
    pub schema_version: String,
    /// 配置版本号（单调递增）
    pub config_version: u64,
    /// 资源集合的 SHA-256（小写十六进制）
    pub checksum: String,
    /// 规范化后的资源集合
    pub bundle: ResourceBundle,
}

impl CompiledSnapshot {
    /// 编译并校验资源集合。
    ///
    /// # 返回
    /// - `Ok(snapshot)`：校验通过
    /// - `Err(errors)`：所有校验错误（批量返回，便于控制面一次性展示）
    pub fn compile(
        bundle: ResourceBundle,
        config_version: u64,
    ) -> Result<Self, Vec<ConfigError>> {
        let bundle = bundle.canonicalized();
        // 复用 Phase 1/2 的完整校验规则；失败时不得生成快照
        bundle.validate()?;

        let checksum = bundle.checksum().map_err(|e| vec![e])?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.to_string(),
            config_version,
            checksum,
            bundle,
        })
    }

    /// 从已校验的 YAML 配置生成初始快照（数据面启动使用）。
    ///
    /// YAML 路径已经调用过 [`crate::validate`]，这里不重复校验，
    /// 只做规范化与 checksum 计算。
    pub fn from_gateway_config(
        cfg: &GatewayConfig,
        config_version: u64,
    ) -> Result<Self, ConfigError> {
        let bundle = ResourceBundle::from_gateway_config(cfg).canonicalized();
        let checksum = bundle.checksum()?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.to_string(),
            config_version,
            checksum,
            bundle,
        })
    }

    /// 校验 schema 版本。
    ///
    /// 数据面只接受自己认识的 schema 版本；不认识的版本必须拒绝应用，
    /// 而不是"尽力解析"。
    pub fn verify_schema(&self) -> Result<(), ConfigError> {
        if self.schema_version == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ConfigError {
                path: "schema_version".to_string(),
                message: format!(
                    "unsupported schema version '{}' (expected '{}')",
                    self.schema_version, SCHEMA_VERSION
                ),
            })
        }
    }

    /// 校验快照完整性：重新计算 checksum 并与存储值比对。
    pub fn verify_checksum(&self) -> Result<(), ConfigError> {
        let actual = self.bundle.checksum()?;
        if actual == self.checksum {
            Ok(())
        } else {
            Err(ConfigError {
                path: "checksum".to_string(),
                message: "snapshot checksum mismatch".to_string(),
            })
        }
    }

    /// 把快照中的资源合并到一个基础配置上。
    ///
    /// 基础配置提供 `gateway` / `server` / `runtime` / `observability` 等
    /// 与资源无关的字段；资源字段全部来自快照。
    pub fn merge_into(&self, base: &GatewayConfig) -> GatewayConfig {
        let mut merged = base.clone();
        merged.routes = self.bundle.routes.clone();
        merged.services = self.bundle.services.clone();
        merged.upstreams = self.bundle.upstreams.clone();
        merged.policies = self.bundle.policies.clone();
        merged
    }

    /// 序列化为 JSON（写入 `config_versions.snapshot`）。
    pub fn to_json(&self) -> Result<Value, ConfigError> {
        serde_json::to_value(self).map_err(|e| ConfigError {
            path: "snapshot".to_string(),
            message: format!("failed to serialize snapshot: {e}"),
        })
    }

    /// 从数据库 JSON 反序列化，并校验 schema 版本与 checksum。
    pub fn from_json(value: &Value) -> Result<Self, ConfigError> {
        let snapshot: Self = serde_json::from_value(value.clone()).map_err(|e| ConfigError {
            path: "snapshot".to_string(),
            message: format!("failed to parse snapshot: {e}"),
        })?;
        snapshot.verify_schema()?;
        snapshot.verify_checksum()?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use gateway_core::{EndpointConfig, PathType, ServiceConfig, UpstreamConfig};
    use serde_json::json;

    use super::*;
    use crate::config::PoliciesConfig;

    fn valid_bundle() -> ResourceBundle {
        ResourceBundle {
            routes: vec![gateway_core::RouteConfig {
                id: "r-1".into(),
                name: None,
                enabled: true,
                priority: 100,
                hosts: vec![],
                methods: vec![],
                path_type: PathType::Prefix,
                path_value: "/api".into(),
                header_matches: vec![],
                query_matches: vec![],
                service_id: "svc-1".into(),
                timeout_policy_id: None,
                auth_policy_id: None,
                rate_limit_policy_id: None,
                retry_policy_id: None,
                circuit_breaker_policy_id: None,
                cors_policy_id: None,
                path_rewrite: None,
                request_transform_id: None,
                response_transform_id: None,
            }],
            services: vec![ServiceConfig {
                id: "svc-1".into(),
                name: None,
                enabled: true,
                upstream_id: "up-1".into(),
            }],
            upstreams: vec![UpstreamConfig {
                id: "up-1".into(),
                name: None,
                enabled: true,
                algorithm: Default::default(),
                endpoints: vec![EndpointConfig {
                    id: None,
                    host: "127.0.0.1".into(),
                    port: 9000,
                    weight: 1,
                    zone: None,
                }],
            }],
            policies: PoliciesConfig::default(),
        }
    }

    #[test]
    fn compile_produces_snapshot_with_checksum() {
        let snapshot = CompiledSnapshot::compile(valid_bundle(), 7).expect("compile");
        assert_eq!(snapshot.config_version, 7);
        assert_eq!(snapshot.schema_version, SCHEMA_VERSION);
        assert_eq!(snapshot.checksum.len(), 64);
        snapshot.verify_schema().expect("schema");
        snapshot.verify_checksum().expect("checksum");
    }

    #[test]
    fn compile_rejects_invalid_reference() {
        let mut bundle = valid_bundle();
        bundle.routes[0].service_id = "missing".into();
        let errors = CompiledSnapshot::compile(bundle, 1).expect_err("invalid");
        assert!(errors.iter().any(|e| e.path.contains("routes")));
    }

    #[test]
    fn json_roundtrip_preserves_snapshot() {
        let snapshot = CompiledSnapshot::compile(valid_bundle(), 3).expect("compile");
        let value = snapshot.to_json().expect("to json");
        let decoded = CompiledSnapshot::from_json(&value).expect("from json");
        assert_eq!(decoded.config_version, 3);
        assert_eq!(decoded.checksum, snapshot.checksum);
    }

    #[test]
    fn tampered_snapshot_is_rejected() {
        let snapshot = CompiledSnapshot::compile(valid_bundle(), 3).expect("compile");
        let mut value = snapshot.to_json().expect("to json");
        // 篡改资源但不改 checksum
        value["bundle"]["routes"][0]["path_value"] = json!("/hacked");
        let err = CompiledSnapshot::from_json(&value).expect_err("tampered");
        assert_eq!(err.path, "checksum");
    }
}
