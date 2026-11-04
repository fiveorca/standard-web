//! 运行时配置快照存储（SnapshotStore）。
//!
//! # 为什么需要这一层
//!
//! Phase 1/2 的配置是启动时一次性加载：`Runtime` 直接持有 `RouteTable` 与
//! `UpstreamRegistry`。Phase 3 控制面要求"不重启网关即可更新配置"，
//! 因此把"运行时派生状态"（路由表 / 上游注册表 / Service→Upstream 映射）
//! 收敛进一个不可变快照 [`RuntimeState`]，用 [`ArcSwap`] 原子替换。
//!
//! # 并发语义
//!
//! - 读路径：`current()` 做一次无锁 `ArcSwap::load`，拿到当前快照的 `Arc`。
//!   请求过程中即使发生替换，本次请求仍然使用旧快照，天然一致。
//! - 写路径：`apply()` 在 `apply_lock` 串行化，校验版本单调递增后一次性
//!   `store`。失败时旧快照保持不变。
//! - 版本单调：拒绝 `config_version <= current` 的快照，防止控制面重复
//!   下发或乱序下发导致旧配置覆盖新配置。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use gateway_config::{CompiledSnapshot, ConfigError, GatewayConfig};
use gateway_routing::RouteTable;
use gateway_upstream::UpstreamRegistry;
use thiserror::Error;

/// YAML 启动配置的初始版本号。
pub const INITIAL_CONFIG_VERSION: u64 = 1;

/// 快照应用错误。
#[derive(Debug, Error)]
pub enum SnapshotApplyError {
    /// schema 版本不受支持
    #[error("snapshot schema mismatch: {0}")]
    Schema(String),

    /// 快照版本不比当前版本新
    #[error("snapshot version {incoming} is not newer than current version {current}")]
    StaleVersion {
        /// 待应用版本
        incoming: u64,
        /// 当前版本
        current: u64,
    },

    /// 应用锁被污染（说明上一次 apply 发生 panic）
    #[error("snapshot apply lock poisoned")]
    LockPoisoned,
}

/// 由配置快照派生出的数据面运行时状态（不可变）。
///
/// 一个请求只读取一次 `current()`，之后一直使用同一个 `Arc<RuntimeState>`，
/// 避免"路由用新配置、上游用旧配置"的撕裂读。
pub struct RuntimeState {
    /// 当前生效的配置版本号
    pub config_version: u64,
    /// 当前生效配置的 checksum
    pub checksum: String,
    /// 编译好的路由表
    pub route_table: RouteTable,
    /// 上游注册表
    pub upstream_registry: UpstreamRegistry,
    /// Service → Upstream 引用解析表
    pub service_upstreams: HashMap<String, String>,
}

impl RuntimeState {
    /// 从编译快照构建运行时状态。
    ///
    /// 快照已经通过完整校验（引用完整性），因此这里不会出现"Service 指向
    /// 不存在的 Upstream"的情况；`RouteTable`/`UpstreamRegistry` 只做编译。
    fn from_snapshot(snapshot: &CompiledSnapshot) -> Self {
        let route_table = RouteTable::compile(&snapshot.bundle.routes);
        let upstream_registry = UpstreamRegistry::new(&snapshot.bundle.upstreams);
        let service_upstreams = snapshot
            .bundle
            .services
            .iter()
            .map(|svc| (svc.id.clone(), svc.upstream_id.clone()))
            .collect();

        tracing::info!(
            target: "runtime",
            config_version = snapshot.config_version,
            checksum = %snapshot.checksum,
            routes = snapshot.bundle.routes.iter().filter(|r| r.enabled).count(),
            upstreams = snapshot.bundle.upstreams.len(),
            "runtime snapshot prepared"
        );

        Self {
            config_version: snapshot.config_version,
            checksum: snapshot.checksum.clone(),
            route_table,
            upstream_registry,
            service_upstreams,
        }
    }
}

/// 原子配置快照存储。
pub struct SnapshotStore {
    /// 当前运行时状态（原子交换）
    current: ArcSwap<RuntimeState>,
    /// 应用串行锁：保证版本比较与 store 的原子性
    apply_lock: Mutex<()>,
}

impl SnapshotStore {
    /// 从 YAML 配置构建初始快照（版本号固定为 [`INITIAL_CONFIG_VERSION`]）。
    pub fn from_config(cfg: &GatewayConfig) -> Result<Self, ConfigError> {
        let snapshot = CompiledSnapshot::from_gateway_config(cfg, INITIAL_CONFIG_VERSION)?;
        Ok(Self::from_snapshot(&snapshot))
    }

    /// 从已编译快照构建存储（初始状态）。
    pub fn from_snapshot(snapshot: &CompiledSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(RuntimeState::from_snapshot(snapshot)),
            apply_lock: Mutex::new(()),
        }
    }

    /// 读取当前快照。
    pub fn current(&self) -> Arc<RuntimeState> {
        self.current.load_full()
    }

    /// 当前配置版本号。
    pub fn config_version(&self) -> u64 {
        self.current.load().config_version
    }

    /// 当前配置 checksum。
    pub fn checksum(&self) -> String {
        self.current.load().checksum.clone()
    }

    /// 原子应用新快照。
    ///
    /// # 校验顺序
    /// 1. schema 版本（拒绝不认识的格式）
    /// 2. 版本单调性（拒绝旧版本）
    /// 3. 构建新状态并一次性替换
    ///
    /// 任何一步失败都不会修改当前快照。
    pub fn apply(&self, snapshot: &CompiledSnapshot) -> Result<u64, SnapshotApplyError> {
        snapshot
            .verify_schema()
            .map_err(|e| SnapshotApplyError::Schema(e.message))?;

        let guard = self.apply_lock.lock().map_err(|_| SnapshotApplyError::LockPoisoned)?;
        let current = self.current.load();
        if snapshot.config_version <= current.config_version {
            return Err(SnapshotApplyError::StaleVersion {
                incoming: snapshot.config_version,
                current: current.config_version,
            });
        }

        let next = Arc::new(RuntimeState::from_snapshot(snapshot));
        self.current.store(next);
        drop(guard);

        tracing::info!(
            target: "runtime",
            config_version = snapshot.config_version,
            "configuration hot-reloaded"
        );
        Ok(snapshot.config_version)
    }
}

#[cfg(test)]
mod tests {
    use gateway_config::ResourceBundle;
    use gateway_core::{EndpointConfig, PathType, RouteConfig, ServiceConfig, UpstreamConfig};

    use super::*;
    use gateway_config::PoliciesConfig;

    fn bundle() -> ResourceBundle {
        ResourceBundle {
            routes: vec![RouteConfig {
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

    fn snapshot(version: u64) -> CompiledSnapshot {
        CompiledSnapshot::compile(bundle(), version).expect("compile snapshot")
    }

    #[test]
    fn apply_replaces_state_and_rejects_stale_versions() {
        let store = SnapshotStore::from_snapshot(&snapshot(1));
        assert_eq!(store.config_version(), 1);

        assert_eq!(store.apply(&snapshot(2)).expect("apply v2"), 2);
        assert_eq!(store.config_version(), 2);

        // 旧版本被拒绝，当前状态保持 v2
        let err = store.apply(&snapshot(2)).expect_err("stale");
        assert!(matches!(err, SnapshotApplyError::StaleVersion { .. }));
        assert_eq!(store.config_version(), 2);
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let store = SnapshotStore::from_snapshot(&snapshot(1));
        let mut incoming = snapshot(5);
        incoming.schema_version = "v9".into();

        let err = store.apply(&incoming).expect_err("schema");
        assert!(matches!(err, SnapshotApplyError::Schema(_)));
        assert_eq!(store.config_version(), 1);
    }

    #[test]
    fn checksum_is_preserved_from_snapshot() {
        let snap = snapshot(3);
        let store = SnapshotStore::from_snapshot(&snap);
        assert_eq!(store.checksum(), snap.checksum);

        // 快照的 bundle 可独立序列化（控制面把它写入 config_versions.snapshot）
        let value = serde_json::to_value(&snap.bundle).expect("serialize bundle");
        assert_eq!(value["routes"].as_array().map(Vec::len), Some(1));
    }
}
