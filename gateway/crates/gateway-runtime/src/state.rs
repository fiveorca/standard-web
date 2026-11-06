//! 运行时配置快照存储（SnapshotStore）。
//!
//! # 为什么需要这一层
//!
//! Phase 1/2 的配置是启动时一次性加载：`Runtime` 直接持有 `RouteTable` 与
//! `UpstreamRegistry`。Phase 3 控制面要求"不重启网关即可更新配置"，
//! 因此把"运行时派生状态"（路由表 / 上游注册表 / Service→Upstream 映射 /
//! 已编译插件注册表）收敛进一个不可变快照 [`RuntimeState`]，用
//! [`ArcSwap`] 原子替换。
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
use gateway_plugin::PluginRegistry;
use gateway_resilience::{CircuitBreakerPlugin, CompiledRetryPolicy};
use gateway_routing::RouteTable;
use gateway_security::{build_cors_plugins, AuthPlugin, WafPlugin};
use gateway_traffic::{QuotaPlugin, RateLimitPlugin};
use gateway_transform::TransformPlugin;
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

    /// 插件编译失败（策略配置与编译期校验不一致）
    #[error("failed to compile plugins: {0}")]
    PluginCompile(String),

    /// TLS 证书解析失败（证书/私钥不匹配或 PEM 非法）
    #[error("failed to apply TLS certificates: {0}")]
    Tls(String),

    /// 应用锁被污染（说明上一次 apply 发生 panic）
    #[error("snapshot apply lock poisoned")]
    LockPoisoned,
}

/// 由配置快照派生出的数据面运行时状态（不可变）。
///
/// 一个请求只读取一次 `current()`，之后一直使用同一个 `Arc<RuntimeState>`，
/// 避免"路由用新配置、上游用旧配置"的撕裂读。
///
/// `plugins` 从快照的策略集合编译，与路由表/上游注册表同生命周期：
/// 热更新时整体原子替换，保证"路由与插件版本一致"。
/// `timeouts` 同理：每个 Route 的 `timeout_policy_id` 在这里可快速查。
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
    /// 已编译的插件注册表（按阶段取链执行）
    pub plugins: PluginRegistry,
    /// TimeoutPolicy：id → request_timeout Duration
    ///
    /// Route 通过 `timeout_policy_id` 引用；不存在或策略被禁用时
    /// 走 ProxyClient 的全局兜底超时
    pub timeouts: HashMap<String, std::time::Duration>,
    /// RetryPolicy：id → 已编译重试策略
    ///
    /// Route 通过 `retry_policy_id` 引用；Runtime 据此包裹
    /// "选 endpoint → forward" 循环，执行安全重试
    pub retries: HashMap<String, CompiledRetryPolicy>,
    /// Upstream 配置快照（含动态服务发现配置）。
    ///
    /// 服务发现后台任务每次 tick 从这里读取最新配置，
    /// 保证热更新后 discovery 配置也随快照变化。
    pub upstream_configs: Vec<gateway_core::UpstreamConfig>,
    /// TLS 证书资源快照（供运行时热更新 SNI 证书集合）。
    pub certificates: Vec<gateway_core::CertificateConfig>,
}

impl RuntimeState {
    /// 从编译快照构建运行时状态。
    ///
    /// 快照已经通过完整校验（引用完整性），因此这里不会出现"Service 指向
    /// 不存在的 Upstream"的情况；`RouteTable`/`UpstreamRegistry` 只做编译。
    ///
    /// 插件编译失败会返回 [`SnapshotApplyError::PluginCompile`]——
    /// 此时旧快照保持不变，调用方应把失败记录为实例应用失败。
    fn from_snapshot(snapshot: &CompiledSnapshot) -> Result<Self, SnapshotApplyError> {
        let route_table = RouteTable::compile(&snapshot.bundle.routes);
        // 多集群（Phase 7）：只加载属于本集群的上游。
        // 部署时通过 GATEWAY_CLUSTER_ID 指定；未设置时不过滤（单集群语义）。
        let local_cluster = std::env::var("GATEWAY_CLUSTER_ID").ok();
        let upstreams: Vec<gateway_core::UpstreamConfig> = snapshot
            .bundle
            .upstreams
            .iter()
            .filter(|u| match (&local_cluster, &u.cluster_id) {
                // 未指定本地集群 → 全部加载
                (None, _) => true,
                // 上游未绑定集群 → 视为公共上游，所有集群可用
                (_, None) => true,
                // 两者都有 → 必须匹配
                (Some(local), Some(target)) => local == target,
            })
            .cloned()
            .collect();
        let upstream_registry = UpstreamRegistry::new(&upstreams);
        let service_upstreams = snapshot
            .bundle
            .services
            .iter()
            // Phase 7：禁用或未发布的 Service 不对外可用
            .filter(|svc| svc.enabled && svc.lifecycle.is_servable())
            .map(|svc| (svc.id.clone(), svc.upstream_id.clone()))
            .collect();

        let plugins = build_plugin_registry(&snapshot.bundle.policies)?;
        // TimeoutPolicy 编译：id → Duration（request_timeout_ms 字段）
        let timeouts = snapshot
            .bundle
            .policies
            .timeout
            .iter()
            .filter(|p| p.enabled && !p.id.is_empty())
            .map(|p| (p.id.clone(), std::time::Duration::from_millis(p.request_timeout_ms)))
            .collect::<HashMap<_, _>>();

        // RetryPolicy 编译：id → CompiledRetryPolicy
        // Phase 2 核心：Runtime 据此包裹重试循环
        let retries: HashMap<String, CompiledRetryPolicy> = snapshot
            .bundle
            .policies
            .retry
            .iter()
            .filter(|p| p.enabled && !p.id.is_empty())
            .filter_map(|p| {
                CompiledRetryPolicy::compile(p)
                    .map_err(|reason| {
                        tracing::warn!(
                            target: "runtime",
                            retry_id = %p.id,
                            error = %reason,
                            "retry policy compile failed, skipping"
                        );
                    })
                    .ok()
            })
            .map(|compiled| (compiled.id.clone(), compiled))
            .collect();

        tracing::info!(
            target: "runtime",
            config_version = snapshot.config_version,
            checksum = %snapshot.checksum,
            routes = snapshot.bundle.routes.iter().filter(|r| r.enabled).count(),
            upstreams = snapshot.bundle.upstreams.len(),
            plugins = plugins.len(),
            timeouts = timeouts.len(),
            retries = retries.len(),
            "runtime snapshot prepared"
        );

        Ok(Self {
            config_version: snapshot.config_version,
            checksum: snapshot.checksum.clone(),
            route_table,
            upstream_registry,
            service_upstreams,
            plugins,
            timeouts,
            retries,
            upstream_configs: upstreams,
            certificates: snapshot.bundle.certificates.clone(),
        })
    }

    /// 取指定阶段的插件链（空链也合法，run 直接放行）。
    pub fn chain(&self, phase: gateway_plugin::PluginPhase) -> gateway_plugin::PluginChain {
        self.plugins.chain_for_phase(phase)
    }
}

// ---------------------------------------------------------------------------
// 插件注册表构建
// ---------------------------------------------------------------------------

/// 从策略集合编译全部内置插件并注册到 [`PluginRegistry`]。
///
/// 当前注册的 Phase 2 插件：
/// | 插件 | 阶段 | 作用 |
/// |---|---|---|
/// | auth | Authentication | JWT / API Key / Basic / IP 黑白名单 |
/// | cors_request | RequestPostRoute | OPTIONS 预检（短路 204 / 403 / 405）|
/// | cors_response | ResponsePreClient | 追加 ACAO / ACAC / ACEH / Vary: Origin |
/// | rate_limit | RequestPostRoute | Token Bucket / Fixed Window |
/// | circuit_breaker_guard | RequestPreUpstream | 熔断前置拦截 |
/// | circuit_breaker_record | UpstreamResponse | 熔断结果记账 |
/// | request_transform | RequestPreUpstream | 请求 Header 改写 |
/// | response_transform | ResponsePreClient | 响应 Header 改写 |
fn build_plugin_registry(
    policies: &gateway_config::PoliciesConfig,
) -> Result<PluginRegistry, SnapshotApplyError> {
    let mut registry = PluginRegistry::new();

    // 鉴权：JWT / API Key / Basic / IP 过滤（单一插件按策略类型分发）
    let auth = AuthPlugin::from_configs(&policies.auth)
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("auth plugin: {e}")))?;
    registry
        .register(Arc::new(auth))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register auth: {e}")))?;

    // 限流：Token Bucket / Fixed Window
    let rl = RateLimitPlugin::from_configs(&policies.rate_limit)
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("rate_limit plugin: {e}")))?;
    registry
        .register(Arc::new(rl))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register rate_limit: {e}")))?;

    // WAF：策略为空时跳过注册
    if !policies.waf.is_empty() {
        let waf = WafPlugin::from_configs(&policies.waf)
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("waf plugin: {e}")))?;
        registry
            .register(Arc::new(waf))
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("register waf: {e}")))?;
    }

    // 配额：策略为空时跳过注册
    if !policies.quota.is_empty() {
        let quota = QuotaPlugin::from_configs(&policies.quota)
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("quota plugin: {e}")))?;
        registry
            .register(Arc::new(quota))
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("register quota: {e}")))?;
    }

    // CORS：两个实例（预检 + 响应头），共享同一已编译策略表；
    // 策略为空时跳过注册（避免空插件进链浪费每次调用的类型检查）
    if !policies.cors.is_empty() {
        let (cors_req, cors_resp) = build_cors_plugins(&policies.cors)
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("cors plugin: {e}")))?;
        registry
            .register(Arc::new(cors_req))
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("register cors_req: {e}")))?;
        registry
            .register(Arc::new(cors_resp))
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("register cors_resp: {e}")))?;
    }

    // 熔断：guard（前置拦截）+ record（后置记账）共享同一熔断器表
    let (cb_guard, cb_record) = CircuitBreakerPlugin::from_configs(&policies.circuit_breaker)
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("circuit_breaker plugin: {e}")))?;
    registry
        .register(Arc::new(cb_guard))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register cb_guard: {e}")))?;
    registry
        .register(Arc::new(cb_record))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register cb_record: {e}")))?;

    // Header 转换：请求方向 + 响应方向两个实例，共享同一编译策略表
    let (req_t, resp_t) =
        TransformPlugin::from_configs(&policies.request_transform, &policies.response_transform)
            .map_err(|e| SnapshotApplyError::PluginCompile(format!("transform plugin: {e}")))?;
    registry
        .register(Arc::new(req_t))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register req_transform: {e}")))?;
    registry
        .register(Arc::new(resp_t))
        .map_err(|e| SnapshotApplyError::PluginCompile(format!("register resp_transform: {e}")))?;

    Ok(registry)
}

// ---------------------------------------------------------------------------
// SnapshotStore
// ---------------------------------------------------------------------------

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
        Self::from_config_with_version(cfg, INITIAL_CONFIG_VERSION)
    }

    /// 使用指定初始版本构建快照。
    ///
    /// 控制面模式（`control_plane.enabled = true`）下，本地 YAML 只作为
    /// "引导配置"，初始版本传 0，保证控制面发布的 v1 快照不会被
    /// `apply` 的版本单调性检查误判为 stale。
    pub fn from_config_with_version(
        cfg: &GatewayConfig,
        config_version: u64,
    ) -> Result<Self, ConfigError> {
        let snapshot = CompiledSnapshot::from_gateway_config(cfg, config_version)?;
        Self::from_snapshot(&snapshot).map_err(|e| ConfigError {
            path: "plugins".to_string(),
            message: e.to_string(),
        })
    }

    /// 从已编译快照构建存储（初始状态）。
    ///
    /// 插件编译失败会返回 [`SnapshotApplyError::PluginCompile`]。
    pub fn from_snapshot(snapshot: &CompiledSnapshot) -> Result<Self, SnapshotApplyError> {
        Ok(Self {
            current: ArcSwap::from_pointee(RuntimeState::from_snapshot(snapshot)?),
            apply_lock: Mutex::new(()),
        })
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
    /// 2. 构建新状态（插件编译失败直接返回，旧快照不变）
    /// 3. 在锁内校验版本单调递增并 store
    ///
    /// 任何一步失败都不会修改当前快照。
    pub fn apply(&self, snapshot: &CompiledSnapshot) -> Result<u64, SnapshotApplyError> {
        snapshot.verify_schema().map_err(|e| SnapshotApplyError::Schema(e.message))?;

        // 先在锁外构建新状态（可能因插件编译失败而失败），
        // 保证失败时旧快照完全不变。
        let next = Arc::new(RuntimeState::from_snapshot(snapshot)?);

        let guard = self.apply_lock.lock().map_err(|_| SnapshotApplyError::LockPoisoned)?;
        let current = self.current.load();
        if snapshot.config_version <= current.config_version {
            return Err(SnapshotApplyError::StaleVersion {
                incoming: snapshot.config_version,
                current: current.config_version,
            });
        }

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
    use gateway_config::{PoliciesConfig, ResourceBundle};
    use gateway_core::{EndpointConfig, PathType, RouteConfig, ServiceConfig, UpstreamConfig};

    use super::*;

    fn bundle() -> ResourceBundle {
        ResourceBundle {
            routes: vec![RouteConfig {
                id: "r-1".into(),
                name: None,
                tenant_id: None,
                lifecycle: gateway_core::LifecycleStatus::Published,
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
                traffic_split: None,
                mirror: None,
                // Phase 7：测试不使用 WAF / 配额
                waf_policy_id: None,
                quota_policy_id: None,
                request_transform_id: None,
                response_transform_id: None,
            }],
            services: vec![ServiceConfig {
                id: "svc-1".into(),
                name: None,
                tenant_id: None,
                lifecycle: gateway_core::LifecycleStatus::Published,
                enabled: true,
                upstream_id: "up-1".into(),
            }],
            upstreams: vec![UpstreamConfig {
                id: "up-1".into(),
                name: None,
                tenant_id: None,
                cluster_id: None,
                enabled: true,
                algorithm: Default::default(),
                endpoints: vec![EndpointConfig {
                    id: None,
                    host: "127.0.0.1".into(),
                    port: 9000,
                    weight: 1,
                    zone: None,
                    region: None,
                }],
                discovery: None,
                health_check: None,
            }],
            certificates: vec![],
            policies: PoliciesConfig::default(),
        }
    }

    fn snapshot(version: u64) -> CompiledSnapshot {
        CompiledSnapshot::compile(bundle(), version).expect("compile snapshot")
    }

    #[test]
    fn apply_replaces_state_and_rejects_stale_versions() {
        let store = SnapshotStore::from_snapshot(&snapshot(1)).expect("init");
        assert_eq!(store.config_version(), 1);

        assert_eq!(store.apply(&snapshot(2)).expect("apply v2"), 2);
        assert_eq!(store.config_version(), 2);

        let err = store.apply(&snapshot(2)).expect_err("stale");
        assert!(matches!(err, SnapshotApplyError::StaleVersion { .. }));
        assert_eq!(store.config_version(), 2);
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let store = SnapshotStore::from_snapshot(&snapshot(1)).expect("init");
        let mut incoming = snapshot(5);
        incoming.schema_version = "v9".into();

        let err = store.apply(&incoming).expect_err("schema");
        assert!(matches!(err, SnapshotApplyError::Schema(_)));
        assert_eq!(store.config_version(), 1);
    }

    #[test]
    fn plugins_are_built_into_runtime_state() {
        let snap = snapshot(1);
        let state = RuntimeState::from_snapshot(&snap).expect("state");
        // 空策略集合下，auth + rate_limit + cors（跳过）+ cb_guard + cb_record +
        // req_transform + resp_transform = 6 个已注册插件
        assert!(state.plugins.len() >= 6);
    }
}
