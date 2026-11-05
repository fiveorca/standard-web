//! 配置资源集合与编译入口。
//!
//! # 背景
//!
//! Phase 1/2 的配置来源是 YAML 文件，编译在 `gateway-runtime` 内部完成。
//! Phase 3 引入控制面后，配置来源变成数据库中的资源集合，需要一套
//! **与来源无关**的编译流程：
//!
//! ```text
//! 资源集合（routes/services/upstreams/policies）
//!         │
//!         ├── canonicalized()   ← 按 ID 排序，保证 checksum 稳定
//!         ├── validate()        ← 复用 Phase 1/2 的全部校验规则
//!         └── checksum()        ← SHA-256(canonical JSON)
//! ```
//!
//! 这样无论配置来自 YAML 还是控制面 API，进入数据面之前都经过同一套校验，
//! 保证"无效配置无法生效"（Phase 3 验收项）。
//!
//! # 为什么复用 `validator::validate`
//!
//! [`crate::validate`] 已经覆盖了 ID 唯一性、引用完整性、路由冲突、
//! 策略安全约束（算法白名单/幂等重试/CORS 冲突/Header 注入）等规则。
//! 重新实现一套规则必然出现"两套校验不一致"的漏洞，因此这里只是把
//! 资源集合装配成 [`GatewayConfig`]，再调用同一入口。

use gateway_core::{
    AuthPolicyConfig, CircuitBreakerPolicyConfig, CorsPolicyConfig, EndpointConfig,
    RateLimitPolicyConfig, RetryPolicyConfig, RouteConfig, ServiceConfig, TimeoutPolicyConfig,
    TransformPolicyConfig, UpstreamConfig,
};
use serde::{Deserialize, Serialize};

use crate::config::{GatewayConfig, PoliciesConfig};
use crate::ConfigError;

/// 当前配置 schema 版本。
///
/// 数据面读到不认识的 `schema_version` 时必须拒绝应用。
pub const SCHEMA_VERSION: &str = "v1";

/// 一次发布所涉及的完整资源集合。
///
/// 泛型参数顺序与 YAML 结构保持一致，方便从 [`GatewayConfig`] 直接转换。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceBundle {
    /// 路由
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// 后端服务
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// 上游
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    /// 治理策略
    #[serde(default)]
    pub policies: PoliciesConfig,
}

impl ResourceBundle {
    /// 从已加载的 [`GatewayConfig`] 提取资源集合（YAML 模式使用）。
    pub fn from_gateway_config(cfg: &GatewayConfig) -> Self {
        Self {
            routes: cfg.routes.clone(),
            services: cfg.services.clone(),
            upstreams: cfg.upstreams.clone(),
            policies: cfg.policies.clone(),
        }
    }

    /// 规范化：按 ID 排序所有资源与策略。
    ///
    /// 数据面不关心顺序（RouteTable 会重新按优先级排序），但 checksum
    /// 必须对"相同的配置集合"稳定——否则数据库中资源行的读取顺序变化
    /// 会导致同一份配置产生不同 checksum，破坏版本比对。
    pub fn canonicalized(mut self) -> Self {
        self.routes.sort_by(|a, b| a.id.cmp(&b.id));
        self.services.sort_by(|a, b| a.id.cmp(&b.id));
        self.upstreams.sort_by(|a, b| a.id.cmp(&b.id));

        // 端点顺序影响 Round-Robin 的起点，这里按地址排序保证确定性
        for upstream in &mut self.upstreams {
            upstream.endpoints.sort_by_key(endpoint_key);
        }

        self.policies.auth.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.rate_limit.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.timeout.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.retry.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.circuit_breaker.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.cors.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.request_transform.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.response_transform.sort_by(|a, b| a.id.cmp(&b.id));
        // Phase 7：WAF / 配额策略参与 checksum，必须稳定排序
        self.policies.waf.sort_by(|a, b| a.id.cmp(&b.id));
        self.policies.quota.sort_by(|a, b| a.id.cmp(&b.id));

        self
    }

    /// 装配成 [`GatewayConfig`]，供 [`crate::validate`] 复用全部校验规则。
    ///
    /// `gateway` / `server` / `runtime` / `observability` 等字段使用默认值：
    /// 它们与"可变配置资源"无关，控制面发布只替换资源部分。
    pub fn to_gateway_config(&self) -> GatewayConfig {
        GatewayConfig {
            gateway: Default::default(),
            server: Default::default(),
            runtime: Default::default(),
            observability: Default::default(),
            control_plane: Default::default(),
            upstreams: self.upstreams.clone(),
            services: self.services.clone(),
            routes: self.routes.clone(),
            policies: self.policies.clone(),
        }
    }

    /// 执行业务校验（ID 唯一性 / 引用完整性 / 路由冲突 / 策略安全约束）。
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        crate::validate(&self.to_gateway_config())
    }

    /// 计算规范化后的 SHA-256 checksum。
    ///
    /// 序列化失败意味着配置类型无法序列化（属于内部错误），返回
    /// [`ConfigError`] 而不是 panic。
    pub fn checksum(&self) -> Result<String, ConfigError> {
        let canonical = self.clone().canonicalized();
        let bytes = serde_json::to_vec(&canonical).map_err(|e| ConfigError {
            path: "checksum".to_string(),
            message: format!("failed to serialize resource bundle: {e}"),
        })?;
        Ok(sha256_hex(&bytes))
    }
}

/// 计算 SHA-256 并转为小写十六进制字符串。
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;

    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    // write! 到 String 不会失败（String 的 fmt::Write 实现总是 Ok），
    // 但生产代码禁止 unwrap，这里忽略返回值。
    use std::fmt::Write;
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// 端点排序键：`host:port` + 可选 ID。
///
/// 不直接实现 `Ord`，避免影响 gateway-core 的领域模型。
fn endpoint_key(endpoint: &EndpointConfig) -> (String, u16, String) {
    (
        endpoint.host.clone(),
        endpoint.port,
        endpoint.id.clone().unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// 类型别名：让控制面服务按资源类型加载时不必重复写长泛型
// ---------------------------------------------------------------------------

/// 路由资源集合。
pub type Routes = Vec<RouteConfig>;
/// 服务资源集合。
pub type Services = Vec<ServiceConfig>;
/// 上游资源集合。
pub type Upstreams = Vec<UpstreamConfig>;
/// 鉴权策略集合。
pub type AuthPolicies = Vec<AuthPolicyConfig>;
/// 限流策略集合。
pub type RateLimitPolicies = Vec<RateLimitPolicyConfig>;
/// 超时策略集合。
pub type TimeoutPolicies = Vec<TimeoutPolicyConfig>;
/// 重试策略集合。
pub type RetryPolicies = Vec<RetryPolicyConfig>;
/// 熔断策略集合。
pub type CircuitBreakerPolicies = Vec<CircuitBreakerPolicyConfig>;
/// CORS 策略集合。
pub type CorsPolicies = Vec<CorsPolicyConfig>;
/// Header 转换策略集合。
pub type TransformPolicies = Vec<TransformPolicyConfig>;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use gateway_core::{PathType, LoadBalanceAlgorithm};

    fn service(id: &str) -> ServiceConfig {
        ServiceConfig {
            id: id.into(),
            name: None,
            tenant_id: None,
            lifecycle: gateway_core::LifecycleStatus::Published,
            enabled: true,
            upstream_id: "up-1".into(),
        }
    }

    fn upstream(id: &str) -> UpstreamConfig {
        UpstreamConfig {
            id: id.into(),
            name: None,
            tenant_id: None,
            cluster_id: None,
            enabled: true,
            algorithm: LoadBalanceAlgorithm::RoundRobin,
            endpoints: vec![EndpointConfig {
                id: Some("ep-1".into()),
                host: "127.0.0.1".into(),
                port: 9000,
                weight: 1,
                zone: None,
                region: None,
            }],
            discovery: None,
        }
    }

    fn route(id: &str, service_id: &str) -> RouteConfig {
        RouteConfig {
            id: id.into(),
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
            service_id: service_id.into(),
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
        }
    }

    #[test]
    fn checksum_is_order_independent() {
        let mut a = ResourceBundle {
            routes: vec![route("r-2", "svc-1"), route("r-1", "svc-1")],
            services: vec![service("svc-1")],
            upstreams: vec![upstream("up-1")],
            policies: PoliciesConfig::default(),
        };
        let checksum_a = a.checksum().expect("checksum");

        // 交换顺序后 checksum 必须相同
        a.routes.reverse();
        assert_eq!(a.checksum().expect("checksum"), checksum_a);
    }

    #[test]
    fn invalid_reference_is_rejected() {
        let bundle = ResourceBundle {
            routes: vec![route("r-1", "missing-svc")],
            services: vec![service("svc-1")],
            upstreams: vec![upstream("up-1")],
            policies: PoliciesConfig::default(),
        };
        let errors = bundle.validate().expect_err("must fail");
        assert!(!errors.is_empty());
    }

    #[test]
    fn valid_bundle_passes_and_config_matches() {
        let bundle = ResourceBundle {
            routes: vec![route("r-1", "svc-1")],
            services: vec![service("svc-1")],
            upstreams: vec![upstream("up-1")],
            policies: PoliciesConfig::default(),
        };
        bundle.validate().expect("valid");
        let cfg = bundle.to_gateway_config();
        assert_eq!(cfg.routes.len(), 1);
        // 资源集合与 JSON 往返保持等价
        let encoded = serde_json::to_value(&bundle).expect("serialize");
        assert_eq!(encoded["routes"][0]["id"], json!("r-1"));
    }
}
