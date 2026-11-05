//! 平台化领域模型（Phase 7）。
//!
//! 这里的结构由控制面持久化、向数据面下发。它们不是「网关运行时」
//! 的必需部分（路由/上游才是），但控制面需要统一的强类型定义，
//! 避免在 API 层散落临时 JSON 结构。
//!
//! 与 `models.rs` 的区别：
//! - `models.rs` 是**数据面运行模型**（编译后进入快照）
//! - 本文件是**控制面平台资源**（租户、证书、集群、OpenAPI 文档等）

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TenantConfig —— 租户
// ---------------------------------------------------------------------------

/// 租户（多租户隔离的最小单元）。
///
/// 隔离模型：
/// - 资源（route/service/upstream）通过 `tenant_id` 归属租户
/// - 控制面按租户过滤列表与写入
/// - 数据面通过认证身份（JWT `tenant` 声明 / API Key 绑定租户）识别请求租户，
///   配额、审计、指标均按租户维度聚合
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// 租户 ID（全局唯一）
    pub id: String,
    /// 展示名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 每日请求配额（0 表示不限）
    #[serde(default)]
    pub daily_request_quota: u64,
    /// 允许使用的集群 ID 列表（空表示不限）
    #[serde(default)]
    pub allowed_clusters: Vec<String>,
    /// 描述
    #[serde(default)]
    pub description: Option<String>,
}

fn default_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// CertificateConfig —— TLS 证书
// ---------------------------------------------------------------------------

/// TLS 证书资源。
///
/// 私钥与证书链以 PEM 文本形式存储；控制面在写入前做格式校验，
/// 数据面启动时从配置中读取并构造 rustls ServerConfig。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// 证书 ID
    pub id: String,
    /// 展示名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 证书链 PEM（可包含中间证书）
    pub cert_pem: String,
    /// 私钥 PEM（PKCS#8 / RSA / ECDSA 均可）
    pub key_pem: String,
    /// 绑定的域名列表（SNI / 证书 SAN 校验）
    #[serde(default)]
    pub domains: Vec<String>,
    /// 证书到期时间（RFC3339，可选；由导入方提供）
    #[serde(default)]
    pub not_after: Option<String>,
}

// ---------------------------------------------------------------------------
// ApiSpecConfig —— OpenAPI 文档
// ---------------------------------------------------------------------------

/// OpenAPI 规范文档资源。
///
/// 存放原始文档（JSON 字符串），以及导入时使用的目标前缀。
/// 导入动作（`gateway-openapi` crate）会基于该文档生成
/// Service / Route / Upstream 草案，写入控制面后再发布。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSpecConfig {
    /// 文档 ID
    pub id: String,
    /// 展示名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用（禁用后导入接口拒绝）
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// OpenAPI 3.x 文档原文（JSON）
    pub spec: String,
    /// 导入时生成的 Service ID 前缀（默认 `openapi-{id}`）
    #[serde(default)]
    pub service_prefix: Option<String>,
    /// 默认上游 ID（导入生成的 Service 关联到该上游）
    pub upstream_id: String,
    /// 最近一次导入时间（RFC3339）
    #[serde(default)]
    pub imported_at: Option<String>,
}

// ---------------------------------------------------------------------------
// ClusterConfig —— 集群 / 地域
// ---------------------------------------------------------------------------

/// 集群资源（多集群 / 多地域编排的最小描述）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// 集群 ID
    pub id: String,
    /// 展示名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 所属地域，例如 `cn-east-1`
    pub region: String,
    /// 该集群控制面 gRPC 地址（数据面注册/心跳目标）
    #[serde(default)]
    pub control_plane_endpoint: Option<String>,
    /// 描述
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_defaults_are_safe() {
        let json = r#"{"id":"t1"}"#;
        let tenant: TenantConfig = serde_json::from_str(json).expect("deserialize tenant");
        assert!(tenant.enabled);
        assert_eq!(tenant.daily_request_quota, 0);
        assert!(tenant.allowed_clusters.is_empty());
    }

    #[test]
    fn certificate_requires_pem_fields() {
        let json = r#"{"id":"c1","cert_pem":"CERT","key_pem":"KEY"}"#;
        let cert: CertificateConfig = serde_json::from_str(json).expect("deserialize cert");
        assert_eq!(cert.cert_pem, "CERT");
        assert!(cert.enabled);
    }
}
