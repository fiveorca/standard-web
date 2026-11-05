//! 鉴权模块共享的数据视图与结果类型。
//!
//! 本模块只放"跨子策略复用"的纯数据类型，不含任何 IO 与状态：
//!
//! ```text
//! AuthRequestView  ← 插件把 &Parts + client_ip 汇总成一个只读视图
//! AuthIdentity     ← 认证通过后写入 parts.extensions 的身份（授权插件消费）
//! AuthRejection    ← 认证/授权失败的结构化结果（含 401/403 与 WWW-Authenticate）
//! Credential       ← 凭据抽取结果（缺失 / 格式非法 / 已取到）
//! ```
//!
//! # 敏感信息约束
//!
//! `AuthIdentity` 只允许承载**不可逆或非机密**的标识：
//!   - Basic 的用户名可以承载（它是身份，不是密码）
//!   - JWT 的 `sub` 可以承载
//!   - API Key / 密码 / JWT 原始串 **绝对禁止**进入 Identity 或日志

use std::borrow::Cow;
use std::net::SocketAddr;

use gateway_common::ErrorCode;
use http::{HeaderMap, StatusCode, Uri};
use subtle::{Choice, ConstantTimeEq};

// ---------------------------------------------------------------------------
// 认证机制
// ---------------------------------------------------------------------------

/// 认证机制标识。
///
/// 用于日志标签、身份来源追踪，以及授权阶段的"该身份来自哪条策略"判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMechanism {
    /// IP 黑白名单（不产生身份，只做网络层准入）
    Ip,
    /// HTTP Basic（RFC 7617）
    Basic,
    /// API Key（Header 或 Query）
    ApiKey,
    /// JWT（静态 HMAC 密钥 + 算法白名单）
    Jwt,
}

impl AuthMechanism {
    /// 稳定的字符串表示，用于日志与指标标签。
    ///
    /// 手工实现而非派生 `Serialize`，避免为日志引入序列化开销，
    /// 同时保证命名风格与策略 YAML 中的 `type` 字段一致。
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMechanism::Ip => "ip",
            AuthMechanism::Basic => "basic",
            AuthMechanism::ApiKey => "api_key",
            AuthMechanism::Jwt => "jwt",
        }
    }
}

// ---------------------------------------------------------------------------
// 认证身份
// ---------------------------------------------------------------------------

/// 认证通过后产出的身份。
///
/// 由 `AuthPlugin` 写入 `request::Parts::extensions`，供后续的
/// Authorization 阶段插件（以及 Phase 3 的 Consumer 映射）读取。
///
/// `Extensions` 要求类型满足 `Clone + Send + Sync + 'static`：
/// 本结构体只含 `String` 与 `Copy` 枚举，天然满足。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity {
    /// 产生该身份的认证机制
    pub mechanism: AuthMechanism,
    /// 主体标识（Basic 用户名 / JWT 的 `sub`）。IP 与无 label 的 API Key 为 `None`
    pub subject: Option<String>,
    /// 可读标签（API Key 配置中的 `label`），用于日志中替代密钥明文
    pub label: Option<String>,
    /// 所属租户（Phase 7）：
    ///   - API Key：策略条目上绑定的 `tenant_id`
    ///   - JWT：`tenant` / `tenant_id` 声明
    pub tenant_id: Option<String>,
}

impl AuthIdentity {
    /// 以指定机制创建空身份。
    ///
    /// 参数：
    /// - `mechanism`：认证机制（决定了后续可用的字段语义）
    pub fn new(mechanism: AuthMechanism) -> Self {
        Self {
            mechanism,
            subject: None,
            label: None,
            tenant_id: None,
        }
    }

    /// 设置主体标识（链式调用）。
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// 设置可读标签（链式调用）。
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// 设置所属租户（链式调用）。
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }
}

// ---------------------------------------------------------------------------
// 鉴权失败
// ---------------------------------------------------------------------------

/// 认证/授权失败的结构化描述。
///
/// 之所以不直接返回 `PluginResponse`：
///   - 子策略（IP/Basic/API Key/JWT）不应该知道 JSON 错误格式与 body 类型
///   - 由 `AuthPlugin` 统一用 `PluginResponse::from_error` 生成一致的 JSON
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRejection {
    /// HTTP 状态码：未认证 401、无权限 403
    pub status: StatusCode,
    /// 稳定错误码（来自 `gateway-common::ErrorCode`，避免散落的魔法字符串）
    pub code: ErrorCode,
    /// 返回给客户端的描述（**不得包含凭据、密钥或内部堆栈**）
    pub message: String,
    /// 可选的 `WWW-Authenticate` 挑战值（仅 401 使用）
    pub challenge: Option<String>,
}

impl AuthRejection {
    /// 构造"未认证"（401）失败。
    ///
    /// 参数：
    /// - `message`：脱敏后的描述
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            // 401 对应 Design §11：GATEWAY_AUTHENTICATION_FAILED
            code: ErrorCode::GatewayAuthenticationFailed,
            message: message.into(),
            challenge: None,
        }
    }

    /// 构造"无权限"（403）失败。
    ///
    /// 语义区别：401 表示"没有证明你是谁"，403 表示"已证明，但不允许访问"。
    /// IP 名单属于后者（身份无关，只是准入拒绝）。
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            // 403 对应 Design §11：GATEWAY_AUTHORIZATION_FAILED
            code: ErrorCode::GatewayAuthorizationFailed,
            message: message.into(),
            challenge: None,
        }
    }

    /// 追加 `WWW-Authenticate` 挑战（链式调用）。
    ///
    /// 参数：
    /// - `challenge`：符合 RFC 7235 的挑战值，例如 `Bearer`、
    ///   `Basic realm="gateway"`
    pub fn with_challenge(mut self, challenge: impl Into<String>) -> Self {
        self.challenge = Some(challenge.into());
        self
    }
}

// ---------------------------------------------------------------------------
// 请求视图
// ---------------------------------------------------------------------------

/// 鉴权所需的最小请求视图。
///
/// 只暴露 headers / uri / client_ip 三样东西：
///   - 不暴露 method（鉴权不看方法）
///   - 不暴露 body（流式 body 不能被安全插件读取，避免内存放大）
///
/// `Copy` 让插件在多个子策略间传递时无需借用管理。
#[derive(Debug, Clone, Copy)]
pub struct AuthRequestView<'a> {
    /// 请求头（已由 Network 层解析为 `HeaderMap`）
    pub headers: &'a HeaderMap,
    /// 请求 URI（`query_param` 读取方式需要解析 query 段）
    pub uri: &'a Uri,
    /// 客户端地址（由 Network 层注入；进程内调用可能为 `None`）
    pub client_ip: Option<SocketAddr>,
}

// ---------------------------------------------------------------------------
// 凭据抽取
// ---------------------------------------------------------------------------

/// 凭据抽取结果。
///
/// 区分"缺失"与"格式非法"是为了给出准确错误信息：
///   - `Missing`：请求根本没带凭据（是否放行取决于策略的 `required`）
///   - `Malformed`：带了但无法解析（一律视为无效凭据）
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Credential<'a> {
    /// 请求未提供凭据
    Missing,
    /// 提供了凭据但格式非法（非 UTF-8、缺少 scheme 等）
    Malformed,
    /// 成功取到凭据值
    Value(Cow<'a, str>),
}

// ---------------------------------------------------------------------------
// 常量时间比较
// ---------------------------------------------------------------------------

/// 常量时间字符串比较。
///
/// # 为什么需要它
/// 普通的 `==` 会在第一个不同字符处提前返回，攻击者可通过响应时间差
/// 逐字节猜解 API Key / 密码。`subtle::ConstantTimeEq` 保证比较耗时
/// 只与**长度**相关，与内容无关。
///
/// # 长度侧信道
/// 长度差异本身仍可被观测。这是所有常量时间字符比较的共性限制：
/// 防御手段是"配置的凭据长度固定/足够长"，而不是在比较函数里补救。
///
/// 参数：
/// - `provided`：请求带来的值
/// - `expected`：配置中的期望值
pub(crate) fn constant_time_eq_str(provided: &str, expected: &str) -> Choice {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    // 长度不同时直接返回"不相等"；`Choice::from(0)` 是 subtle 的常量 0
    if a.len() != b.len() {
        return Choice::from(0);
    }
    // 长度相同：逐字节常量时间比较（底层为位运算，无 early return）
    a.ct_eq(b)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 401 与 403 的错误码必须分别映射到"未认证/无权限"
    #[test]
    fn rejection_status_and_code_pairs() {
        let unauthorized = AuthRejection::unauthenticated("no token");
        assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized.code,
            ErrorCode::GatewayAuthenticationFailed
        );

        let forbidden = AuthRejection::forbidden("ip denied");
        assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
        assert_eq!(forbidden.code, ErrorCode::GatewayAuthorizationFailed);
    }

    /// 常量时间比较语义正确：相同为真、不同为假、长度不同为假
    #[test]
    fn constant_time_comparison_semantics() {
        assert!(bool::from(constant_time_eq_str("secret", "secret")));
        assert!(!bool::from(constant_time_eq_str("secret", "secreT")));
        assert!(!bool::from(constant_time_eq_str("secret", "secret-longer")));
        assert!(bool::from(constant_time_eq_str("", "")));
    }

    /// 身份构造与机制字符串
    #[test]
    fn identity_builder_and_mechanism_name() {
        let identity = AuthIdentity::new(AuthMechanism::Jwt)
            .with_subject("user-42")
            .with_label("web-app");
        assert_eq!(identity.subject.as_deref(), Some("user-42"));
        assert_eq!(identity.label.as_deref(), Some("web-app"));
        assert_eq!(AuthMechanism::Jwt.as_str(), "jwt");
    }
}
