//! 已编译的鉴权策略集合。
//!
//! # 编译期 vs 运行期
//!
//! ```text
//! AuthPolicyConfig（YAML 映射，纯数据）
//!        │  compile（启动期，一次性）
//!        ▼
//! CompiledAuthPolicy（预解析 CIDR / HeaderName / JWT Validation）
//!        │  evaluate（请求路径，零分配或极少分配）
//!        ▼
//! Ok(Some(AuthIdentity)) / Ok(None) / Err(AuthRejection)
//! ```
//!
//! Route 只持有 `auth_policy_id` 字符串；`AuthPlugin` 用它在
//! `CompiledAuthPolicies` 里查出**已编译**的策略再执行。
//! 这样请求路径上不会出现 "每次请求解析 CIDR、构造 Validation" 的开销。

use std::collections::HashMap;

use gateway_core::{AuthPolicyConfig, AuthPolicySpec};
use http::header::AUTHORIZATION;

use crate::api_key::ApiKeyPolicy;
use crate::basic::BasicPolicy;
use crate::ip_filter::CidrMatcher;
use crate::jwt::{JwtPolicy, JwtSettings};
use crate::model::{AuthIdentity, AuthRejection, AuthRequestView};

// ---------------------------------------------------------------------------
// 单条策略
// ---------------------------------------------------------------------------

/// 已编译策略的具体形态。
#[derive(Debug)]
pub enum AuthPolicyKind {
    /// 显式停用（`enabled: false`）：直接放行
    Disabled,
    /// IP 允许名单
    IpAllowlist(CidrMatcher),
    /// IP 拒绝名单
    IpDenylist(CidrMatcher),
    /// HTTP Basic
    Basic(BasicPolicy),
    /// API Key
    ApiKey(ApiKeyPolicy),
    /// JWT（静态 HMAC 密钥 + 算法白名单）
    ///
    /// 用 `Box` 承载：`JwtPolicy` 含 `Validation`（多个 HashSet）体积较大，
    /// 装箱后整个枚举只有指针大小，避免 `AuthPolicyKind` 因最大变体而膨胀
    /// （否则每个 IP 策略实例都要付出一份 JWT 结构的栈空间）。
    Jwt(Box<JwtPolicy>),
}

/// 一条已编译的鉴权策略。
#[derive(Debug)]
pub struct CompiledAuthPolicy {
    /// 策略 ID（与 `RouteConfig::auth_policy_id` 对应）
    pub id: String,
    /// 人类可读名称（日志用）
    pub name: Option<String>,
    /// 编译后的策略实体
    pub kind: AuthPolicyKind,
}

impl CompiledAuthPolicy {
    /// 编译单条鉴权策略。
    ///
    /// 参数：
    /// - `config`：YAML 反序列化得到的策略配置
    ///
    /// 返回：
    /// - `Ok(policy)`：编译成功
    /// - `Err(reason)`：配置非法（原因已带字段路径，便于定位）
    pub fn compile(config: &AuthPolicyConfig) -> Result<Self, String> {
        // `enabled: false` 的策略不编译规则，直接进入 Disabled 分支。
        // 这样即使后续配置校验有遗漏，停用的策略也不会意外执行。
        let kind = if !config.enabled {
            AuthPolicyKind::Disabled
        } else {
            match &config.spec {
                // ---- IP 黑白名单 ----
                AuthPolicySpec::IpAllowlist { cidrs } => {
                    AuthPolicyKind::IpAllowlist(CidrMatcher::compile(cidrs)?)
                },
                AuthPolicySpec::IpDenylist { cidrs } => {
                    AuthPolicyKind::IpDenylist(CidrMatcher::compile(cidrs)?)
                },

                // ---- Basic ----
                AuthPolicySpec::Basic { credentials } => {
                    AuthPolicyKind::Basic(BasicPolicy::compile(credentials)?)
                },

                // ---- API Key ----
                AuthPolicySpec::ApiKey {
                    keys,
                    header_name,
                    query_param,
                } => AuthPolicyKind::ApiKey(ApiKeyPolicy::compile(
                    keys,
                    header_name,
                    query_param.as_deref(),
                )?),

                // ---- JWT ----
                AuthPolicySpec::Jwt {
                    secret,
                    algorithms,
                    issuer,
                    audience,
                    leeway_secs,
                    required,
                    header_name,
                    query_param,
                    validate_exp,
                } => {
                    // 静态密钥方案下 secret 必填（validator 已校验，这里再兜底一次）
                    let secret = secret
                        .as_deref()
                        .ok_or_else(|| "secret is required for JWT policies".to_string())?;
                    AuthPolicyKind::Jwt(Box::new(JwtPolicy::compile(JwtSettings {
                        secret,
                        algorithms,
                        issuer: issuer.as_deref(),
                        audience: audience.as_deref(),
                        leeway_secs: *leeway_secs,
                        required: *required,
                        header_name,
                        query_param: query_param.as_deref(),
                        validate_exp: *validate_exp,
                    })?))
                },
            }
        };

        Ok(Self {
            id: config.id.clone(),
            name: config.name.clone(),
            kind,
        })
    }

    /// 执行本策略。
    ///
    /// 参数：
    /// - `view`：请求的最小只读视图（headers / uri / client_ip）
    ///
    /// 返回：
    /// - `Ok(Some(identity))`：认证通过并产生身份
    /// - `Ok(None)`：放行但不产生身份（IP 名单、Disabled、可选 JWT）
    /// - `Err(rejection)`：认证/授权失败
    pub fn evaluate(
        &self,
        view: &AuthRequestView<'_>,
    ) -> Result<Option<AuthIdentity>, AuthRejection> {
        match &self.kind {
            // 停用：放行
            AuthPolicyKind::Disabled => Ok(None),

            // 允许名单：客户端 IP 必须命中，否则 403
            AuthPolicyKind::IpAllowlist(matcher) => {
                // 拿不到 client_ip 就无法证明"被允许"→ fail closed
                let Some(addr) = view.client_ip else {
                    return Err(AuthRejection::forbidden(
                        "client address unavailable for IP allowlist",
                    ));
                };
                if matcher.contains(addr.ip()) {
                    Ok(None)
                } else {
                    Err(AuthRejection::forbidden("client IP is not allowed"))
                }
            },

            // 拒绝名单：命中即 403；拿不到 IP 时无法命中名单 → 放行
            AuthPolicyKind::IpDenylist(matcher) => match view.client_ip {
                Some(addr) if matcher.contains(addr.ip()) => {
                    Err(AuthRejection::forbidden("client IP is denied"))
                },
                _ => Ok(None),
            },

            // Basic 固定从 Authorization 头读取（RFC 7617）
            AuthPolicyKind::Basic(policy) => policy
                .verify(view.headers.get(AUTHORIZATION))
                .map(Some),

            // API Key：Header 优先，可回退 Query
            AuthPolicyKind::ApiKey(policy) => policy.verify(view.headers, view.uri).map(Some),

            // JWT：required = false 时可能返回 Ok(None)
            AuthPolicyKind::Jwt(policy) => policy.verify(view.headers, view.uri),
        }
    }
}

// ---------------------------------------------------------------------------
// 策略集合
// ---------------------------------------------------------------------------

/// 全部鉴权策略的编译结果（ID → 已编译策略）。
#[derive(Debug, Default)]
pub struct CompiledAuthPolicies {
    /// 按 ID 索引；启动期构建后只读
    by_id: HashMap<String, CompiledAuthPolicy>,
}

impl CompiledAuthPolicies {
    /// 编译全部鉴权策略。
    ///
    /// 参数：
    /// - `configs`：`policies.auth` 段的原始配置
    ///
    /// 返回 `Err` 时**整个集合拒绝加载**（不做部分生效）：
    /// 部分生效会让"某些路由的鉴权策略静默缺失"，属于安全事故。
    pub fn compile(configs: &[AuthPolicyConfig]) -> Result<Self, String> {
        let mut by_id = HashMap::with_capacity(configs.len());

        for (idx, config) in configs.iter().enumerate() {
            if config.id.is_empty() {
                return Err(format!("auth[{idx}].id must not be empty"));
            }
            // 重复 ID 会让路由引用产生歧义，必须在编译期拒绝
            if by_id.contains_key(&config.id) {
                return Err(format!("duplicate auth policy id '{}'", config.id));
            }

            let compiled = CompiledAuthPolicy::compile(config)
                // 错误信息带上配置索引与策略 ID，便于定位 YAML 出错位置
                .map_err(|reason| format!("auth[{idx}] ('{}'): {reason}", config.id))?;
            by_id.insert(config.id.clone(), compiled);
        }

        Ok(Self { by_id })
    }

    /// 按 ID 查找策略。
    ///
    /// 返回 `None` 表示路由引用了不存在的策略——调用方应视为
    /// **配置错误并 fail closed**（不能因为查不到就放行）。
    pub fn get(&self, id: &str) -> Option<&CompiledAuthPolicy> {
        self.by_id.get(id)
    }

    /// 策略数量。
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否为空集合。
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{ApiKeyConfig, BasicCredentialConfig};
    use http::{HeaderMap, Uri};
    use std::net::SocketAddr;

    /// 辅助：构造空请求视图
    fn view<'a>(
        headers: &'a HeaderMap,
        uri: &'a Uri,
        client_ip: Option<SocketAddr>,
    ) -> AuthRequestView<'a> {
        AuthRequestView {
            headers,
            uri,
            client_ip,
        }
    }

    /// 辅助：构造 IP 策略配置
    fn ip_config(id: &str, deny: bool, enabled: bool) -> AuthPolicyConfig {
        AuthPolicyConfig {
            id: id.into(),
            name: None,
            enabled,
            spec: if deny {
                AuthPolicySpec::IpDenylist {
                    cidrs: vec!["10.0.0.0/8".into()],
                }
            } else {
                AuthPolicySpec::IpAllowlist {
                    cidrs: vec!["10.0.0.0/8".into()],
                }
            },
        }
    }

    /// 重复的策略 ID 必须整体拒绝
    #[test]
    fn duplicate_ids_are_rejected() {
        let configs = vec![ip_config("dup", false, true), ip_config("dup", true, true)];
        assert!(CompiledAuthPolicies::compile(&configs).is_err());
    }

    /// allowlist：命中放行、未命中 403、无客户端 IP 403（fail closed）
    #[test]
    fn allowlist_semantics() {
        let policies =
            CompiledAuthPolicies::compile(&[ip_config("allow", false, true)]).expect("compile");
        let policy = policies.get("allow").expect("policy exists");

        let headers = HeaderMap::new();
        let uri: Uri = "/".parse().expect("uri");
        let allowed: SocketAddr = "10.1.2.3:1234".parse().expect("addr");
        let denied: SocketAddr = "192.168.1.5:1234".parse().expect("addr");

        assert!(policy.evaluate(&view(&headers, &uri, Some(allowed))).is_ok());
        assert_eq!(
            policy
                .evaluate(&view(&headers, &uri, Some(denied)))
                .expect_err("denied ip")
                .status,
            http::StatusCode::FORBIDDEN
        );
        // 客户端地址缺失：不能证明被允许 → 拒绝
        assert_eq!(
            policy
                .evaluate(&view(&headers, &uri, None))
                .expect_err("unknown ip")
                .status,
            http::StatusCode::FORBIDDEN
        );
    }

    /// denylist：命中 403；未命中 / 无 IP 放行
    #[test]
    fn denylist_semantics() {
        let policies =
            CompiledAuthPolicies::compile(&[ip_config("deny", true, true)]).expect("compile");
        let policy = policies.get("deny").expect("policy exists");

        let headers = HeaderMap::new();
        let uri: Uri = "/".parse().expect("uri");
        let blocked: SocketAddr = "10.1.2.3:1234".parse().expect("addr");
        let other: SocketAddr = "192.168.1.5:1234".parse().expect("addr");

        assert_eq!(
            policy
                .evaluate(&view(&headers, &uri, Some(blocked)))
                .expect_err("denied ip")
                .status,
            http::StatusCode::FORBIDDEN
        );
        assert!(policy.evaluate(&view(&headers, &uri, Some(other))).is_ok());
        assert!(policy.evaluate(&view(&headers, &uri, None)).is_ok());
    }

    /// 停用的策略即使规则本身会拒绝，也必须放行
    #[test]
    fn disabled_policy_always_passes() {
        let policies =
            CompiledAuthPolicies::compile(&[ip_config("off", true, false)]).expect("compile");
        let policy = policies.get("off").expect("policy exists");

        let headers = HeaderMap::new();
        let uri: Uri = "/".parse().expect("uri");
        let blocked: SocketAddr = "10.1.2.3:1234".parse().expect("addr");
        assert!(policy.evaluate(&view(&headers, &uri, Some(blocked))).is_ok());
    }

    /// 非法子策略配置会让整条策略编译失败
    #[test]
    fn invalid_sub_policy_fails_compilation() {
        let bad_basic = AuthPolicyConfig {
            id: "basic".into(),
            name: None,
            enabled: true,
            spec: AuthPolicySpec::Basic {
                credentials: vec![BasicCredentialConfig {
                    username: String::new(),
                    password: "p".into(),
                }],
            },
        };
        assert!(CompiledAuthPolicies::compile(&[bad_basic]).is_err());

        let bad_key = AuthPolicyConfig {
            id: "key".into(),
            name: None,
            enabled: true,
            spec: AuthPolicySpec::ApiKey {
                keys: vec![ApiKeyConfig {
                    key: String::new(),
                    label: None,
                }],
                header_name: "X-API-Key".into(),
                query_param: None,
            },
        };
        assert!(CompiledAuthPolicies::compile(&[bad_key]).is_err());
    }
}
