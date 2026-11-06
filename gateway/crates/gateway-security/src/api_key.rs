//! API Key 认证。
//!
//! 读取位置（按优先级）：
//!   1. 配置的 Header（默认 `X-API-Key`）
//!   2. 可选的 Query 参数（默认关闭）
//!
//! # 安全要点
//!   1. **Header 优先于 Query**：同时存在时以 Header 为准，避免攻击者用
//!      Query 覆盖合法 Header
//!   2. 校验交给 [`ApiKeyStore`]：只比较 SHA-256 摘要，
//!      支持过期 / 吊销 / 作用域，并累计使用次数
//!   3. `label` / `consumer_id` 用于日志与身份，**Key 原文绝不进入身份或日志**
//!   4. Query 方式默认关闭：URL 会进入访问日志、浏览器历史与 Referer，
//!      只有明确配置 `query_param` 才启用
//!
//! # 拒绝语义
//!   - 不存在 / 过期 / 吊销：统一 401，不暴露具体原因
//!   - 作用域不足：403（身份已证明，但权限不够）

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gateway_core::ApiKeyConfig;
use http::{HeaderMap, HeaderName, Uri};

use crate::api_key_store::{ApiKeyStore, ApiKeyVerifyError};
use crate::model::{AuthIdentity, AuthMechanism, AuthRejection};

/// 已编译的 API Key 策略。
#[derive(Debug, Clone)]
pub struct ApiKeyPolicy {
    /// 生命周期存储（只读索引 + 原子用量计数）
    store: Arc<ApiKeyStore>,
    /// 读取 Key 的 Header 名称（启动期解析为 `HeaderName`，避免每次请求重新校验）
    header_name: HeaderName,
    /// 可选的 Query 参数名（`None` 表示不允许从 Query 读取）
    query_param: Option<String>,
    /// 必须同时具备的作用域
    required_scopes: Vec<String>,
}

impl ApiKeyPolicy {
    /// 编译 API Key 策略。
    ///
    /// 参数：
    /// - `keys`：Key 条目（明文或 SHA-256 摘要）
    /// - `header_name`：读取 Key 的 Header 名称
    /// - `query_param`：可选的 Query 参数名
    /// - `required_scopes`：要求 Key 具备的作用域（空表示不校验）
    ///
    /// 返回 `Err` 时整条策略拒绝加载。
    pub fn compile(
        keys: &[ApiKeyConfig],
        header_name: &str,
        query_param: Option<&str>,
        required_scopes: &[String],
    ) -> Result<Self, String> {
        if keys.is_empty() {
            return Err("keys must not be empty".into());
        }

        // 编译期完成摘要计算与重复校验；明文不会进入存储
        let store = ApiKeyStore::from_configs(keys, now_secs())?;

        // `HeaderName::from_bytes` 会拒绝非法字符（空格、冒号等）
        let header_name = HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|e| format!("invalid header_name '{header_name}': {e}"))?;

        // 配置了 query_param 就必须非空：空参数名无法定位到具体 Query 项
        if let Some(param) = query_param {
            if param.is_empty() {
                return Err("query_param must not be empty when configured".into());
            }
        }

        for scope in required_scopes {
            if scope.is_empty() {
                return Err("required_scopes entries must not be empty".into());
            }
        }

        Ok(Self {
            store: Arc::new(store),
            header_name,
            query_param: query_param.map(str::to_string),
            required_scopes: required_scopes.to_vec(),
        })
    }

    /// 只读访问生命周期存储（诊断 / 管理接口用）。
    pub fn store(&self) -> &ApiKeyStore {
        &self.store
    }

    /// 校验请求携带的 API Key。
    ///
    /// 参数：
    /// - `headers`：请求头
    /// - `uri`：请求 URI（Query 方式需要）
    ///
    /// 返回：
    /// - `Ok(identity)`：Key 有效；`subject` 为绑定的 Consumer ID
    /// - `Err(rejection)`：缺失或无效（401）、作用域不足（403）
    pub fn verify(&self, headers: &HeaderMap, uri: &Uri) -> Result<AuthIdentity, AuthRejection> {
        // 1) 抽取 Key：不存在的由 lookup 返回 401（缺失）
        let provided = self.lookup(headers, uri)?;

        // 2) 生命周期校验（摘要比对 + 过期/吊销检查 + 用量累计）
        let meta = match self.store.verify(provided.as_ref(), now_secs()) {
            Ok(meta) => meta,
            Err(reason) => {
                // 细分原因只进 debug 日志：对外必须统一，避免存在性预言机
                tracing::debug!(
                    target: "security",
                    reason = %reason,
                    "api key rejected"
                );
                return match reason {
                    ApiKeyVerifyError::ScopeMissing(scope) => Err(AuthRejection::forbidden(
                        format!("API key is missing required scope '{scope}'"),
                    )),
                    _ => Err(AuthRejection::unauthenticated("invalid API key")),
                };
            },
        };

        // 3) 作用域校验（身份已证明 → 403）
        if let Err(scope) = meta.has_scopes(&self.required_scopes) {
            return Err(AuthRejection::forbidden(format!(
                "API key is missing required scope '{scope}'"
            )));
        }

        // 4) 身份只承载非机密标识：Key 原文严禁进入身份结构
        let mut identity = AuthIdentity::new(AuthMechanism::ApiKey);
        // Consumer 绑定：作为主体写回，供配额 / 审计 / 分析使用
        if let Some(consumer) = meta.consumer_id {
            identity = identity.with_subject(consumer);
        }
        if let Some(label) = meta.label {
            identity = identity.with_label(label);
        }
        if let Some(tenant) = meta.tenant_id {
            identity = identity.with_tenant(tenant);
        }
        Ok(identity)
    }

    /// 从 Header 或 Query 中抽取 Key。
    ///
    /// 参数：
    /// - `headers`：请求头
    /// - `uri`：请求 URI
    ///
    /// 返回：
    /// - `Ok(Cow::Borrowed)`：来自 Header（零拷贝）
    /// - `Ok(Cow::Owned)`：来自 Query（已做百分号解码，必然分配）
    /// - `Err(rejection)`：缺失或 Header 非 UTF-8
    fn lookup<'a>(
        &self,
        headers: &'a HeaderMap,
        uri: &'a Uri,
    ) -> Result<Cow<'a, str>, AuthRejection> {
        // Header 优先：存在即不再看 Query
        if let Some(value) = headers.get(&self.header_name) {
            return value
                .to_str()
                .map(Cow::Borrowed)
                .map_err(|_| AuthRejection::unauthenticated("API key is not valid UTF-8"));
        }

        // Header 缺失时，按配置决定是否回退到 Query
        if let Some(param) = &self.query_param {
            let query = uri.query().unwrap_or("");
            // `form_urlencoded::parse` 完成 percent-decoding 与 `+` → 空格
            for (name, value) in form_urlencoded::parse(query.as_bytes()) {
                if name == param.as_str() {
                    return Ok(Cow::Owned(value.into_owned()));
                }
            }
        }

        Err(AuthRejection::unauthenticated("missing API key"))
    }
}

/// 当前 Unix 时间（秒）。
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    /// 辅助：构造策略（单 Key、无作用域要求）
    fn policy(keys: &[&str], query_param: Option<&str>) -> ApiKeyPolicy {
        let configs: Vec<ApiKeyConfig> = keys
            .iter()
            .enumerate()
            .map(|(idx, key)| ApiKeyConfig {
                key: (*key).to_string(),
                label: Some(format!("caller-{idx}")),
                ..ApiKeyConfig::default()
            })
            .collect();
        ApiKeyPolicy::compile(&configs, "X-API-Key", query_param, &[])
            .expect("api key policy should compile")
    }

    /// 辅助：带 `X-API-Key` 的请求头
    fn headers_with_key(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_str(key).expect("valid header value"),
        );
        headers
    }

    /// 辅助：构造空 URI（无 query）
    fn empty_uri() -> Uri {
        "/".parse().expect("valid uri")
    }

    /// Header 中的正确 Key 通过，并带上 label
    #[test]
    fn header_key_passes_with_label() {
        let policy = policy(&["k-1", "k-2"], None);
        let identity =
            policy.verify(&headers_with_key("k-2"), &empty_uri()).expect("key should match");
        assert_eq!(identity.mechanism, AuthMechanism::ApiKey);
        // 未绑定 Consumer 时 subject 为空；绝不能是 Key 原文
        assert!(identity.subject.is_none());
        assert_eq!(identity.label.as_deref(), Some("caller-1"));
    }

    /// 错误的 Key 返回 401
    #[test]
    fn wrong_key_is_rejected() {
        let policy = policy(&["k-1"], None);
        let err = policy
            .verify(&headers_with_key("wrong"), &empty_uri())
            .expect_err("wrong key must fail");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// 未配置 query_param 时不允许从 Query 读取
    #[test]
    fn query_is_ignored_when_not_configured() {
        let policy = policy(&["k-1"], None);
        let uri: Uri = "/path?api_key=k-1".parse().expect("valid uri");
        let err = policy.verify(&HeaderMap::new(), &uri).expect_err("query must be ignored");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// 配置 query_param 后可从 Query 读取（含百分号解码）
    #[test]
    fn query_key_is_accepted_when_configured() {
        let policy = policy(&["k 1"], Some("api_key"));
        let uri: Uri = "/path?api_key=k%201".parse().expect("valid uri");
        let identity =
            policy.verify(&HeaderMap::new(), &uri).expect("decoded query key should match");
        assert_eq!(identity.label.as_deref(), Some("caller-0"));
    }

    /// Consumer 绑定 / 租户 / 作用域 / 过期 在策略层生效
    #[test]
    fn lifecycle_metadata_is_enforced() {
        let configs = vec![
            ApiKeyConfig {
                key: "k-ok".into(),
                id: Some("ok".into()),
                consumer_id: Some("consumer-a".into()),
                tenant_id: Some("tenant-1".into()),
                scopes: vec!["orders:read".into()],
                ..ApiKeyConfig::default()
            },
            ApiKeyConfig {
                key: "k-expired".into(),
                id: Some("expired".into()),
                expires_at: Some(1),
                ..ApiKeyConfig::default()
            },
            ApiKeyConfig {
                key: "k-revoked".into(),
                id: Some("revoked".into()),
                revoked: true,
                ..ApiKeyConfig::default()
            },
        ];
        let policy = ApiKeyPolicy::compile(&configs, "X-API-Key", None, &["orders:read".into()])
            .expect("policy should compile");

        let identity = policy.verify(&headers_with_key("k-ok"), &empty_uri()).expect("valid key");
        assert_eq!(identity.subject.as_deref(), Some("consumer-a"));
        assert_eq!(identity.tenant_id.as_deref(), Some("tenant-1"));

        // 过期与吊销统一 401
        assert_eq!(
            policy
                .verify(&headers_with_key("k-expired"), &empty_uri())
                .expect_err("expired")
                .status,
            http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            policy
                .verify(&headers_with_key("k-revoked"), &empty_uri())
                .expect_err("revoked")
                .status,
            http::StatusCode::UNAUTHORIZED
        );

        // 用量计数在每次成功校验后累计
        let (used, last_used) = policy.store().usage("ok").expect("usage");
        assert_eq!(used, 1);
        assert!(last_used.is_some());
    }

    /// 作用域不足 → 403
    #[test]
    fn missing_scope_is_forbidden() {
        let configs = vec![ApiKeyConfig {
            key: "k".into(),
            id: Some("k".into()),
            scopes: vec!["orders:read".into()],
            ..ApiKeyConfig::default()
        }];
        let policy = ApiKeyPolicy::compile(&configs, "X-API-Key", None, &["orders:write".into()])
            .expect("policy should compile");
        let err = policy
            .verify(&headers_with_key("k"), &empty_uri())
            .expect_err("scope must be required");
        assert_eq!(err.status, http::StatusCode::FORBIDDEN);
    }

    /// 空 Key 列表 / 非法 Header 名 必须编译失败
    #[test]
    fn invalid_config_is_rejected() {
        assert!(ApiKeyPolicy::compile(&[], "X-API-Key", None, &[]).is_err());
        let keys = vec![ApiKeyConfig {
            key: "k".into(),
            ..ApiKeyConfig::default()
        }];
        assert!(ApiKeyPolicy::compile(&keys, "bad header", None, &[]).is_err());
    }
}
