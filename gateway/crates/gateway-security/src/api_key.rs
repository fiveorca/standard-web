//! API Key 认证。
//!
//! 读取位置（按优先级）：
//!   1. 配置的 Header（默认 `X-API-Key`）
//!   2. 可选的 Query 参数（默认关闭）
//!
//! # 安全要点
//!   1. **Header 优先于 Query**：同时存在时以 Header 为准，避免攻击者用
//!      Query 覆盖合法 Header
//!   2. 全部 Key 使用常量时间比较，且遍历完整个列表（不因命中而提前退出）
//!   3. `label` 用于日志（调用方名称），**Key 原文绝不进入身份或日志**
//!   4. Query 方式默认关闭：URL 会进入访问日志、浏览器历史与 Referer，
//!      只有明确配置 `query_param` 才启用

use std::borrow::Cow;

use gateway_core::ApiKeyConfig;
use http::{HeaderMap, HeaderName, Uri};
use subtle::Choice;

use crate::model::{
    constant_time_eq_str, AuthIdentity, AuthMechanism, AuthRejection,
};

/// 已编译的 API Key 策略。
#[derive(Debug, Clone)]
pub struct ApiKeyPolicy {
    /// 允许的 Key 列表（含可选 label）
    keys: Vec<ApiKeyConfig>,
    /// 读取 Key 的 Header 名称（启动期解析为 `HeaderName`，避免每次请求重新校验）
    header_name: HeaderName,
    /// 可选的 Query 参数名（`None` 表示不允许从 Query 读取）
    query_param: Option<String>,
}

impl ApiKeyPolicy {
    /// 编译 API Key 策略。
    ///
    /// 参数：
    /// - `keys`：允许的 Key 列表
    /// - `header_name`：读取 Key 的 Header 名称
    /// - `query_param`：可选的 Query 参数名
    ///
    /// 返回 `Err` 时整条策略拒绝加载。
    pub fn compile(
        keys: &[ApiKeyConfig],
        header_name: &str,
        query_param: Option<&str>,
    ) -> Result<Self, String> {
        if keys.is_empty() {
            return Err("keys must not be empty".into());
        }

        let mut compiled = Vec::with_capacity(keys.len());
        for (idx, key) in keys.iter().enumerate() {
            // 空 Key 会匹配空字符串，属于危险配置，必须在启动期拒绝
            if key.key.is_empty() {
                return Err(format!("keys[{idx}].key must not be empty"));
            }
            compiled.push(key.clone());
        }

        // `HeaderName::from_bytes` 会拒绝非法字符（空格、冒号等）
        let header_name = HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|e| format!("invalid header_name '{header_name}': {e}"))?;

        // 配置了 query_param 就必须非空：空参数名无法定位到具体 Query 项
        if let Some(param) = query_param {
            if param.is_empty() {
                return Err("query_param must not be empty when configured".into());
            }
        }

        Ok(Self {
            keys: compiled,
            header_name,
            query_param: query_param.map(str::to_string),
        })
    }

    /// 校验请求携带的 API Key。
    ///
    /// 参数：
    /// - `headers`：请求头
    /// - `uri`：请求 URI（Query 方式需要）
    ///
    /// 返回：
    /// - `Ok(identity)`：Key 有效，`label` 来自配置
    /// - `Err(rejection)`：缺失或无效（401）
    pub fn verify(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Result<AuthIdentity, AuthRejection> {
        // 1) 抽取 Key：不存在的由 lookup 返回 401（缺失）
        let provided = self.lookup(headers, uri)?;

        // 2) 常量时间遍历全部 Key：
        //    即使已命中也不提前结束，防止"Key 在列表中的位置"影响响应时间
        let mut matched = Choice::from(0);
        let mut label: Option<String> = None;
        for key in &self.keys {
            let eq = constant_time_eq_str(provided.as_ref(), &key.key);
            matched |= eq;
            // 命中后记录 label（label 是非机密展示名，可安全用于日志）
            if bool::from(eq) {
                label = key.label.clone();
            }
        }

        if !bool::from(matched) {
            return Err(AuthRejection::unauthenticated("invalid API key"));
        }

        // 3) 身份只承载 label：Key 原文属于机密，严禁进入身份结构
        let mut identity = AuthIdentity::new(AuthMechanism::ApiKey);
        if let Some(label) = label {
            identity = identity.with_label(label);
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    /// 辅助：构造策略
    fn policy(keys: &[&str], query_param: Option<&str>) -> ApiKeyPolicy {
        let configs: Vec<ApiKeyConfig> = keys
            .iter()
            .enumerate()
            .map(|(idx, key)| ApiKeyConfig {
                key: (*key).to_string(),
                label: Some(format!("caller-{idx}")),
            })
            .collect();
        ApiKeyPolicy::compile(&configs, "X-API-Key", query_param)
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
        let identity = policy
            .verify(&headers_with_key("k-2"), &empty_uri())
            .expect("key should match");
        assert_eq!(identity.mechanism, AuthMechanism::ApiKey);
        // subject 绝不能是 Key 原文
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
        let err = policy
            .verify(&HeaderMap::new(), &uri)
            .expect_err("query must be ignored");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// 配置 query_param 后可从 Query 读取（含百分号解码）
    #[test]
    fn query_key_is_accepted_when_configured() {
        let policy = policy(&["k 1"], Some("api_key"));
        let uri: Uri = "/path?api_key=k%201".parse().expect("valid uri");
        let identity = policy
            .verify(&HeaderMap::new(), &uri)
            .expect("decoded query key should match");
        assert_eq!(identity.label.as_deref(), Some("caller-0"));
    }

    /// 空 Key 列表 / 非法 Header 名 必须编译失败
    #[test]
    fn invalid_config_is_rejected() {
        assert!(ApiKeyPolicy::compile(&[], "X-API-Key", None).is_err());
        let keys = vec![ApiKeyConfig {
            key: "k".into(),
            label: None,
        }];
        assert!(ApiKeyPolicy::compile(&keys, "bad header", None).is_err());
    }
}
