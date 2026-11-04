//! JWT 认证 —— **静态密钥 + 算法白名单**方案。
//!
//! # 方案边界（与需求文档的对应关系）
//!
//! 需求 §4.4 要求实现 11 项 JWT 校验能力。Phase 2 采用静态 HMAC 密钥：
//!
//! | 需求项 | 本实现 |
//! |---|---|
//! | Token 格式验证 | `decode_header` + `decode` 双重解析 |
//! | 签名验证 | `jsonwebtoken::decode`（HMAC-SHA256/384/512） |
//! | 过期时间验证 | `exp`（必填，`leeway` 容忍时钟漂移） |
//! | Not Before 验证 | `nbf`（存在时校验） |
//! | Issuer 验证 | 配置 `issuer` 时精确匹配 |
//! | Audience 验证 | 配置 `audience` 时精确匹配 |
//! | 算法白名单 | `algorithms` 白名单 + 显式 header 预检 |
//! | Key ID / JWKS / Rotation / 撤销 | 静态密钥方案不适用，留待 Phase 3 |
//!
//! # 关键安全决策
//!
//! 1. **算法绝不由 Token 自身决定**：
//!    `decode_header` 先把 `alg` 解析成**枚举**，`none` 与其他算法在
//!    反序列化阶段就失败；随后还要求 `alg` 落在配置白名单内。
//!    这同时防住了 `alg: none` 伪造与 `alg` 混淆攻击。
//! 2. **`aud` 语义必须显式**：`jsonwebtoken` 默认 `validate_aud = true`，
//!    未配置 `aud` 时携带 `aud` 的 Token 会被判非法。本实现按策略语义
//!    显式设置 `validate_aud`，避免"未配置却拒绝合法 Token"的意外。
//! 3. **失败信息统一化**：对外只返回 `invalid JWT`，不区分"过期/签名错/
//!    iss 不匹配"，避免给攻击者提供校验预言机；细节只写 debug 日志。
//! 4. **密钥与 Token 绝不进入日志**。

use std::borrow::Cow;

use gateway_core::JwtAlgorithm;
use http::{HeaderMap, HeaderName, Uri};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::model::{AuthIdentity, AuthMechanism, AuthRejection, Credential};

/// 401 时使用的 `WWW-Authenticate` 挑战。
const BEARER_CHALLENGE: &str = "Bearer";

/// JWT 策略编译参数。
///
/// 用独立结构体承载参数，而不是给 `compile` 传 9 个位置参数：
///   - 避免 `clippy::too_many_arguments`
///   - 调用点字段名可读，不会把 `required` 与 `validate_exp` 传反
pub struct JwtSettings<'a> {
    /// HMAC 静态密钥（按 UTF-8 字节直接作为 key material）
    pub secret: &'a str,
    /// 算法白名单（**不能为空**）
    pub algorithms: &'a [JwtAlgorithm],
    /// 期望的签发者（`iss`）
    pub issuer: Option<&'a str>,
    /// 期望的受众（`aud`）
    pub audience: Option<&'a str>,
    /// 时钟偏移容忍（秒），作用于 `exp` / `nbf`
    pub leeway_secs: u64,
    /// 是否强制要求携带 Token
    pub required: bool,
    /// 读取 Token 的 Header 名
    pub header_name: &'a str,
    /// 可选的 Query 参数名
    pub query_param: Option<&'a str>,
    /// 是否校验 `exp`（配置 validator 禁止 false，这里保留以支持单测）
    pub validate_exp: bool,
}

/// 已编译的 JWT 策略。
pub struct JwtPolicy {
    /// 密钥字节（启动期从配置复制，运行期只读；不参与 Debug 输出）
    secret: Vec<u8>,
    /// 算法白名单（jsonwebtoken 枚举形式）
    algorithms: Vec<Algorithm>,
    /// 算法白名单（字符串形式，仅用于日志）
    algorithm_names: Vec<&'static str>,
    /// 是否要求请求必须携带 Token
    required: bool,
    /// 读取 Token 的 Header 名
    header_name: HeaderName,
    /// 可选的 Query 参数名
    query_param: Option<String>,
    /// 预构建的 `jsonwebtoken` 校验配置（exp/nbf/iss/aud/算法白名单）
    validation: Validation,
}

impl std::fmt::Debug for JwtPolicy {
    /// 手写 Debug：**绝不能**把 `secret` 打出来。
    ///
    /// 只输出非敏感字段，保证日志/panic 消息即使打印 `JwtPolicy`
    /// 也不会泄漏密钥。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtPolicy")
            .field("algorithms", &self.algorithm_names)
            .field("required", &self.required)
            .field("header_name", &self.header_name)
            .field("query_param", &self.query_param)
            // 只暴露密钥长度，不暴露内容
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl JwtPolicy {
    /// 编译 JWT 策略。
    ///
    /// 参数：
    /// - `settings`：见 [`JwtSettings`]
    ///
    /// 返回 `Err` 时整条策略拒绝加载：
    ///   - 算法白名单为空
    ///   - 密钥缺失/过短（与 `gateway-config` 的 validator 采用同一阈值）
    ///   - Header 名非法
    pub fn compile(settings: JwtSettings<'_>) -> Result<Self, String> {
        // 1) 算法白名单不能为空：空白名单没有任何校验意义
        if settings.algorithms.is_empty() {
            return Err("algorithms must not be empty".into());
        }

        // 2) 静态 HMAC 密钥必须足够长（32 字节 ≈ 256 bit，匹配 HS256 强度）
        if settings.secret.is_empty() {
            return Err("secret must not be empty".into());
        }
        if settings.secret.len() < 32 {
            return Err("secret must be at least 32 bytes (HMAC security)".into());
        }

        // 3) Header 名在启动期就校验，避免每次请求都解析失败
        let header_name = HeaderName::from_bytes(settings.header_name.as_bytes())
            .map_err(|e| format!("invalid header_name '{}': {e}", settings.header_name))?;

        // 4) query_param 若配置必须非空
        if let Some(param) = settings.query_param {
            if param.is_empty() {
                return Err("query_param must not be empty when configured".into());
            }
        }

        // 5) 白名单枚举 → jsonwebtoken 算法（同时保存字符串用于日志）
        let mut algorithms = Vec::with_capacity(settings.algorithms.len());
        let mut algorithm_names = Vec::with_capacity(settings.algorithms.len());
        for alg in settings.algorithms {
            algorithms.push(jsonwebtoken_algorithm(*alg));
            algorithm_names.push(jwt_algorithm_name(*alg));
        }

        // 6) 构建校验配置。
        //    `Validation::new` 默认 required_spec_claims = {"exp"}、leeway = 60、
        //    validate_exp = true、validate_aud = true；下面逐项按策略覆盖。
        let mut validation = Validation::new(algorithms[0]);
        // 算法白名单：header 中的 alg 不在该列表时 decode 直接返回 InvalidAlgorithm
        validation.algorithms = algorithms.clone();
        // 时钟偏移容忍（秒）
        validation.leeway = settings.leeway_secs;
        // exp 校验开关
        validation.validate_exp = settings.validate_exp;
        // nbf 校验：只有 Token 携带 nbf 时才生效（需求要求实现 Not Before 校验）
        validation.validate_nbf = true;

        // 关闭 exp 校验时必须同时移除"exp 必填"，否则无 exp 的 Token 仍会被拒绝
        if !settings.validate_exp {
            validation.required_spec_claims.remove("exp");
        }

        // aud 语义：配置了 audience 才校验；未配置则关闭 aud 校验，
        // 否则 jsonwebtoken 会把"带 aud 但未配置期望值"的合法 Token 判为非法
        match settings.audience {
            Some(audience) => {
                validation.validate_aud = true;
                validation.set_audience(&[audience]);
            },
            None => {
                validation.validate_aud = false;
            },
        }

        // iss：配置后 precise match（jsonwebtoken 在 iss 存在配置时强制比较）
        if let Some(issuer) = settings.issuer {
            validation.set_issuer(&[issuer]);
        }

        Ok(Self {
            secret: settings.secret.as_bytes().to_vec(),
            algorithms,
            algorithm_names,
            required: settings.required,
            header_name,
            query_param: settings.query_param.map(str::to_string),
            validation,
        })
    }

    /// 校验请求携带的 JWT。
    ///
    /// 返回：
    /// - `Ok(Some(identity))`：Token 有效，`subject` 为 `sub`
    /// - `Ok(None)`：未携带 Token 且 `required = false`（可选登录态场景）
    /// - `Err(rejection)`：缺失（required）或无效（401 + Bearer 挑战）
    pub fn verify(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Result<Option<AuthIdentity>, AuthRejection> {
        // 1) 抽取 Token，区分"缺失"与"格式非法"
        let token = match self.extract(headers, uri) {
            Credential::Missing => {
                if self.required {
                    return Err(AuthRejection::unauthenticated("missing bearer token")
                        .with_challenge(BEARER_CHALLENGE));
                }
                // 可选登录态：匿名请求放行（不产生身份）
                return Ok(None);
            },
            Credential::Malformed => {
                return Err(invalid_token());
            },
            Credential::Value(token) => token,
        };

        if token.is_empty() {
            return Err(invalid_token());
        }

        // 2) 先解析 header：`alg` 必须是已知枚举值（`none` 在此处即失败）
        let header = match decode_header(token.as_ref()) {
            Ok(header) => header,
            Err(err) => {
                // 只记录错误类别，不记录 Token 内容
                tracing::debug!(target: "security", error = %err, "jwt header rejected");
                return Err(invalid_token());
            },
        };

        // 3) 显式算法白名单预检（纵深防御：即使 decode 的算法检查被误配置也拦得住）
        if !self.algorithms.contains(&header.alg) {
            tracing::debug!(
                target: "security",
                alg = ?header.alg,
                allowed = ?self.algorithm_names,
                "jwt algorithm rejected by whitelist"
            );
            return Err(invalid_token());
        }

        // 4) 验签 + 声明校验（exp / nbf / iss / aud 全部由 `Validation` 实施）
        let key = DecodingKey::from_secret(&self.secret);
        let data = match decode::<Value>(token.as_ref(), &key, &self.validation) {
            Ok(data) => data,
            Err(err) => {
                tracing::debug!(target: "security", error = %err, "jwt verification failed");
                return Err(invalid_token());
            },
        };

        // 5) 身份只取 `sub`：其余声明（含 Token 原文）绝不进入身份结构
        let mut identity = AuthIdentity::new(AuthMechanism::Jwt);
        if let Some(subject) = data.claims.get("sub").and_then(Value::as_str) {
            identity = identity.with_subject(subject);
        }
        Ok(Some(identity))
    }

    /// 从 Header 或 Query 抽取 Token。
    ///
    /// # 抽取规则
    ///   - Header 优先，存在即不再看 Query
    ///   - Header 值形如 `Bearer <token>` 时去掉 scheme（大小写不敏感）
    ///   - 自定义 Header 直接携带裸 Token 时也可识别
    ///   - Query 参数默认关闭；开启后按 `form_urlencoded` 规则解码
    fn extract<'a>(&self, headers: &'a HeaderMap, uri: &'a Uri) -> Credential<'a> {
        if let Some(value) = headers.get(&self.header_name) {
            return match value.to_str() {
                Ok(text) => match strip_bearer_scheme(text) {
                    Some(token) => Credential::Value(Cow::Borrowed(token)),
                    None => Credential::Malformed,
                },
                // Header 含非可见 ASCII 字节：不猜测，直接判非法
                Err(_) => Credential::Malformed,
            };
        }

        if let Some(param) = &self.query_param {
            let query = uri.query().unwrap_or("");
            for (name, value) in form_urlencoded::parse(query.as_bytes()) {
                if name == param.as_str() {
                    return Credential::Value(Cow::Owned(value.into_owned()));
                }
            }
        }

        Credential::Missing
    }

    /// 算法白名单（字符串形式），用于启动自检日志。
    pub fn algorithm_names(&self) -> &[&'static str] {
        &self.algorithm_names
    }
}

/// 去掉 `Bearer` 前缀（大小写不敏感）。
///
/// 参数：
/// - `text`：Header 原始值
///
/// 返回 `None` 表示值非法（空白、`Bearer` 后没有 Token）。
/// 非 `Bearer` 前缀时把整段视为裸 Token，以兼容自定义 Header 的部署习惯。
fn strip_bearer_scheme(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    match trimmed.split_once(' ') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => {
            let token = rest.trim();
            if token.is_empty() {
                None
            } else {
                Some(token)
            }
        },
        _ => Some(trimmed),
    }
}

/// 统一的"Token 无效"401 拒绝（带 Bearer 挑战）。
fn invalid_token() -> AuthRejection {
    AuthRejection::unauthenticated("invalid JWT").with_challenge(BEARER_CHALLENGE)
}

/// `JwtAlgorithm` → `jsonwebtoken::Algorithm`。
fn jsonwebtoken_algorithm(alg: JwtAlgorithm) -> Algorithm {
    match alg {
        JwtAlgorithm::Hs256 => Algorithm::HS256,
        JwtAlgorithm::Hs384 => Algorithm::HS384,
        JwtAlgorithm::Hs512 => Algorithm::HS512,
    }
}

/// `JwtAlgorithm` → 字符串（日志/自检用）。
fn jwt_algorithm_name(alg: JwtAlgorithm) -> &'static str {
    match alg {
        JwtAlgorithm::Hs256 => "HS256",
        JwtAlgorithm::Hs384 => "HS384",
        JwtAlgorithm::Hs512 => "HS512",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    /// 测试密钥：32 字节，满足编译期长度要求
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// 辅助：构造默认策略（HS256 白名单，required = true，无 iss/aud）
    fn policy(required: bool) -> JwtPolicy {
        JwtPolicy::compile(JwtSettings {
            secret: std::str::from_utf8(SECRET).expect("ascii secret"),
            algorithms: &[JwtAlgorithm::Hs256],
            issuer: None,
            audience: None,
            leeway_secs: 0,
            required,
            header_name: "Authorization",
            query_param: None,
            validate_exp: true,
        })
        .expect("jwt policy should compile")
    }

    /// 辅助：签发 Token（默认 HS256）
    fn sign(claims: Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("token should be signed")
    }

    /// 辅助：把 Token 放进 Authorization: Bearer 头
    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).expect("valid header"),
        );
        headers
    }

    /// 辅助：空 URI
    fn empty_uri() -> Uri {
        "/".parse().expect("valid uri")
    }

    /// 有效 Token 通过，sub 进入身份
    #[test]
    fn valid_token_passes_and_exposes_subject() {
        let token = sign(json!({
            "sub": "alice",
            "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        let identity = policy(true)
            .verify(&bearer_headers(&token), &empty_uri())
            .expect("valid token should pass")
            .expect("required token yields identity");
        assert_eq!(identity.mechanism, AuthMechanism::Jwt);
        assert_eq!(identity.subject.as_deref(), Some("alice"));
    }

    /// 过期 Token 被拒绝
    #[test]
    fn expired_token_is_rejected() {
        let token = sign(json!({
            "sub": "alice",
            // 当前时间之前 1 小时
            "exp": jsonwebtoken::get_current_timestamp().saturating_sub(3600)
        }));
        let err = policy(true)
            .verify(&bearer_headers(&token), &empty_uri())
            .expect_err("expired token must fail");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.challenge.as_deref(), Some(BEARER_CHALLENGE));
    }

    /// 算法不在白名单内（HS384 签名、白名单只允许 HS256）被拒绝
    #[test]
    fn algorithm_outside_whitelist_is_rejected() {
        let token = encode(
            &Header::new(Algorithm::HS384),
            &json!({ "sub": "alice", "exp": jsonwebtoken::get_current_timestamp() + 3600 }),
            &EncodingKey::from_secret(SECRET),
        )
        .expect("hs384 token should be signed");

        let err = policy(true)
            .verify(&bearer_headers(&token), &empty_uri())
            .expect_err("hs384 must be rejected when only hs256 is allowed");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// `alg: none` 的伪造 Token 必须被拒绝（不允许无签名 Token）
    #[test]
    fn alg_none_is_rejected() {
        use base64::Engine;
        // 手工拼接 header {"alg":"none"} + 任意 payload + 空签名
        let header = base64::engine::general_purpose::STANDARD.encode(r#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_string(&json!({ "sub": "attacker" })).expect("serialize claims"),
        );
        let forged = format!("{header}.{payload}.");

        let err = policy(true)
            .verify(&bearer_headers(&forged), &empty_uri())
            .expect_err("alg none must be rejected");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// 错误密钥签发的 Token 被拒绝
    #[test]
    fn wrong_secret_is_rejected() {
        let other_secret = b"ffffffffffffffffffffffffffffffff";
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({ "sub": "alice", "exp": jsonwebtoken::get_current_timestamp() + 3600 }),
            &EncodingKey::from_secret(other_secret),
        )
        .expect("token should be signed");
        assert!(policy(true).verify(&bearer_headers(&token), &empty_uri()).is_err());
    }

    /// required = false 时缺失 Token 放行；required = true 时返回带挑战的 401
    #[test]
    fn optional_token_semantics() {
        let optional = policy(false);
        assert!(optional
            .verify(&HeaderMap::new(), &empty_uri())
            .expect("missing token is allowed")
            .is_none());

        let required = policy(true);
        let err = required
            .verify(&HeaderMap::new(), &empty_uri())
            .expect_err("missing token must fail");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.challenge.as_deref(), Some(BEARER_CHALLENGE));
    }

    /// iss / aud 配置后必须精确匹配
    #[test]
    fn issuer_and_audience_are_enforced_when_configured() {
        let settings = |issuer: Option<&'static str>, audience: Option<&'static str>| JwtSettings {
            secret: std::str::from_utf8(SECRET).expect("ascii secret"),
            algorithms: &[JwtAlgorithm::Hs256],
            issuer,
            audience,
            leeway_secs: 0,
            required: true,
            header_name: "Authorization",
            query_param: None,
            validate_exp: true,
        };

        let strict = JwtPolicy::compile(settings(Some("gateway"), Some("api")))
            .expect("policy should compile");

        // 正确 iss + aud
        let ok_token = sign(json!({
            "sub": "alice", "iss": "gateway", "aud": "api",
            "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        assert!(strict.verify(&bearer_headers(&ok_token), &empty_uri()).is_ok());

        // iss 不匹配
        let bad_iss = sign(json!({
            "sub": "alice", "iss": "other", "aud": "api",
            "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        assert!(strict.verify(&bearer_headers(&bad_iss), &empty_uri()).is_err());

        // aud 不匹配
        let bad_aud = sign(json!({
            "sub": "alice", "iss": "gateway", "aud": "other",
            "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        assert!(strict.verify(&bearer_headers(&bad_aud), &empty_uri()).is_err());
    }

    /// 未配置 audience 时，带 aud 的 Token 仍可接受（语义与配置一致）
    #[test]
    fn unconfigured_audience_does_not_reject_token_with_aud() {
        let token = sign(json!({
            "sub": "alice", "aud": "anything",
            "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        assert!(policy(true).verify(&bearer_headers(&token), &empty_uri()).is_ok());
    }

    /// 配置 query_param 后可从 Query 读取 Token
    #[test]
    fn token_from_query_param() {
        let token = sign(json!({
            "sub": "alice", "exp": jsonwebtoken::get_current_timestamp() + 3600
        }));
        let policy = JwtPolicy::compile(JwtSettings {
            secret: std::str::from_utf8(SECRET).expect("ascii secret"),
            algorithms: &[JwtAlgorithm::Hs256],
            issuer: None,
            audience: None,
            leeway_secs: 0,
            required: true,
            header_name: "Authorization",
            query_param: Some("access_token"),
            validate_exp: true,
        })
        .expect("policy should compile");

        let uri: Uri = format!("/path?access_token={token}")
            .parse()
            .expect("valid uri");
        assert!(policy.verify(&HeaderMap::new(), &uri).is_ok());
    }

    /// 空算法白名单 / 短密钥 / 非法 Header 名 必须编译失败
    #[test]
    fn invalid_settings_are_rejected() {
        let base = JwtSettings {
            secret: std::str::from_utf8(SECRET).expect("ascii secret"),
            algorithms: &[JwtAlgorithm::Hs256],
            issuer: None,
            audience: None,
            leeway_secs: 0,
            required: true,
            header_name: "Authorization",
            query_param: None,
            validate_exp: true,
        };

        assert!(JwtPolicy::compile(JwtSettings { algorithms: &[], ..base }).is_err());
        assert!(JwtPolicy::compile(JwtSettings { secret: "short", ..base }).is_err());
        assert!(JwtPolicy::compile(JwtSettings { header_name: "bad header", ..base }).is_err());
    }
}
