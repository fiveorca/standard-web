//! HTTP Basic 认证（RFC 7617）。
//!
//! 协议形态：
//! ```text
//! Authorization: Basic base64(username:password)
//! ```
//!
//! # 安全要点
//!   1. scheme 名称大小写不敏感（RFC 7235 规定 auth-scheme 不区分大小写）
//!   2. base64 解码失败 / 无冒号 / 非 UTF-8 一律视为**无效凭据**
//!   3. 用户名与密码都使用常量时间比较（见 `model::constant_time_eq_str`）
//!   4. 401 响应必须带 `WWW-Authenticate: Basic realm="..."`（RFC 7235）
//!   5. 日志与错误消息中**绝不输出**用户名或密码原文

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gateway_core::BasicCredentialConfig;
use http::HeaderValue;
use subtle::Choice;

use crate::model::{
    constant_time_eq_str, AuthIdentity, AuthMechanism, AuthRejection,
};

/// `WWW-Authenticate` 挑战值。
///
/// realm 使用固定字符串：它只用于浏览器弹窗提示，不应包含环境相关信息。
const BASIC_CHALLENGE: &str = "Basic realm=\"gateway\"";

/// 已编译的 Basic 策略。
///
/// 凭据在启动期从配置复制为 `(username, password)` 元组，运行期只读。
#[derive(Debug, Clone)]
pub struct BasicPolicy {
    /// 允许的凭据列表（顺序无关）
    credentials: Vec<(String, String)>,
}

impl BasicPolicy {
    /// 编译 Basic 策略。
    ///
    /// 参数：
    /// - `credentials`：配置中的用户名/密码列表
    ///
    /// 返回 `Err` 时整条策略拒绝加载（不做"跳过坏条目继续"的部分生效）。
    pub fn compile(credentials: &[BasicCredentialConfig]) -> Result<Self, String> {
        if credentials.is_empty() {
            return Err("credentials must not be empty".into());
        }

        let mut compiled = Vec::with_capacity(credentials.len());
        for (idx, cred) in credentials.iter().enumerate() {
            // 空用户名/空密码无法构成有效凭据，属于配置错误
            if cred.username.is_empty() {
                return Err(format!("credentials[{idx}].username must not be empty"));
            }
            if cred.password.is_empty() {
                return Err(format!("credentials[{idx}].password must not be empty"));
            }
            compiled.push((cred.username.clone(), cred.password.clone()));
        }

        Ok(Self {
            credentials: compiled,
        })
    }

    /// 校验请求的 `Authorization` 头。
    ///
    /// 参数：
    /// - `authorization`：`Authorization` 头的原始值（可能为 `None`）
    ///
    /// 返回：
    /// - `Ok(identity)`：凭据有效，`subject` 为用户名
    /// - `Err(rejection)`：缺失/格式非法/不匹配（401 + Basic 挑战）
    pub fn verify(
        &self,
        authorization: Option<&HeaderValue>,
    ) -> Result<AuthIdentity, AuthRejection> {
        // 1) 缺失：提示客户端使用 Basic 认证
        let value = authorization.ok_or_else(|| {
            AuthRejection::unauthenticated("missing Basic credentials")
                .with_challenge(BASIC_CHALLENGE)
        })?;

        // 2) 非 ASCII / 非法字节：直接拒绝（不做猜测式解码）
        let text = value.to_str().map_err(|_| {
            invalid_credentials("Basic credentials are not valid UTF-8")
        })?;

        // 3) 拆分 scheme 与 base64 段；只允许恰好一个分隔空格
        let (scheme, encoded) = text.split_once(' ').ok_or_else(|| {
            invalid_credentials("Basic credentials must be 'Basic <base64>'")
        })?;
        // auth-scheme 大小写不敏感（RFC 7235 §2.1）
        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(invalid_credentials("unsupported authentication scheme"));
        }

        // 4) base64 解码（STANDARD 引擎：RFC 4648 标准字母表 + `=` padding）
        let decoded = STANDARD
            .decode(encoded.trim().as_bytes())
            .map_err(|_| invalid_credentials("Basic credentials are not valid base64"))?;

        // 5) base64 解出的必须是 UTF-8 的 "username:password"
        let decoded_text = std::str::from_utf8(&decoded)
            .map_err(|_| invalid_credentials("Basic credentials are not valid UTF-8"))?;
        // 只按**第一个**冒号切分：RFC 2617 允许密码包含冒号
        let (username, password) = decoded_text.split_once(':').ok_or_else(|| {
            invalid_credentials("Basic credentials must be 'username:password'")
        })?;

        // 6) 常量时间遍历全部凭据：
        //    即使已命中也不提前退出，避免"凭据在列表中的位置"泄露到响应时间
        let mut matched = Choice::from(0);
        for (expected_user, expected_password) in &self.credentials {
            let user_eq = constant_time_eq_str(username, expected_user);
            let password_eq = constant_time_eq_str(password, expected_password);
            // `&` 表示"两者都匹配"，`|=` 表示"任一凭据匹配"（均为位运算，无分支）
            matched |= user_eq & password_eq;
        }

        if bool::from(matched) {
            // 身份只承载用户名，绝不携带密码
            Ok(AuthIdentity::new(AuthMechanism::Basic).with_subject(username))
        } else {
            Err(invalid_credentials("invalid Basic credentials"))
        }
    }
}

/// 构造"格式非法/凭据不匹配"的 401 拒绝（带 Basic 挑战）。
///
/// 参数：
/// - `message`：脱敏描述（不含凭据原文）
fn invalid_credentials(message: &str) -> AuthRejection {
    AuthRejection::unauthenticated(message).with_challenge(BASIC_CHALLENGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助：构造配置
    fn policy(user: &str, password: &str) -> BasicPolicy {
        BasicPolicy::compile(&[BasicCredentialConfig {
            username: user.into(),
            password: password.into(),
        }])
        .expect("basic policy should compile")
    }

    /// 辅助：把 `user:password` 编码成 Authorization 头值
    fn header_for(user: &str, password: &str) -> HeaderValue {
        let encoded = STANDARD.encode(format!("{user}:{password}"));
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header value")
    }

    /// 正确凭据通过，并产出用户名身份
    #[test]
    fn correct_credentials_pass() {
        let policy = policy("alice", "s3cret");
        let identity = policy
            .verify(Some(&header_for("alice", "s3cret")))
            .expect("credentials should match");
        assert_eq!(identity.mechanism, AuthMechanism::Basic);
        assert_eq!(identity.subject.as_deref(), Some("alice"));
    }

    /// 密码错误 / 用户名错误都拒绝，且返回 401 + Basic 挑战
    #[test]
    fn wrong_credentials_are_rejected() {
        let policy = policy("alice", "s3cret");
        let err = policy
            .verify(Some(&header_for("alice", "wrong")))
            .expect_err("wrong password must fail");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.challenge.as_deref(), Some(BASIC_CHALLENGE));

        let err = policy
            .verify(Some(&header_for("bob", "s3cret")))
            .expect_err("wrong user must fail");
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
    }

    /// 密码中包含冒号时按第一个冒号切分，密码部分保留剩余内容
    #[test]
    fn password_may_contain_colon() {
        let policy = policy("alice", "pa:ss");
        let identity = policy
            .verify(Some(&header_for("alice", "pa:ss")))
            .expect("password with colon should match");
        assert_eq!(identity.subject.as_deref(), Some("alice"));
    }

    /// 缺失 / 非 base64 / 无冒号 / scheme 错误 都被拒绝
    #[test]
    fn malformed_credentials_are_rejected() {
        let policy = policy("alice", "s3cret");
        assert!(policy.verify(None).is_err());

        // 非法 base64
        let bad_b64 = HeaderValue::from_static("Basic !!!not-base64!!!");
        assert!(policy.verify(Some(&bad_b64)).is_err());

        // 合法 base64 但缺少冒号
        let no_colon = HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("alice")))
            .expect("valid header value");
        assert!(policy.verify(Some(&no_colon)).is_err());

        // scheme 不是 Basic
        let bearer = HeaderValue::from_static("Bearer abc");
        assert!(policy.verify(Some(&bearer)).is_err());
    }

    /// 空配置必须编译失败
    #[test]
    fn empty_credentials_fail_to_compile() {
        assert!(BasicPolicy::compile(&[]).is_err());
    }
}
