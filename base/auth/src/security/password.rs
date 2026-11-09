//! 密码哈希、密码策略与一次性验证码哈希。

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::config::PasswordConfig;
use crate::shared::{hmac_sha256_hex, AppError, AppResult};

#[derive(Clone)]
pub struct PasswordService {
    params: Params,
    history_size: usize,
}

impl PasswordService {
    pub fn new(config: &PasswordConfig) -> AppResult<Self> {
        let params = Params::new(
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
            None,
        )
        .map_err(|error| AppError::server_error(format!("Argon2 参数无效: {error}")))?;
        Ok(Self {
            params,
            history_size: config.history_size,
        })
    }

    pub fn history_size(&self) -> usize {
        self.history_size
    }

    /// 在阻塞线程池中计算 Argon2id 哈希。
    pub async fn hash(&self, password: String) -> AppResult<String> {
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|error| AppError::server_error(format!("密码哈希失败: {error}")))
        })
        .await
        .map_err(|error| AppError::server_error(format!("密码哈希任务失败: {error}")))?
    }

    pub async fn verify(&self, password: String, hash: String) -> AppResult<bool> {
        tokio::task::spawn_blocking(move || {
            let parsed = match PasswordHash::new(&hash) {
                Ok(parsed) => parsed,
                Err(_) => return Ok(false),
            };
            let argon2 = Argon2::default();
            Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
        })
        .await
        .map_err(|error| AppError::server_error(format!("密码校验任务失败: {error}")))?
    }
}

/// 校验新密码是否符合安全策略。
pub fn validate_password(
    password: &str,
    policy: &PasswordConfig,
    forbidden_fragments: &[&str],
) -> AppResult<()> {
    let length = password.chars().count();
    if length < policy.min_length {
        return Err(AppError::validation(
            "password",
            format!("密码长度不能少于 {} 个字符", policy.min_length),
        ));
    }
    if length > policy.max_length {
        return Err(AppError::validation(
            "password",
            format!("密码长度不能超过 {} 个字符", policy.max_length),
        ));
    }
    if password.trim() != password {
        return Err(AppError::validation("password", "密码首尾不能包含空白字符"));
    }
    if password.chars().any(char::is_control) {
        return Err(AppError::validation("password", "密码不能包含控制字符"));
    }
    if policy.require_upper && !password.chars().any(|c| c.is_uppercase()) {
        return Err(AppError::validation("password", "密码必须包含大写字母"));
    }
    if policy.require_lower && !password.chars().any(|c| c.is_lowercase()) {
        return Err(AppError::validation("password", "密码必须包含小写字母"));
    }
    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AppError::validation("password", "密码必须包含数字"));
    }
    if policy.require_symbol && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(AppError::validation("password", "密码必须包含符号"));
    }
    let lowered = password.to_ascii_lowercase();
    for weak in [
        "password", "123456", "qwerty", "admin", "letmein", "welcome", "passw0rd",
    ] {
        if lowered.contains(weak) {
            return Err(AppError::validation("password", "密码包含常见弱口令片段"));
        }
    }
    for fragment in forbidden_fragments {
        let fragment = fragment.trim().to_ascii_lowercase();
        if fragment.len() >= 3 && lowered.contains(&fragment) {
            return Err(AppError::validation(
                "password",
                "密码不能包含用户名、邮箱或手机号",
            ));
        }
    }
    Ok(())
}

/// 一次性验证码哈希：使用主密钥做 HMAC，避免数据库中直接可取验证码。
pub fn hash_verification_code(
    master_key: &[u8],
    purpose: &str,
    target: &str,
    code: &str,
) -> String {
    hmac_sha256_hex(master_key, format!("{purpose}|{target}|{code}"))
}

pub fn hash_recovery_code(master_key: &[u8], identity_id: uuid::Uuid, code: &str) -> String {
    hmac_sha256_hex(
        master_key,
        format!(
            "recovery|{identity_id}|{}",
            code.trim().to_ascii_uppercase()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PasswordConfig;

    fn policy() -> PasswordConfig {
        PasswordConfig {
            min_length: 8,
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_symbol: false,
            ..PasswordConfig::default()
        }
    }

    #[tokio::test]
    async fn hashes_and_verifies_password() {
        let service = PasswordService::new(&policy()).unwrap();
        let hash = service.hash("CorrectHorse9".to_string()).await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(service
            .verify("CorrectHorse9".to_string(), hash.clone())
            .await
            .unwrap());
        assert!(!service
            .verify("WrongHorse9".to_string(), hash)
            .await
            .unwrap());
    }

    #[test]
    fn rejects_weak_passwords() {
        let policy = policy();
        assert!(validate_password("short", &policy, &[]).is_err());
        assert!(validate_password("alllowercase1", &policy, &[]).is_err());
        assert!(validate_password("ALLUPPERCASE1", &policy, &[]).is_err());
        assert!(validate_password("NoDigitsHere", &policy, &[]).is_err());
        assert!(validate_password("Password123", &policy, &[]).is_err());
        assert!(validate_password("AlicePass123", &policy, &["alice"]).is_err());
        assert!(validate_password("ZebraCanyon42", &policy, &["alice"]).is_ok());
    }

    #[test]
    fn verification_code_hash_is_context_bound() {
        let key = b"0123456789abcdef0123456789abcdef";
        let a = hash_verification_code(key, "login", "a@example.com", "123456");
        let b = hash_verification_code(key, "login", "b@example.com", "123456");
        assert_ne!(a, b);
    }
}
