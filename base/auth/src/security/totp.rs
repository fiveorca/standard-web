//! TOTP（RFC 6238）实现：密钥生成、校验与 provisioning URI。

use totp_rs::{Builder, Secret, Totp};

use crate::shared::{AppError, AppResult};

pub fn generate_secret_base32() -> String {
    Secret::generate().to_base32()
}

pub fn build_totp(secret_base32: &str, issuer: &str, account: &str) -> AppResult<Totp> {
    let secret = Secret::try_from_base32(secret_base32.trim())
        .map_err(|error| AppError::server_error(format!("TOTP 密钥无效: {error}")))?;
    Builder::new()
        .with_secret(secret)
        .with_account_name(account)
        .with_issuer(Some(issuer))
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .build()
        .map_err(|error| AppError::server_error(format!("TOTP 初始化失败: {error}")))
}

/// 校验 TOTP 验证码，返回命中的时间步（用于防重放）。
pub fn verify_code(
    secret_base32: &str,
    issuer: &str,
    account: &str,
    code: &str,
) -> AppResult<Option<u64>> {
    let totp = build_totp(secret_base32, issuer, account)?;
    Ok(totp.check_current(code.trim()))
}

pub fn provisioning_uri(secret_base32: &str, issuer: &str, account: &str) -> String {
    let encode = |value: &str| -> String {
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encode(issuer),
        encode(account),
        encode(secret_base32),
        encode(issuer)
    )
}

pub fn current_step() -> u64 {
    (crate::shared::unix_secs().max(0) as u64) / 30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_verifies_codes() {
        let secret = generate_secret_base32();
        let totp = build_totp(&secret, "Auth Center", "alice@example.com").unwrap();
        let code = totp.generate_current().to_string();
        let step = verify_code(&secret, "Auth Center", "alice@example.com", &code)
            .unwrap()
            .expect("code should verify");
        assert!(step > 0);
        assert!(verify_code(&secret, "Auth Center", "alice@example.com", "000000").is_ok());
    }

    #[test]
    fn provisioning_uri_contains_parameters() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "Auth Center", "alice@example.com");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=Auth%20Center"));
    }
}
