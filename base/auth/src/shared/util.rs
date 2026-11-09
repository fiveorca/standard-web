//! 通用工具：标识符、脱敏、哈希、随机串与规范化。

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

pub fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

pub fn uuid_v7() -> Uuid {
    Uuid::now_v7()
}

pub fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// URL 安全的随机字符串。
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// 纯数字随机码（验证码）。
pub fn random_numeric(len: usize) -> String {
    let mut output = String::with_capacity(len);
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    for byte in buf {
        output.push(char::from(b'0' + (byte % 10)));
    }
    output
}

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    hex::encode(digest)
}

pub fn sha256_bytes(input: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(input.as_ref()).to_vec()
}

pub fn sha256_base64url(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256_bytes(input))
}

pub fn hmac_sha256_hex(secret: &[u8], input: impl AsRef<[u8]>) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap_or_else(|_| unreachable!());
    mac.update(input.as_ref());
    hex::encode(mac.finalize().into_bytes())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}

pub fn b64url_encode(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input.as_ref())
}

pub fn b64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

pub fn normalize_email(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn normalize_username(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// 规范化权限/角色编码：小写、去除空白、禁止危险字符。
pub fn normalize_permission_code(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.' | '*'))
        .collect()
}

pub fn normalize_phone(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect::<String>()
}

pub fn is_valid_email(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
            .unwrap_or_else(|_| unreachable!())
    });
    value.len() <= 254 && re.is_match(value)
}

pub fn is_valid_phone(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE
        .get_or_init(|| regex::Regex::new(r"^\+?[0-9]{6,20}$").unwrap_or_else(|_| unreachable!()));
    re.is_match(value)
}

pub fn is_valid_username(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$").unwrap_or_else(|_| unreachable!())
    });
    re.is_match(value)
}

pub fn mask_email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) if !local.is_empty() => {
            let head: String = local.chars().take(1).collect();
            format!("{head}***@{domain}")
        }
        _ => "***".to_string(),
    }
}

pub fn mask_phone(value: &str) -> String {
    let digits: Vec<char> = value.chars().collect();
    if digits.len() <= 4 {
        return "****".to_string();
    }
    let head: String = digits.iter().take(3).collect();
    let tail: String = digits.iter().skip(digits.len() - 4).collect();
    format!("{head}****{tail}")
}

pub fn mask_secret(value: &str) -> String {
    if value.len() <= 6 {
        return "***".to_string();
    }
    format!("{}***{}", &value[..3], &value[value.len() - 2..])
}

/// 生成稳定的规范化 JSON 字符串（用于审计哈希链）。
pub fn canonical_json(value: &Value) -> String {
    fn canonical(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(v) => out.push_str(&v.to_string()),
            Value::String(v) => {
                out.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "\"\"".to_string()))
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                out.push('{');
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(
                        &serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()),
                    );
                    out.push(':');
                    canonical(item, out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    canonical(value, &mut out);
    out
}

/// 计算密码过期时间；`expiry_days == 0` 表示不过期。
pub fn password_expires_at(days: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    if days == 0 {
        None
    } else {
        Some(now() + chrono::Duration::days(days as i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys() {
        let a = serde_json::json!({"b": 1, "a": {"d": 2, "c": 3}});
        let b = serde_json::json!({"a": {"c": 3, "d": 2}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn masks_sensitive_values() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_phone("13800138000"), "138****8000");
    }

    #[test]
    fn validates_inputs() {
        assert!(is_valid_email("user.name+tag@example.co"));
        assert!(!is_valid_email("bad@@example.com"));
        assert!(is_valid_phone("+8613800138000"));
        assert!(is_valid_username("user_01"));
        assert!(!is_valid_username("u"));
    }

    #[test]
    fn random_tokens_are_unique() {
        assert_ne!(random_token(32), random_token(32));
        assert_eq!(random_numeric(6).len(), 6);
    }
}
