//! PKCE (RFC 7636) 校验。

use crate::shared::b64url_encode;
use sha2::{Digest, Sha256};

pub fn valid_code_verifier(verifier: &str) -> bool {
    let length = verifier.len();
    (43..=128).contains(&length)
        && verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

pub fn challenge_for(verifier: &str, method: &str) -> Option<String> {
    match method {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            Some(b64url_encode(digest))
        }
        "plain" => Some(verifier.to_string()),
        _ => None,
    }
}

pub fn verify(verifier: &str, challenge: &str, method: &str) -> bool {
    if !valid_code_verifier(verifier) {
        return false;
    }
    match challenge_for(verifier, method) {
        Some(expected) => {
            crate::shared::util::constant_time_eq(expected.as_bytes(), challenge.as_bytes())
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_s256_challenge() {
        // RFC 7636 附录 B 的示例
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify(verifier, challenge, "S256"));
        assert!(!verify(verifier, challenge, "plain"));
    }

    #[test]
    fn rejects_invalid_verifier() {
        assert!(!valid_code_verifier("short"));
        assert!(!valid_code_verifier(&"a".repeat(42)));
        assert!(valid_code_verifier(&"a".repeat(43)));
        assert!(!valid_code_verifier(&"a".repeat(129)));
    }
}
