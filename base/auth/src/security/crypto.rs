//! 对称加密与密钥生成。
//!
//! 用于加密 TOTP 密钥、上游身份提供商 Client Secret、SAML 私钥等敏感数据。
//! 主密钥来自 `security.master_key`（Base64 32 字节），不会写入数据库。

use aes_gcm::aead::rand_core::OsRng as AeadOsRng;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine as _;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::shared::{AppError, AppResult};

#[derive(Clone)]
pub struct CryptoBox {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for CryptoBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CryptoBox(***)")
    }
}

impl CryptoBox {
    pub fn new(master_key: &[u8]) -> Self {
        let key = Sha256::digest(master_key);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .unwrap_or_else(|_| unreachable!("sha256 yields 32 bytes"));
        Self { cipher }
    }

    /// 加密并返回 `base64url(nonce || ciphertext)`。
    pub fn encrypt(&self, plaintext: &[u8]) -> AppResult<String> {
        let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| AppError::server_error("敏感数据加密失败"))?;
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload))
    }

    pub fn encrypt_str(&self, plaintext: &str) -> AppResult<String> {
        self.encrypt(plaintext.as_bytes())
    }

    pub fn decrypt(&self, encoded: &str) -> AppResult<Vec<u8>> {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AppError::server_error("敏感数据格式损坏"))?;
        if payload.len() < 13 {
            return Err(AppError::server_error("敏感数据格式损坏"));
        }
        let (nonce, ciphertext) = payload.split_at(12);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| AppError::server_error("敏感数据解密失败，请检查主密钥"))
    }

    pub fn decrypt_str(&self, encoded: &str) -> AppResult<String> {
        String::from_utf8(self.decrypt(encoded)?)
            .map_err(|_| AppError::server_error("敏感数据不是合法 UTF-8"))
    }
}

pub struct GeneratedKey {
    pub kid: String,
    pub private_pem: String,
    pub public_pem: String,
    pub public_jwk: Value,
}

/// 生成签名密钥对并导出 PEM/JWK。
pub fn generate_signing_key(algorithm: &str) -> AppResult<GeneratedKey> {
    match algorithm {
        "RS256" | "RS384" | "RS512" => generate_rsa_key(),
        "ES256" => generate_ec_key(),
        other => Err(AppError::bad_request(format!("不支持的签名算法: {other}"))),
    }
}

fn generate_rsa_key() -> AppResult<GeneratedKey> {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|error| AppError::server_error(format!("生成 RSA 密钥失败: {error}")))?;
    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| AppError::server_error(format!("导出 RSA 私钥失败: {error}")))?
        .to_string();
    let public = private.to_public_key();
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| AppError::server_error(format!("导出 RSA 公钥失败: {error}")))?;
    let kid = kid_from_public_pem(&public_pem);
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    });
    Ok(GeneratedKey {
        kid,
        private_pem,
        public_pem,
        public_jwk: jwk,
    })
}

fn generate_ec_key() -> AppResult<GeneratedKey> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    use p256::SecretKey;

    let secret = SecretKey::random(&mut rand::thread_rng());
    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| AppError::server_error(format!("导出 EC 私钥失败: {error}")))?
        .to_string();
    let public = secret.public_key();
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| AppError::server_error(format!("导出 EC 公钥失败: {error}")))?;
    let kid = kid_from_public_pem(&public_pem);
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| AppError::server_error("EC 公钥缺少 X 坐标"))?;
    let y = point
        .y()
        .ok_or_else(|| AppError::server_error("EC 公钥缺少 Y 坐标"))?;
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
    });
    Ok(GeneratedKey {
        kid,
        private_pem,
        public_pem,
        public_jwk: jwk,
    })
}

pub fn kid_from_public_pem(public_pem: &str) -> String {
    let digest = Sha256::digest(public_pem.as_bytes());
    hex::encode(&digest[..8])
}

/// 生成自签名证书（SAML IdP 元数据需要）。返回 (cert_pem, key_pem_pkcs8)。
pub fn generate_self_signed_certificate(common_name: &str) -> AppResult<(String, String)> {
    let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()])
        .map_err(|error| AppError::server_error(format!("生成证书参数失败: {error}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|error| AppError::server_error(format!("生成证书密钥失败: {error}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| AppError::server_error(format!("签发证书失败: {error}")))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts() {
        let crypto = CryptoBox::new(b"0123456789abcdef0123456789abcdef");
        let ciphertext = crypto.encrypt_str("secret-value").unwrap();
        assert_ne!(ciphertext, "secret-value");
        assert_eq!(crypto.decrypt_str(&ciphertext).unwrap(), "secret-value");
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let a = CryptoBox::new(b"0123456789abcdef0123456789abcdef");
        let b = CryptoBox::new(b"fedcba9876543210fedcba9876543210");
        let ciphertext = a.encrypt_str("secret-value").unwrap();
        assert!(b.decrypt_str(&ciphertext).is_err());
    }

    #[test]
    fn generates_rsa_key() {
        let key = generate_signing_key("RS256").unwrap();
        assert!(key.private_pem.contains("PRIVATE KEY"));
        assert_eq!(key.public_jwk["kty"], "RSA");
    }
}
