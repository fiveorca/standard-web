//! 安全原语：密码、JWT 密钥、TOTP、WebAuthn、加密、Cookie、PKCE 与重定向校验。

pub mod cookie;
pub mod crypto;
pub mod jwt;
pub mod password;
pub mod pkce;
pub mod redirect;
pub mod totp;
pub mod webauthn;

pub use cookie::{bearer_from_headers, cookie_from_headers};
pub use crypto::CryptoBox;
pub use jwt::{KeyManager, SigningAlgorithm};
pub use password::{
    hash_recovery_code, hash_verification_code, validate_password, PasswordService,
};
pub use webauthn::WebauthnService;
