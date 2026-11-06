//! JWKS（JSON Web Key Set）解析、缓存与 `kid` 选择。
//!
//! # 工作方式
//!
//! ```text
//! 配置中的内联 JWKS 文档
//!        │ parse（编译期一次）
//!        ▼
//! JwksKeySet（常驻内存，即"缓存"）
//!        │ 请求期：按 Token Header 的 kid + alg 选公钥
//!        ▼
//! DecodingKey → jsonwebtoken::decode
//! ```
//!
//! 文档只在策略编译时解析一次，请求路径不再做 JSON 解析，
//! 只做小规模线性查找（JWKS 通常只有个位数密钥）。
//!
//! # 密钥轮换
//!
//! 1. **同一文档多密钥**：新旧密钥可以同时存在，Token 通过 `kid` 命中各自公钥，
//!    签发方可以在不中断服务的情况下切换签名密钥。
//! 2. **快照轮换**：发布包含新 JWKS 的配置快照即可整体替换密钥集合；
//!    旧 Token 在 `exp` 到期前仍可验签（只要旧公钥仍在文档中）。
//!
//! # 安全约束
//!
//!   - `kid` 未知时 **拒绝**（fail closed），不回退到"任意公钥试一遍"，
//!     避免密钥混淆与算法混淆攻击。
//!   - Token 的 `alg` 必须与 JWK 声明的 `alg` / 密钥类型兼容；
//!     HMAC 密钥（`kty = oct`）只允许用于 `HS*`，非对称公钥只允许用于对应算法族。
//!   - 不接受 `none`：该值在 `JwtAlgorithm` 枚举中不存在，反序列化阶段即失败。

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey};

/// 已解析的 JWKS 密钥集合。
#[derive(Debug, Clone)]
pub struct JwksKeySet {
    /// 文档中的全部密钥（保持原始顺序，`kid` 冲突时以先出现者为准）
    keys: Vec<Jwk>,
}

impl JwksKeySet {
    /// 解析 JWKS 文档。
    ///
    /// 返回 `Err` 时策略拒绝加载：
    ///   - JSON 非法
    ///   - `keys` 为空
    ///   - 存在不支持的密钥类型（例如 Ed25519，当前算法白名单未提供）
    pub fn parse(document: &str) -> Result<Self, String> {
        let set: JwkSet =
            serde_json::from_str(document).map_err(|e| format!("invalid JWKS document: {e}"))?;
        Self::from_set(set)
    }

    /// 从已解析的 [`JwkSet`] 构建。
    pub fn from_set(set: JwkSet) -> Result<Self, String> {
        if set.keys.is_empty() {
            return Err("JWKS document must contain at least one key".into());
        }
        for (idx, key) in set.keys.iter().enumerate() {
            if !is_supported(key) {
                return Err(format!("JWKS keys[{idx}] uses an unsupported key type"));
            }
        }
        Ok(Self { keys: set.keys })
    }

    /// 密钥数量。
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 是否为空（构造时已禁止，保留以保持 API 完整性）。
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// 为指定 Token 选择验签公钥。
    ///
    /// 参数：
    /// - `kid`：Token Header 中的 `kid`（可选）
    /// - `alg`：Token Header 中的算法（已在策略白名单内校验过）
    ///
    /// 返回：
    /// - `Ok(key)`：唯一匹配的公钥
    /// - `Err(reason)`：`kid` 未知 / 无兼容密钥 / 同一 `kid` 有多把兼容密钥
    pub fn decoding_key(&self, kid: Option<&str>, alg: Algorithm) -> Result<DecodingKey, String> {
        let candidates: Vec<&Jwk> = match kid {
            Some(kid) => {
                let key = self
                    .keys
                    .iter()
                    .find(|key| key.common.key_id.as_deref() == Some(kid))
                    .ok_or_else(|| format!("unknown kid '{kid}'"))?;
                if !is_compatible(key, alg) {
                    return Err(format!("kid '{kid}' is not compatible with algorithm {alg:?}"));
                }
                vec![key]
            },
            None => {
                // 无 kid 时必须能唯一定位：多把兼容密钥意味着歧义，拒绝
                let compatible: Vec<&Jwk> =
                    self.keys.iter().filter(|key| is_compatible(key, alg)).collect();
                if compatible.is_empty() {
                    return Err(format!("no JWKS key is compatible with algorithm {alg:?}"));
                }
                if compatible.len() > 1 {
                    return Err(
                        "token has no kid and JWKS contains multiple compatible keys".into()
                    );
                }
                compatible
            },
        };

        DecodingKey::from_jwk(candidates[0])
            .map_err(|e| format!("failed to build decoding key from JWK: {e}"))
    }
}

/// 是否为当前运行时可用的密钥类型。
fn is_supported(key: &Jwk) -> bool {
    matches!(
        key.algorithm,
        AlgorithmParameters::RSA(_)
            | AlgorithmParameters::EllipticCurve(_)
            | AlgorithmParameters::OctetKey(_)
    )
}

/// JWK 是否与 Token 算法兼容。
///
/// 两道检查：
///   1. 密钥类型 vs 算法族（RSA → RS*、EC → ES*、oct → HS*）
///   2. JWK 若显式声明 `alg`，必须与 Token 的 `alg` 完全一致
fn is_compatible(key: &Jwk, alg: Algorithm) -> bool {
    let type_matches = match (&key.algorithm, alg) {
        (AlgorithmParameters::RSA(_), Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512) => {
            true
        },
        (AlgorithmParameters::EllipticCurve(_), Algorithm::ES256 | Algorithm::ES384) => true,
        (
            AlgorithmParameters::OctetKey(_),
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512,
        ) => true,
        _ => false,
    };
    if !type_matches {
        return false;
    }

    match key.common.key_algorithm {
        Some(declared) => key_algorithm_matches(declared, alg),
        // JWK 未声明 alg 时允许按密钥类型匹配（RFC 7517 允许省略）
        None => true,
    }
}

/// JWK 声明的 `alg` 是否与 Token 算法一致。
fn key_algorithm_matches(declared: KeyAlgorithm, alg: Algorithm) -> bool {
    matches!(
        (declared, alg),
        (KeyAlgorithm::HS256, Algorithm::HS256)
            | (KeyAlgorithm::HS384, Algorithm::HS384)
            | (KeyAlgorithm::HS512, Algorithm::HS512)
            | (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// 构造 HMAC JWK（测试用：避免引入 RSA 私钥材料）
    fn hmac_jwks(kid: &str, secret: &[u8]) -> String {
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        format!(r#"{{"keys":[{{"kty":"oct","alg":"HS256","kid":"{kid}","k":"{k}"}}]}}"#)
    }

    /// 按 kid 选择公钥
    #[test]
    fn select_by_kid() {
        let set = JwksKeySet::parse(&hmac_jwks("key-1", b"0123456789abcdef0123456789abcdef"))
            .expect("parse");
        assert_eq!(set.len(), 1);
        assert!(set.decoding_key(Some("key-1"), Algorithm::HS256).is_ok());
        assert!(set.decoding_key(Some("missing"), Algorithm::HS256).is_err());
    }

    /// 无 kid 且只有一把兼容密钥时可用；算法不兼容时拒绝
    #[test]
    fn select_without_kid() {
        let set = JwksKeySet::parse(&hmac_jwks("key-1", b"0123456789abcdef0123456789abcdef"))
            .expect("parse");
        assert!(set.decoding_key(None, Algorithm::HS256).is_ok());
        assert!(set.decoding_key(None, Algorithm::RS256).is_err());
        assert!(set.decoding_key(Some("key-1"), Algorithm::RS256).is_err());
    }

    /// 多把兼容密钥但没有 kid → 拒绝（不能猜测）
    #[test]
    fn ambiguous_selection_is_rejected() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let k1 = URL_SAFE_NO_PAD.encode(b"0123456789abcdef0123456789abcdef");
        let k2 = URL_SAFE_NO_PAD.encode(b"ffffffffffffffffffffffffffffffff");
        let document = format!(
            r#"{{"keys":[
                {{"kty":"oct","alg":"HS256","kid":"a","k":"{k1}"}},
                {{"kty":"oct","alg":"HS256","kid":"b","k":"{k2}"}}
            ]}}"#
        );
        let set = JwksKeySet::parse(&document).expect("parse");
        assert!(set.decoding_key(None, Algorithm::HS256).is_err());
        assert!(set.decoding_key(Some("a"), Algorithm::HS256).is_ok());
        assert!(set.decoding_key(Some("b"), Algorithm::HS256).is_ok());
    }

    /// 空文档 / 非法 JSON 必须拒绝
    #[test]
    fn invalid_documents_are_rejected() {
        assert!(JwksKeySet::parse(r#"{"keys":[]}"#).is_err());
        assert!(JwksKeySet::parse("not-json").is_err());
    }
}
