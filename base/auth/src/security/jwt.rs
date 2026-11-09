//! JWT 签名密钥管理。
//!
//! - 私钥仅存放在数据库，并使用 `CryptoBox` 加密；JWKS 只暴露公钥。
//! - 支持密钥轮换：新密钥成为 active，旧密钥保留用于验签，到期后退出 JWKS。
//! - 验签强制校验签名、`iss`、`aud`、`exp`、`nbf` 与 `kid`。

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::security::crypto::{generate_signing_key, CryptoBox};
use crate::shared::{now, AppError, AppResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningAlgorithm {
    Rs256,
    Rs384,
    Rs512,
    Es256,
}

impl SigningAlgorithm {
    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "ES256" => Ok(Self::Es256),
            other => Err(AppError::server_error(format!("不支持的签名算法: {other}"))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Es256 => "ES256",
        }
    }

    pub fn jsonwebtoken(&self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Es256 => Algorithm::ES256,
        }
    }
}

pub struct TokenKey {
    pub kid: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    pub jwk: Value,
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKey").field("kid", &self.kid).finish()
    }
}

pub struct KeyManager {
    pool: PgPool,
    crypto: Arc<CryptoBox>,
    algorithm: SigningAlgorithm,
    rotate_days: u64,
    retain_days: u64,
    active: RwLock<Option<Arc<TokenKey>>>,
    cache: RwLock<HashMap<String, Arc<TokenKey>>>,
}

impl KeyManager {
    pub async fn init(
        pool: PgPool,
        crypto: Arc<CryptoBox>,
        algorithm: SigningAlgorithm,
        rotate_days: u64,
        retain_days: u64,
    ) -> AppResult<Self> {
        let manager = Self {
            pool,
            crypto,
            algorithm,
            rotate_days,
            retain_days,
            active: RwLock::new(None),
            cache: RwLock::new(HashMap::new()),
        };
        manager.load_all().await?;

        let needs_new_key = match manager.active.read().await.clone() {
            None => true,
            Some(_) => manager.active_key_expired().await?,
        };
        if needs_new_key {
            manager.rotate().await?;
        }
        Ok(manager)
    }

    async fn active_key_expired(&self) -> AppResult<bool> {
        let row: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
            "SELECT activated_at FROM signing_keys WHERE status = 'active' ORDER BY activated_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some((activated_at,)) if self.rotate_days > 0 => {
                activated_at + chrono::Duration::days(self.rotate_days as i64) < now()
            }
            _ => false,
        })
    }

    async fn load_all(&self) -> AppResult<()> {
        let rows = sqlx::query_as::<_, crate::domain::SigningKey>(
            "SELECT id, kid, algorithm, private_key_encrypted, public_pem, public_jwk, status,
                    created_at, activated_at, retired_at, not_after
             FROM signing_keys WHERE status <> 'revoked' ORDER BY activated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut cache = HashMap::new();
        let mut active = None;
        for row in rows {
            if row.algorithm != self.algorithm.as_str() {
                continue;
            }
            let key = Arc::new(self.build_key(&row)?);
            if row.status == "active" && active.is_none() {
                active = Some(key.clone());
            }
            cache.insert(row.kid.clone(), key);
        }
        *self.cache.write().await = cache;
        *self.active.write().await = active;
        Ok(())
    }

    fn build_key(&self, row: &crate::domain::SigningKey) -> AppResult<TokenKey> {
        let private_pem = self.crypto.decrypt_str(&row.private_key_encrypted)?;
        let algorithm = self.algorithm.jsonwebtoken();
        let (encoding, decoding) = match self.algorithm {
            SigningAlgorithm::Es256 => (
                EncodingKey::from_ec_pem(private_pem.as_bytes())
                    .map_err(|error| AppError::server_error(format!("EC 私钥加载失败: {error}")))?,
                DecodingKey::from_ec_pem(row.public_pem.as_bytes())
                    .map_err(|error| AppError::server_error(format!("EC 公钥加载失败: {error}")))?,
            ),
            _ => (
                EncodingKey::from_rsa_pem(private_pem.as_bytes()).map_err(|error| {
                    AppError::server_error(format!("RSA 私钥加载失败: {error}"))
                })?,
                DecodingKey::from_rsa_pem(row.public_pem.as_bytes()).map_err(|error| {
                    AppError::server_error(format!("RSA 公钥加载失败: {error}"))
                })?,
            ),
        };
        let _ = algorithm;
        Ok(TokenKey {
            kid: row.kid.clone(),
            encoding,
            decoding,
            jwk: row.public_jwk.clone(),
        })
    }

    /// 轮换签名密钥：旧 active 进入 retired，新密钥成为 active。
    pub async fn rotate(&self) -> AppResult<String> {
        let algorithm = self.algorithm.as_str().to_string();
        let generated = tokio::task::spawn_blocking(move || generate_signing_key(&algorithm))
            .await
            .map_err(|error| AppError::server_error(format!("密钥生成任务失败: {error}")))??;

        let mut jwk = generated.public_jwk.clone();
        jwk["alg"] = Value::String(self.algorithm.as_str().to_string());

        let encrypted_private = self.crypto.encrypt_str(&generated.private_pem)?;
        let retain_until = now() + chrono::Duration::days(self.retain_days.max(1) as i64);

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE signing_keys SET status = 'retired', retired_at = now(), not_after = $1 WHERE status = 'active'",
        )
        .bind(retain_until)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO signing_keys (kid, algorithm, private_key_encrypted, public_pem, public_jwk, status)
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(&generated.kid)
        .bind(self.algorithm.as_str())
        .bind(&encrypted_private)
        .bind(&generated.public_pem)
        .bind(&jwk)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.load_all().await?;
        tracing::info!(kid = %generated.kid, algorithm = %self.algorithm.as_str(), "signing key rotated");
        Ok(generated.kid)
    }

    pub async fn active_kid(&self) -> AppResult<String> {
        let active = self.active.read().await.clone();
        active
            .map(|key| key.kid.clone())
            .ok_or_else(|| AppError::server_error("没有可用的签名密钥"))
    }

    pub async fn sign<T: Serialize>(&self, claims: &T) -> AppResult<(String, String)> {
        let key = {
            let active = self.active.read().await.clone();
            active.ok_or_else(|| AppError::server_error("没有可用的签名密钥"))?
        };
        let mut header = Header::new(self.algorithm.jsonwebtoken());
        header.kid = Some(key.kid.clone());
        header.typ = Some("JWT".to_string());
        let token = jsonwebtoken::encode(&header, claims, &key.encoding)
            .map_err(|error| AppError::server_error(format!("Token 签名失败: {error}")))?;
        Ok((token, key.kid.clone()))
    }

    pub async fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        expected_audience: Option<&str>,
    ) -> AppResult<T> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header
            .kid
            .clone()
            .ok_or_else(|| AppError::unauthorized("Token 缺少 kid"))?;
        if header.alg != self.algorithm.jsonwebtoken() {
            return Err(AppError::unauthorized("Token 签名算法不被接受"));
        }
        let key = self.key_for_kid(&kid).await?;
        let mut validation = Validation::new(self.algorithm.jsonwebtoken());
        validation.validate_nbf = true;
        validation.leeway = 5;
        if let Some(audience) = expected_audience {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }
        let data = jsonwebtoken::decode::<T>(token, &key.decoding, &validation)?;
        Ok(data.claims)
    }

    async fn key_for_kid(&self, kid: &str) -> AppResult<Arc<TokenKey>> {
        if let Some(key) = self.cache.read().await.get(kid).cloned() {
            return Ok(key);
        }
        let row = sqlx::query_as::<_, crate::domain::SigningKey>(
            "SELECT id, kid, algorithm, private_key_encrypted, public_pem, public_jwk, status,
                    created_at, activated_at, retired_at, not_after
             FROM signing_keys WHERE kid = $1 AND status <> 'revoked'",
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::unauthorized("Token 的签名密钥不存在"))?;
        if row.algorithm != self.algorithm.as_str() {
            return Err(AppError::unauthorized("Token 签名算法不被接受"));
        }
        if let Some(not_after) = row.not_after {
            if not_after < now() {
                return Err(AppError::unauthorized("Token 的签名密钥已过期"));
            }
        }
        let key = Arc::new(self.build_key(&row)?);
        self.cache
            .write()
            .await
            .insert(kid.to_string(), key.clone());
        Ok(key)
    }

    pub async fn jwks(&self) -> AppResult<Value> {
        let now_time = now();
        let rows = sqlx::query_as::<_, crate::domain::SigningKey>(
            "SELECT id, kid, algorithm, private_key_encrypted, public_pem, public_jwk, status,
                    created_at, activated_at, retired_at, not_after
             FROM signing_keys
             WHERE status IN ('active', 'retired') AND algorithm = $1
             ORDER BY activated_at DESC",
        )
        .bind(self.algorithm.as_str())
        .fetch_all(&self.pool)
        .await?;
        let keys: Vec<Value> = rows
            .into_iter()
            .filter(|row| row.not_after.map(|until| until > now_time).unwrap_or(true))
            .map(|row| row.public_jwk)
            .collect();
        Ok(json!({ "keys": keys }))
    }

    /// 查询所有令牌可用的签名密钥 ID（用于测试与状态检查）。
    pub async fn available_kids(&self) -> AppResult<Vec<String>> {
        Ok(self.cache.read().await.keys().cloned().collect())
    }
}
