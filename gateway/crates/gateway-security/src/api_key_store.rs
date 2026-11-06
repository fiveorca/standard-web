//! API Key 生命周期存储。
//!
//! # 能力
//!
//! | 能力 | 方法 |
//! |---|---|
//! | 生成（明文只返回一次） | [`ApiKeyStore::generate`] |
//! | 元数据查询 | [`ApiKeyStore::get`] / [`ApiKeyStore::list`] |
//! | 校验（含过期 / 吊销 / 作用域） | [`ApiKeyStore::verify`] |
//! | 吊销 | [`ApiKeyStore::revoke`] |
//! | 轮换（生成新明文） | [`ApiKeyStore::rotate`] |
//! | 使用次数统计 | [`ApiKeyStore::usage`]（校验时自动累计） |
//! | Consumer / 租户绑定 | 记录字段 `consumer_id` / `tenant_id` |
//!
//! # 安全约束
//!
//! 1. **只保存摘要**：内存中保存 SHA-256 摘要，明文只在
//!    `generate` / `rotate` 的返回值中出现一次，绝不进入日志或元数据。
//! 2. **统一拒绝语义**：对所有失败原因（不存在 / 过期 / 吊销）对外只体现
//!    为同一个 401，避免给攻击者提供"Key 是否存在"的判别预言机；
//!    细分原因只写 debug 日志。
//! 3. **常量时间**：摘要比对由 `[u8; 32]` 的定长比较完成，
//!    与明文长度、内容无关。
//!
//! # 为什么是"存储"而不是"策略"
//!
//! 策略负责从请求中抽取 Key，存储负责判定 Key 的状态。
//! 二者分离后，控制面（管理接口）与数据面（认证）可以共享同一份
//! 生命周期语义，而数据面只读、无管理副作用。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use base64::Engine;
use gateway_core::ApiKeyConfig;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 生成 Key 的固定前缀。
///
/// 便于日志脱敏（按前缀识别敏感串）与密钥轮换时的快速定位。
pub const API_KEY_PREFIX: &str = "gw_";

/// 摘要长度（SHA-256 = 32 字节）。
const HASH_LEN: usize = 32;

/// 校验失败原因。
///
/// 只用于内部日志与测试；对外统一映射为 401（作用域不足除外，映射 403）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyVerifyError {
    /// Key 不存在（或摘要不匹配）
    Invalid,
    /// 已过期（`now >= expires_at`）
    Expired,
    /// 已吊销
    Revoked,
    /// 缺少要求的作用域
    ScopeMissing(String),
}

impl std::fmt::Display for ApiKeyVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "api key not found"),
            Self::Expired => write!(f, "api key expired"),
            Self::Revoked => write!(f, "api key revoked"),
            Self::ScopeMissing(scope) => write!(f, "api key missing scope '{scope}'"),
        }
    }
}

/// 一条 API Key 的对外元数据（**不含摘要与明文**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyMetadata {
    /// 稳定标识（吊销 / 轮换 / 用量查询的索引）
    pub id: String,
    /// 可读标签
    pub label: Option<String>,
    /// 所属租户
    pub tenant_id: Option<String>,
    /// 绑定的消费者
    pub consumer_id: Option<String>,
    /// 授予的作用域
    pub scopes: Vec<String>,
    /// 创建时间（Unix 秒）
    pub created_at: u64,
    /// 过期时间（Unix 秒）
    pub expires_at: Option<u64>,
    /// 吊销时间（Unix 秒）
    pub revoked_at: Option<u64>,
    /// 累计使用次数
    pub usage_count: u64,
    /// 最后使用时间（Unix 秒）
    pub last_used_at: Option<u64>,
}

impl ApiKeyMetadata {
    /// 是否已吊销。
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// 在指定时刻是否已过期。
    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires| now >= expires)
    }

    /// 是否具备全部要求的作用域。
    pub fn has_scopes(&self, required: &[String]) -> Result<(), String> {
        for scope in required {
            if !self.scopes.iter().any(|s| s == scope) {
                return Err(scope.clone());
            }
        }
        Ok(())
    }
}

/// 生成 API Key 的输入。
#[derive(Debug, Clone, Default)]
pub struct NewApiKey {
    /// 指定 ID（缺省时按摘要前缀生成）
    pub id: Option<String>,
    /// 可读标签
    pub label: Option<String>,
    /// 所属租户
    pub tenant_id: Option<String>,
    /// 绑定的消费者
    pub consumer_id: Option<String>,
    /// 授予的作用域
    pub scopes: Vec<String>,
    /// 过期时间（Unix 秒）
    pub expires_at: Option<u64>,
}

/// 内部记录（摘要 + 原子计数）。
#[derive(Debug)]
struct ApiKeyRecord {
    id: String,
    hash: [u8; HASH_LEN],
    label: Option<String>,
    tenant_id: Option<String>,
    consumer_id: Option<String>,
    scopes: Vec<String>,
    created_at: u64,
    expires_at: Option<u64>,
    /// 0 表示未吊销；否则为吊销时刻
    revoked_at: AtomicU64,
    /// 累计使用次数
    usage_count: AtomicU64,
    /// 0 表示从未使用；否则为最后使用时刻
    last_used_at: AtomicU64,
}

impl ApiKeyRecord {
    fn metadata(&self) -> ApiKeyMetadata {
        ApiKeyMetadata {
            id: self.id.clone(),
            label: self.label.clone(),
            tenant_id: self.tenant_id.clone(),
            consumer_id: self.consumer_id.clone(),
            scopes: self.scopes.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked_at: non_zero(self.revoked_at.load(Ordering::Relaxed)),
            usage_count: self.usage_count.load(Ordering::Relaxed),
            last_used_at: non_zero(self.last_used_at.load(Ordering::Relaxed)),
        }
    }
}

/// 把 0 解释为 `None`（时间戳 0 在真实场景不可能出现）。
fn non_zero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

/// 存储内部索引。
#[derive(Debug, Default)]
struct StoreInner {
    /// 摘要 → 记录（校验路径 O(1)）
    by_hash: HashMap<[u8; HASH_LEN], Arc<ApiKeyRecord>>,
    /// ID → 记录（管理路径）
    by_id: HashMap<String, Arc<ApiKeyRecord>>,
}

/// 进程内 API Key 生命周期存储。
///
/// 通过 `Arc` 共享，内部 `RwLock` 保护索引，记录上的计数使用原子变量，
/// 因此认证热路径不会因为管理操作而阻塞。
#[derive(Debug, Clone, Default)]
pub struct ApiKeyStore {
    inner: Arc<RwLock<StoreInner>>,
}

impl ApiKeyStore {
    /// 创建空存储。
    pub fn new() -> Self {
        Self::default()
    }

    /// 从配置列表构建存储。
    ///
    /// 支持两种输入：
    ///   - `key`：明文（编译期计算摘要，明文不会保留）
    ///   - `key_hash`：已计算好的 SHA-256 摘要
    ///
    /// 返回 `Err` 时整条策略拒绝加载（重复 ID / 重复摘要 / 摘要格式非法）。
    pub fn from_configs(configs: &[ApiKeyConfig], now: u64) -> Result<Self, String> {
        let store = Self::new();
        for (idx, config) in configs.iter().enumerate() {
            store
                .insert_config(config, now)
                .map_err(|reason| format!("keys[{idx}]: {reason}"))?;
        }
        Ok(store)
    }

    /// 插入一条配置来源的 Key（明文或摘要）。
    pub fn insert_config(&self, config: &ApiKeyConfig, now: u64) -> Result<ApiKeyMetadata, String> {
        let hash = resolve_hash(config)?;
        let hash_hex = to_hex(&hash);
        let id = config.id.clone().unwrap_or_else(|| format!("k-{}", &hash_hex[..16]));

        if id.is_empty() {
            return Err("id must not be empty".into());
        }

        let revoked_at = if config.revoked { now } else { 0 };
        let record = Arc::new(ApiKeyRecord {
            id: id.clone(),
            hash,
            label: config.label.clone(),
            tenant_id: config.tenant_id.clone(),
            consumer_id: config.consumer_id.clone(),
            scopes: config.scopes.clone(),
            created_at: now,
            expires_at: config.expires_at,
            revoked_at: AtomicU64::new(revoked_at),
            usage_count: AtomicU64::new(0),
            last_used_at: AtomicU64::new(0),
        });

        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if inner.by_id.contains_key(&id) {
            return Err(format!("duplicate api key id '{id}'"));
        }
        if inner.by_hash.contains_key(&hash) {
            return Err(format!("duplicate api key hash for id '{id}'"));
        }
        inner.by_hash.insert(hash, Arc::clone(&record));
        inner.by_id.insert(id, record.clone());
        Ok(record.metadata())
    }

    /// 生成一条新 Key。
    ///
    /// 返回值第一个元素是**明文**，只在此刻返回一次；
    /// 存储中只保留摘要。调用方必须把明文交给使用者后立即丢弃。
    pub fn generate(
        &self,
        request: NewApiKey,
        now: u64,
    ) -> Result<(String, ApiKeyMetadata), String> {
        let secret = random_secret();
        let hash = sha256(&secret);
        let hash_hex = to_hex(&hash);
        let id = request.id.clone().unwrap_or_else(|| format!("k-{}", &hash_hex[..16]));

        if id.is_empty() {
            return Err("id must not be empty".into());
        }

        let record = Arc::new(ApiKeyRecord {
            id: id.clone(),
            hash,
            label: request.label,
            tenant_id: request.tenant_id,
            consumer_id: request.consumer_id,
            scopes: request.scopes,
            created_at: now,
            expires_at: request.expires_at,
            revoked_at: AtomicU64::new(0),
            usage_count: AtomicU64::new(0),
            last_used_at: AtomicU64::new(0),
        });

        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if inner.by_id.contains_key(&id) {
            return Err(format!("duplicate api key id '{id}'"));
        }
        inner.by_hash.insert(hash, Arc::clone(&record));
        inner.by_id.insert(id, record.clone());
        Ok((secret, record.metadata()))
    }

    /// 校验明文 Key。
    ///
    /// 成功时累计使用次数并刷新最后使用时间；
    /// 失败时返回细分原因（调用方对外必须统一为 401）。
    pub fn verify(&self, provided: &str, now: u64) -> Result<ApiKeyMetadata, ApiKeyVerifyError> {
        if provided.is_empty() {
            return Err(ApiKeyVerifyError::Invalid);
        }

        let hash = sha256(provided);
        let record = {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            inner.by_hash.get(&hash).map(Arc::clone)
        };
        let Some(record) = record else {
            return Err(ApiKeyVerifyError::Invalid);
        };

        if record.revoked_at.load(Ordering::Relaxed) != 0 {
            return Err(ApiKeyVerifyError::Revoked);
        }
        if record.expires_at.is_some_and(|expires| now >= expires) {
            return Err(ApiKeyVerifyError::Expired);
        }

        record.usage_count.fetch_add(1, Ordering::Relaxed);
        record.last_used_at.store(now, Ordering::Relaxed);
        Ok(record.metadata())
    }

    /// 按 ID 吊销 Key（幂等：重复吊销保留首次时间）。
    pub fn revoke(&self, id: &str, now: u64) -> Result<ApiKeyMetadata, String> {
        let record = self.lookup(id)?;
        let _ = record.revoked_at.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
        Ok(record.metadata())
    }

    /// 轮换 Key：保留 ID 与元数据，替换密钥材料并清除吊销状态。
    ///
    /// 返回新的明文（只此一次）。使用计数与最后使用时间归零，
    /// 避免旧密钥的历史用量被错误归因到新密钥。
    pub fn rotate(&self, id: &str) -> Result<(String, ApiKeyMetadata), String> {
        let record = self.lookup(id)?;
        let secret = random_secret();
        let hash = sha256(&secret);

        let updated = Arc::new(ApiKeyRecord {
            id: record.id.clone(),
            hash,
            label: record.label.clone(),
            tenant_id: record.tenant_id.clone(),
            consumer_id: record.consumer_id.clone(),
            scopes: record.scopes.clone(),
            created_at: record.created_at,
            expires_at: record.expires_at,
            revoked_at: AtomicU64::new(0),
            usage_count: AtomicU64::new(0),
            last_used_at: AtomicU64::new(0),
        });

        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        // 旧摘要必须先移除，否则会留下一个仍然可用的幽灵 Key
        inner.by_hash.remove(&record.hash);
        inner.by_hash.insert(hash, Arc::clone(&updated));
        inner.by_id.insert(id.to_string(), Arc::clone(&updated));
        Ok((secret, updated.metadata()))
    }

    /// 按 ID 查询元数据。
    pub fn get(&self, id: &str) -> Option<ApiKeyMetadata> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.by_id.get(id).map(|r| r.metadata())
    }

    /// 查询使用次数与最后使用时间。
    pub fn usage(&self, id: &str) -> Option<(u64, Option<u64>)> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.by_id.get(id).map(|r| {
            (
                r.usage_count.load(Ordering::Relaxed),
                non_zero(r.last_used_at.load(Ordering::Relaxed)),
            )
        })
    }

    /// 列出全部元数据（按 ID 排序，便于稳定展示）。
    pub fn list(&self) -> Vec<ApiKeyMetadata> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut items: Vec<_> = inner.by_id.values().map(|r| r.metadata()).collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        items
    }

    /// 记录数量。
    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).by_id.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lookup(&self, id: &str) -> Result<Arc<ApiKeyRecord>, String> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .by_id
            .get(id)
            .map(Arc::clone)
            .ok_or_else(|| format!("api key '{id}' not found"))
    }
}

/// 计算 API Key 的 SHA-256 摘要（十六进制小写）。
///
/// 供控制面生成 Key 时持久化摘要使用。
pub fn hash_api_key(key: &str) -> String {
    to_hex(&sha256(key))
}

/// 解析配置条目的摘要。
fn resolve_hash(config: &ApiKeyConfig) -> Result<[u8; HASH_LEN], String> {
    if !config.key.is_empty() {
        return Ok(sha256(&config.key));
    }
    match config.key_hash.as_deref() {
        Some(hash) => parse_hex32(hash),
        None => Err("either 'key' or 'key_hash' must be provided".into()),
    }
}

/// SHA-256 摘要。
fn sha256(key: &str) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 十六进制编码（小写）。
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 解析 64 位十六进制摘要。
fn parse_hex32(input: &str) -> Result<[u8; HASH_LEN], String> {
    if input.len() != HASH_LEN * 2 {
        return Err(format!(
            "key_hash must be {} hex characters (SHA-256), got {}",
            HASH_LEN * 2,
            input.len()
        ));
    }
    let bytes = input.as_bytes();
    let mut out = [0u8; HASH_LEN];
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let high =
            hex_val(chunk[0]).ok_or_else(|| "key_hash contains non-hex characters".to_string())?;
        let low =
            hex_val(chunk[1]).ok_or_else(|| "key_hash contains non-hex characters".to_string())?;
        out[idx] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 生成 256 位随机密钥（base64url，无填充，带固定前缀）。
fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{API_KEY_PREFIX}{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn config(key: &str, id: &str) -> ApiKeyConfig {
        ApiKeyConfig {
            key: key.to_string(),
            id: Some(id.to_string()),
            ..ApiKeyConfig::default()
        }
    }

    /// 生成 → 校验成功，且明文只出现在返回值中
    #[test]
    fn generate_then_verify() {
        let store = ApiKeyStore::new();
        let (secret, meta) = store
            .generate(
                NewApiKey {
                    consumer_id: Some("consumer-a".into()),
                    scopes: vec!["orders:read".into()],
                    ..NewApiKey::default()
                },
                NOW,
            )
            .expect("generate");
        assert!(secret.starts_with(API_KEY_PREFIX));
        assert_eq!(meta.usage_count, 0);

        let verified = store.verify(&secret, NOW + 1).expect("verify");
        assert_eq!(verified.consumer_id.as_deref(), Some("consumer-a"));
        assert_eq!(verified.usage_count, 1);
        assert_eq!(verified.last_used_at, Some(NOW + 1));

        // 元数据中不含摘要/明文
        assert!(!format!("{meta:?}").contains(&secret));
    }

    /// 吊销后立即失效；轮换后旧密钥失效、新密钥可用
    #[test]
    fn revoke_and_rotate() {
        let store = ApiKeyStore::new();
        let (old, meta) = store.generate(NewApiKey::default(), NOW).expect("generate");

        store.revoke(&meta.id, NOW + 10).expect("revoke");
        assert_eq!(store.verify(&old, NOW + 11).unwrap_err(), ApiKeyVerifyError::Revoked);

        let (new, rotated) = store.rotate(&meta.id).expect("rotate");
        assert_eq!(rotated.id, meta.id);
        assert!(store.verify(&old, NOW + 21).is_err(), "old secret must stop working");
        assert!(store.verify(&new, NOW + 21).is_ok(), "new secret must work");
        assert_eq!(store.usage(&meta.id), Some((1, Some(NOW + 21))));
    }

    /// 过期时间生效
    #[test]
    fn expired_key_is_rejected() {
        let store = ApiKeyStore::new();
        let (secret, _) = store
            .generate(
                NewApiKey {
                    expires_at: Some(NOW + 5),
                    ..NewApiKey::default()
                },
                NOW,
            )
            .expect("generate");
        assert!(store.verify(&secret, NOW + 4).is_ok());
        assert_eq!(store.verify(&secret, NOW + 5).unwrap_err(), ApiKeyVerifyError::Expired);
    }

    /// 作用域检查
    #[test]
    fn scope_check() {
        let store = ApiKeyStore::new();
        let (secret, meta) = store
            .generate(
                NewApiKey {
                    scopes: vec!["orders:read".into()],
                    ..NewApiKey::default()
                },
                NOW,
            )
            .expect("generate");
        let verified = store.verify(&secret, NOW).expect("verify");
        assert!(verified.has_scopes(&["orders:read".into()]).is_ok());
        assert_eq!(meta.has_scopes(&["orders:write".into()]).unwrap_err(), "orders:write");
    }

    /// 配置支持明文与摘要两种形态，摘要与明文等价
    #[test]
    fn config_accepts_plaintext_and_hash() {
        let plaintext =
            ApiKeyStore::from_configs(&[config("secret-key", "a")], NOW).expect("plain");
        assert!(plaintext.verify("secret-key", NOW).is_ok());

        let hashed = ApiKeyStore::from_configs(
            &[ApiKeyConfig {
                key_hash: Some(hash_api_key("secret-key")),
                id: Some("b".into()),
                ..ApiKeyConfig::default()
            }],
            NOW,
        )
        .expect("hashed");
        assert!(hashed.verify("secret-key", NOW).is_ok());
    }

    /// 非法配置：重复 ID / 重复摘要 / 缺少来源 / 摘要格式错误
    #[test]
    fn invalid_configs_are_rejected() {
        assert!(
            ApiKeyStore::from_configs(&[config("k", "same"), config("k2", "same")], NOW).is_err()
        );
        assert!(ApiKeyStore::from_configs(&[config("k", "a"), config("k", "b")], NOW).is_err());
        assert!(ApiKeyStore::from_configs(&[ApiKeyConfig::default()], NOW).is_err());
        assert!(ApiKeyStore::from_configs(
            &[ApiKeyConfig {
                key_hash: Some("zz".into()),
                ..ApiKeyConfig::default()
            }],
            NOW
        )
        .is_err());
    }
}
