//! 存储层错误类型。
//!
//! 设计原则：
//!   1. 错误信息中不包含数据库连接串、密码等敏感内容
//!   2. 区分"资源不存在 / 冲突 / 版本冲突 / 载荷非法 / 数据库错误"
//!      让控制面 API 能映射成正确的 HTTP 状态码
//!   3. 不向外暴露底层 SQL 语句，只保留简短原因

use thiserror::Error;

/// 存储层统一错误。
#[derive(Debug, Error)]
pub enum StorageError {
    /// 资源不存在
    #[error("resource not found: {kind}/{id}")]
    NotFound {
        /// 资源类型（API 名称，例如 `"routes"`）
        kind: String,
        /// 资源 ID
        id: String,
    },

    /// 资源已存在（主键冲突）
    #[error("resource already exists: {kind}/{id}")]
    Conflict {
        /// 资源类型
        kind: String,
        /// 资源 ID
        id: String,
    },

    /// 乐观锁版本冲突
    ///
    /// 控制面允许更新时携带 `expected_version`，防止两个管理员基于旧版本
    /// 互相覆盖。版本不匹配时返回该错误。
    #[error(
        "resource version conflict: {kind}/{id} expected {expected}, actual {actual}"
    )]
    VersionConflict {
        /// 资源类型
        kind: String,
        /// 资源 ID
        id: String,
        /// 客户端期望的版本
        expected: i64,
        /// 数据库中当前版本
        actual: i64,
    },

    /// 资源载荷（JSON）不合法或无法反序列化为领域类型
    #[error("invalid resource payload: {message}")]
    InvalidPayload {
        /// 人类可读原因（不包含敏感数据）
        message: String,
    },

    /// 数据库访问错误（SQLx）
    #[error("database error: {message}")]
    Database {
        /// 简短原因；不包含 SQL 语句与连接串
        message: String,
    },

    /// 存储后端暂不可用（连接池耗尽 / 网络故障）
    #[error("storage unavailable: {message}")]
    Unavailable {
        /// 简短原因
        message: String,
    },
}

impl StorageError {
    /// 资源不存在错误的便捷构造。
    pub fn not_found(kind: &str, id: &str) -> Self {
        Self::NotFound {
            kind: kind.to_string(),
            id: id.to_string(),
        }
    }

    /// 主键冲突错误的便捷构造。
    pub fn conflict(kind: &str, id: &str) -> Self {
        Self::Conflict {
            kind: kind.to_string(),
            id: id.to_string(),
        }
    }

    /// 载荷错误错误的便捷构造。
    pub fn invalid_payload(message: impl Into<String>) -> Self {
        Self::InvalidPayload {
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        // 只保留 SQLx 错误的 Display 文本。SQLx 的 Display 不包含绑定参数，
        // 不会泄露凭据；但仍截断到 200 字符，避免日志被超长错误撑爆。
        let mut message = err.to_string();
        if message.len() > 200 {
            message.truncate(200);
            message.push_str("...");
        }
        Self::Database { message }
    }
}
