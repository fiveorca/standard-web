//! 控制面业务错误。
//!
//! 该类型是"领域错误"层：向上给 API 层提供稳定的语义分类，
//! 向下把存储错误收敛成统一枚举。API 层负责映射 HTTP 状态码与
//! 统一错误 JSON，本层不直接依赖 Axum。

use gateway_config::ConfigError;
use gateway_storage::StorageError;
use thiserror::Error;

/// 控制面业务错误。
#[derive(Debug, Error)]
pub enum ControlError {
    /// 资源不存在
    #[error("resource not found: {resource}/{id}")]
    NotFound {
        /// 资源类型（API 名称）
        resource: String,
        /// 资源 ID
        id: String,
    },

    /// 资源已存在
    #[error("resource already exists: {resource}/{id}")]
    Conflict {
        /// 资源类型
        resource: String,
        /// 资源 ID
        id: String,
    },

    /// 请求参数不合法（缺失字段、未知资源类型、分页参数非法等）
    #[error("invalid request: {message}")]
    InvalidRequest {
        /// 人类可读原因
        message: String,
    },

    /// 资源载荷不合法（JSON 结构与领域模型不匹配）
    #[error("invalid resource payload: {message}")]
    InvalidPayload {
        /// 人类可读原因（不包含敏感数据）
        message: String,
    },

    /// 乐观锁版本冲突
    #[error("resource version conflict: {resource}/{id} expected {expected}, actual {actual}")]
    VersionConflict {
        /// 资源类型
        resource: String,
        /// 资源 ID
        id: String,
        /// 期望版本
        expected: i64,
        /// 实际版本
        actual: i64,
    },

    /// 配置校验失败（可能是多项错误）
    #[error("configuration validation failed: {} error(s)", .errors.len())]
    Validation {
        /// 所有校验错误
        errors: Vec<ConfigError>,
    },

    /// 快照应用失败（数据库已保存，但数据面未生效）
    #[error("snapshot apply failed: {message}")]
    ApplyFailed {
        /// 简短原因
        message: String,
    },

    /// 存储层错误
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl ControlError {
    /// 资源不存在错误的便捷构造。
    pub fn not_found(resource: &str, id: &str) -> Self {
        Self::NotFound {
            resource: resource.to_string(),
            id: id.to_string(),
        }
    }

    /// 参数错误错误的便捷构造。
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    /// 载荷错误错误的便捷构造。
    pub fn invalid_payload(message: impl Into<String>) -> Self {
        Self::InvalidPayload {
            message: message.into(),
        }
    }
}

impl From<ConfigError> for ControlError {
    fn from(err: ConfigError) -> Self {
        Self::Validation { errors: vec![err] }
    }
}
