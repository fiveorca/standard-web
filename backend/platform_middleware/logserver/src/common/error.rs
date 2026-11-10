// ! 通用错误类型

use tonic::{Code, Status};

/// 应用层错误
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("配置错误: {0}")]
    Config(String),

    #[error("参数校验失败: {0}")]
    Validation(String),

    #[error("事件ID冲突: {0}")]
    EventIdConflict(String),

    #[error("Kafka错误: {0}")]
    Kafka(String),

    #[error("ClickHouse错误: {0}")]
    ClickHouse(String),

    #[error("gRPC内部错误: {0}")]
    GrpcInternal(String),

    #[error("脱敏规则命中敏感字段")]
    SensitiveField,

    #[error("未授权: {0}")]
    Unauthorized(String),

    #[error("租户隔离违规")]
    TenantIsolation,

    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("未知错误: {0}")]
    Anyhow(#[from] anyhow::Error),
}

impl AppError {
    /// 判断是否是可重试的临时错误
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AppError::Kafka(_) | AppError::ClickHouse(_)
        )
    }

    /// 判断是否应该进 DLQ
    pub fn should_go_to_dlq(&self) -> bool {
        matches!(
            self,
            AppError::Validation(_) | AppError::EventIdConflict(_) | AppError::Serde(_)
        )
    }
}

impl From<AppError> for Status {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Validation(msg) => Status::new(Code::InvalidArgument, msg),
            AppError::Kafka(msg) => Status::new(Code::Unavailable, msg),
            AppError::ClickHouse(msg) => Status::new(Code::Unavailable, msg),
            AppError::Unauthorized(msg) => Status::new(Code::Unauthenticated, msg),
            AppError::TenantIsolation => Status::new(Code::PermissionDenied, "tenant isolation violation"),
            AppError::EventIdConflict(id) => {
                Status::new(Code::AlreadyExists, format!("event_id={} already accepted", id))
            }
            other => Status::new(Code::Internal, other.to_string()),
        }
    }
}

/// DLQ 分类
#[derive(Debug, Clone, Copy)]
pub enum DlqStage {
    Parse,
    Validate,
    Schema,
    Kafka,
    ClickHouse,
}

impl DlqStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            DlqStage::Parse => "PARSE",
            DlqStage::Validate => "VALIDATE",
            DlqStage::Schema => "SCHEMA",
            DlqStage::Kafka => "KAFKA",
            DlqStage::ClickHouse => "CLICKHOUSE",
        }
    }
}
