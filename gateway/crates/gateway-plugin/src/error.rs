//! 插件错误类型。
//!
//! 插件层的错误必须满足两个要求：
//!   1. **不能携带内部细节到客户端**：错误消息会进入 AccessLog，
//!      但返回给客户端的 JSON 只包含稳定错误码 + 脱敏后的描述
//!   2. **必须可映射为 `GatewayError`**：统一由 Runtime 转成 HTTP 响应
//!
//! 因此这里定义独立的 `PluginError`（比 `GatewayError` 更贴近插件语义），
//! 并提供 [`PluginError::to_gateway_error`] 做一次显式映射。

use gateway_common::GatewayError;
use thiserror::Error;

/// 插件层错误。
#[derive(Debug, Error)]
pub enum PluginError {
    /// 插件配置非法（启动阶段校验失败，属于"配置错误"而非"请求错误"）
    #[error("plugin '{plugin}' config invalid: {message}")]
    ConfigInvalid {
        /// 插件唯一名称（`Plugin::name()` 的返回值）
        plugin: String,
        /// 人类可读的错误原因
        message: String,
    },

    /// 插件初始化失败（例如密钥无法解析、连接池创建失败）
    #[error("plugin '{plugin}' init failed: {message}")]
    InitFailed {
        /// 插件唯一名称
        plugin: String,
        /// 初始化失败原因
        message: String,
    },

    /// 插件执行返回错误。
    ///
    /// 语义：该错误会**短路**整条插件链，由 Runtime 映射为 500。
    /// 例外：认证类插件应返回 `PluginDecision::ShortCircuit`（401）而不是
    /// `Err`，因为"凭据无效"是预期内的业务结果，不是系统故障。
    #[error("plugin '{plugin}' execution failed: {message}")]
    ExecutionFailed {
        /// 插件唯一名称
        plugin: String,
        /// 错误原因
        message: String,
    },

    /// 插件执行超过自身声明的超时时间。
    #[error("plugin '{plugin}' timed out after {timeout_ms}ms")]
    Timeout {
        /// 插件唯一名称
        plugin: String,
        /// 触发超时的阈值（毫秒），来自 `Plugin::timeout()`
        timeout_ms: u64,
    },

    /// 注册表里出现同名插件。
    ///
    /// 插件名是"确定性执行顺序"的第二排序键，
    /// 重名会导致顺序不稳定，必须在注册阶段拒绝。
    #[error("duplicate plugin name '{name}'")]
    DuplicateName {
        /// 重复的插件名
        name: String,
    },

    /// 插件初始化了但注册表中不存在（配置引用错误）
    #[error("plugin '{name}' not found in registry")]
    NotFound {
        /// 被查找的插件名
        name: String,
    },
}

impl PluginError {
    /// 把插件错误映射为全局 `GatewayError`。
    ///
    /// 映射规则：
    ///   - 配置类（`ConfigInvalid` / `InitFailed` / `DuplicateName` / `NotFound`）
    ///     属于部署期错误 → `ConfigurationInvalid`
    ///   - 运行时类（`ExecutionFailed` / `Timeout`）→ `Internal`
    ///
    /// 之所以不把 `Timeout` 映射成 `UpstreamTimeout`：插件超时是网关自身
    /// 处理超时，不是上游响应超时，错误码语义必须区分。
    pub fn to_gateway_error(&self) -> GatewayError {
        match self {
            PluginError::ConfigInvalid { plugin, message } => GatewayError::ConfigurationInvalid {
                path: format!("plugins.{plugin}"),
                message: message.clone(),
            },
            PluginError::InitFailed { plugin, message } => GatewayError::ConfigurationApplyFailed {
                message: format!("plugin '{plugin}' init failed: {message}"),
            },
            PluginError::DuplicateName { name } => GatewayError::ConfigurationApplyFailed {
                message: format!("duplicate plugin name '{name}'"),
            },
            PluginError::NotFound { name } => GatewayError::ConfigurationInvalid {
                path: name.clone(),
                message: "plugin not registered".into(),
            },
            PluginError::ExecutionFailed { plugin, message } => {
                GatewayError::Internal(format!("plugin '{plugin}' failed: {message}"))
            },
            PluginError::Timeout { plugin, timeout_ms } => {
                GatewayError::Internal(format!("plugin '{plugin}' timed out after {timeout_ms}ms"))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::ErrorCode;

    /// 配置类错误映射为 ConfigurationInvalid
    #[test]
    fn config_error_maps_to_configuration_invalid() {
        let err = PluginError::ConfigInvalid {
            plugin: "jwt".into(),
            message: "secret missing".into(),
        };
        assert_eq!(
            err.to_gateway_error().code(),
            ErrorCode::GatewayConfigurationInvalid
        );
    }

    /// 执行类错误映射为 Internal
    #[test]
    fn execution_error_maps_to_internal() {
        let err = PluginError::ExecutionFailed {
            plugin: "rate-limit".into(),
            message: "counter store broken".into(),
        };
        assert_eq!(err.to_gateway_error().code(), ErrorCode::GatewayInternalError);
    }
}
