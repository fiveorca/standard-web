//! # gateway-config
//!
//! Gateway 配置加载与校验。
//!
//! 职责：
//!   1. 定义顶层 `GatewayConfig` YAML 结构（对应需求文档第七章示例）
//!   2. 从 YAML 文件 + 环境变量加载配置（Figment）
//!   3. 业务校验（引用完整性、默认值填充、ID 唯一性）
//!   4. 拒绝未知字段（Schema 严格模式）
//!   5. 校验错误必须带有明确的字段路径，例如 `"routes[2].methods"`
//!
//! 约束：
//!   - 本 crate 只负责读取和校验，不参与运行时配置分发
//!   - 本 crate 不依赖 tokio/hyper/axum
//!   - 本 crate 不依赖 gateway-routing / gateway-proxy 等运行时模块
//!
//! # Figment 简介
//!
//! Figment 是一个分层配置库：
//!   - `Figment::merge()` 把多个 Provider 合并，后者覆盖前者
//!   - `Figment::extract()` 把合并后的结果反序列化为目标类型
//!
//! 我们用两层 Provider：YAML 文件 → 环境变量。
//! 这样部署时可以用环境变量覆盖 YAML 中的敏感字段（例如数据库密码）。

#![allow(clippy::needless_doctest_main)]
// 配置结构体的 impl Default 普遍需要自定义默认值，clippy::derivable_impls 在此场景下过于激进
#![allow(clippy::derivable_impls)]

pub mod config;
pub mod loader;
pub mod validator;

pub use config::GatewayConfig;
pub use loader::load_from_path;
pub use validator::validate;

/// 配置校验错误。
///
/// 当 YAML 解析成功但业务校验失败时返回此类型。
/// `path` 字段给出错误的精确位置，方便用户排查。
#[derive(Debug, Clone)]
pub struct ConfigError {
    /// 错误位置，例如 `"routes[2].methods"` 或 `"server.http.port"`
    pub path: String,
    /// 错误描述，人类可读
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error at '{}': {}", self.path, self.message)
    }
}

impl std::error::Error for ConfigError {}

impl From<ConfigError> for gateway_common::GatewayError {
    fn from(err: ConfigError) -> Self {
        gateway_common::GatewayError::ConfigurationInvalid {
            path: err.path,
            message: err.message,
        }
    }
}
