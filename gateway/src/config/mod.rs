//! 配置模块。

pub mod loader;
pub mod model;
pub mod validate;

pub use loader::{load, save_routes, LoadedConfig};
pub use model::*;
pub use validate::{validate, Severity, ValidationReport};
