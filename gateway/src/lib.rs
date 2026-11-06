//! Rust API Gateway
//!
//! 一个生产级的 API 网关实现，参考 Spring Cloud Gateway 的能力模型，
//! 但使用 Rust + Axum + Hyper 技术栈独立实现。
//!
//! 模块划分：
//! - [`bootstrap`]：启动装配、运行时构建
//! - [`config`]：配置模型、加载、校验
//! - [`core`]：路由、断言、过滤器、代理、上游、负载均衡、服务发现
//! - [`middleware`]：认证、授权、限流、CORS、IP 过滤、请求 ID、安全
//! - [`resilience`]：熔断、重试、超时、健康检查
//! - [`cache`]：响应缓存
//! - [`admin`]：管理 API
//! - [`observability`]：日志、指标、追踪
//! - [`transport`]：HTTP/HTTPS 监听与优雅关闭
//! - [`error`]：统一错误模型
//! - [`utils`]：通用工具

pub mod admin;
pub mod bootstrap;
pub mod cache;
pub mod config;
pub mod core;
pub mod error;
pub mod middleware;
pub mod observability;
pub mod resilience;
pub mod transport;
pub mod utils;

/// 当前网关版本号。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
