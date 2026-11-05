//! `gateway-security` —— Phase 2 治理能力：鉴权 + CORS。
//!
//! # 模块
//!
//! | 模块 | 阶段 | 作用 |
//! |---|---|---|
//! | `plugin.rs` | Authentication | JWT / API Key / Basic / IP 黑白名单 |
//! | `cors.rs` | RequestPostRoute / ResponsePreClient | OPTIONS 预检 + CORS 响应头 |
//!
//! 两个模块各自实现 `Plugin` trait，由 RuntimeState 编译时一起注册
//! 到 `PluginRegistry`。

pub mod api_key;
pub mod basic;
pub mod cors;
pub mod ip_filter;
pub mod jwt;
pub mod model;
pub mod plugin;
pub mod policy;

pub use cors::{
    build_cors_plugins, CompiledCorsPolicy, CorsRequestPlugin, CorsResponsePlugin,
    CORS_REQUEST_PLUGIN_NAME, CORS_RESPONSE_PLUGIN_NAME,
};
pub use plugin::AuthPlugin;
pub use policy::CompiledAuthPolicies;
