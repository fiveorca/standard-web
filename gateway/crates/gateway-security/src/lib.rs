//! `gateway-security` —— 鉴权 + CORS + WAF。
//!
//! # 模块
//!
//! | 模块 | 阶段 | 作用 |
//! |---|---|---|
//! | `plugin.rs` | Authentication | JWT / API Key / Basic / IP 黑白名单 |
//! | `api_key_store.rs` | — | API Key 生命周期（生成/吊销/轮换/过期/作用域/用量） |
//! | `jwks.rs` | — | JWKS 解析、缓存与 `kid` 选择 |
//! | `cors.rs` | RequestPostRoute / ResponsePreClient | OPTIONS 预检 + CORS 响应头 |
//! | `waf.rs` | RequestPostRoute | SQL 注入 / XSS / RCE / 路径穿越 / 扫描器探测 |
//!
//! 插件模块各自实现 `Plugin` trait，由 RuntimeState 编译时一起注册
//! 到 `PluginRegistry`。

pub mod api_key;
pub mod api_key_store;
pub mod basic;
pub mod cors;
pub mod ip_filter;
pub mod jwks;
pub mod jwt;
pub mod model;
pub mod plugin;
pub mod policy;
pub mod waf;

pub use api_key::ApiKeyPolicy;
pub use api_key_store::{
    hash_api_key, ApiKeyMetadata, ApiKeyStore, ApiKeyVerifyError, NewApiKey, API_KEY_PREFIX,
};
pub use cors::{
    build_cors_plugins, CompiledCorsPolicy, CorsRequestPlugin, CorsResponsePlugin,
    CORS_REQUEST_PLUGIN_NAME, CORS_RESPONSE_PLUGIN_NAME,
};
pub use jwks::JwksKeySet;
pub use jwt::JwtPolicy;
pub use plugin::AuthPlugin;
pub use policy::CompiledAuthPolicies;
pub use waf::{CompiledWafPolicies, WafPlugin, WAF_PLUGIN_NAME};
