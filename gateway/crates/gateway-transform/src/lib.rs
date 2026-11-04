//! `gateway-transform` —— Header 转换能力（Phase 2 / P2.5）。
//!
//! # 分层位置
//!
//! ```text
//! gateway-runtime（组装插件链）
//!        │
//!        ▼
//! gateway-transform ──▶ gateway-plugin（Plugin / PluginChain / Registry）
//!        │              gateway-core  （TransformPolicyConfig / RouteConfig）
//!        │              gateway-common（ErrorCode / RequestId）
//!        ▼
//! （无下游依赖：本 crate 不发起网络请求、不读写配置源）
//! ```
//!
//! # 两个插件实例
//!
//! Route 有两个独立引用字段，所以本 crate 提供两个 `Plugin` 实例：
//!
//! | 实例 | Phase | Route 字段 |
//! |---|---|---|
//! | `request_transform` | `RequestPreUpstream` | `request_transform_id` |
//! | `response_transform` | `ResponsePreClient` | `response_transform_id` |
//!
//! 它们共享同一个已编译的策略表——同一个策略 id 可以同时被请求方向和
//! 响应方向引用（常见场景：统一注入 `X-Request-Id`）。
//!
//! # 支持的操作
//!
//! | 操作 | 语义 | HeaderMap 方法 |
//! |---|---|---|
//! | `remove_headers` | 按名删除 | `headers.remove(name)` |
//! | `set_headers` | 覆盖写入（不存在则新建） | `headers.insert(name, value)` |
//! | `add_headers` | 追加写入（保留同名头） | `headers.append(name, value)` |
//!
//! # 占位符
//!
//! | 占位符 | 值 |
//! |---|---|
//! | `${request_id}` | 请求 ID |
//! | `${client_ip}` | 客户端 IP（进程内调用时缺失） |
//! | `${method}` | HTTP 方法 |
//! | `${path}` | 请求路径 |
//! | `${host}` | 主机名 |
//! | `${protocol}` | HTTP 版本 |
//! | `${header:<name>}` | 指定请求头值（大小写不敏感） |
//!
//! 缺失值的占位符**原样保留**，方便调试。
//!
//! # 安全约束
//!   - Header 值拒绝 CR / LF / NUL（注入防护）
//!   - Header 名在启动期预解析（非法值编译期拒绝）
//!   - Header 值替换后仍做 sanitize 检查
//!   - 渲染失败 → fail closed（不接受"转换不完整"的半故障状态）

pub mod compile;
pub mod placeholder;
pub mod plugin;

// 扁平 re-export
pub use compile::{CompiledTransformPolicies, CompiledTransformPolicy, HeaderAction};
pub use plugin::{TransformDirection, TransformPlugin, PLUGIN_NAME};
