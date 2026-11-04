//! gateway-plugin —— 插件系统（P2.2）。
//!
//! # 模块职责
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`phase`] | 9 个插件执行阶段（强类型枚举，声明顺序即 Pipeline 顺序） |
//! | [`plugin`] | `Plugin` trait、`PluginContext`、`PluginDecision`、`PluginResponse` |
//! | [`chain`] | `PluginChain`（确定性排序 + 短路传播）与 `PluginRegistry`（编译期注册） |
//! | [`error`] | `PluginError` 及其到 `GatewayError` 的映射 |
//!
//! # 分层位置
//!
//! ```text
//!                ┌──────────────┐
//!                │ gateway-     │  ← 只依赖 common + core
//!                │   plugin     │
//!                └──────┬───────┘
//!         ┌─────────────┼──────────────┬──────────────┐
//!         ▼             ▼              ▼              ▼
//!   gateway-      gateway-       gateway-       gateway-
//!   security      traffic        transform      resilience
//!   (P2.3)        (P2.4)         (P2.5)         (P2.6)
//! ```
//!
//! 各能力 crate 只负责实现具体 `Plugin`，执行顺序、短路与超时统一由本 crate
//! 管理。这样可以保证"安全插件一定先于业务插件执行"这一约定不被破坏。
//!
//! # Phase 2 的插件配置来源
//!
//! Phase 2 采用"策略即插件配置"的方式：每个内置插件在启动时读取
//! 对应的策略段（`policies.auth` / `policies.rate_limit` / ...）构造自身实例，
//! 再注册到 [`PluginRegistry`]。设计文档 6.14 的独立 `plugins:` 配置段
//! 属于 Phase 3 动态插件管理（含 WASM 沙箱）范围，Phase 2 不引入，
//! 避免与策略配置形成两套并行的配置来源。
//!
//! # 安全约束
//!
//! 设计文档 4.12 明确"禁止任意插件绕过安全校验"。落在本 crate 的对应实现是：
//!   - 同阶段内按 `(priority, name)` 确定性排序，安全插件用低优先级值
//!   - 插件出错或超时一律 **fail closed**（短路并返回 500）
//!   - 插件层不持有 IO 能力（不依赖 network/proxy crate），无法自行放行绕过上游

pub mod chain;
pub mod error;
pub mod phase;
pub mod plugin;

// 常用类型的扁平 re-export，方便下游 crate 一行导入
pub use chain::{PluginChain, PluginRegistry};
pub use error::PluginError;
pub use phase::PluginPhase;
pub use plugin::{Plugin, PluginContext, PluginDecision, PluginResponse, ResponseParts};
