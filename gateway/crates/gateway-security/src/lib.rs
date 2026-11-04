//! `gateway-security` —— 鉴权能力（Phase 2 / P2.3）。
//!
//! # 分层位置
//!
//! ```text
//! gateway-runtime（组装插件链）
//!        │
//!        ▼
//! gateway-security ──▶ gateway-plugin（Plugin / PluginChain / Registry）
//!        │              gateway-core  （AuthPolicyConfig / RouteConfig）
//!        │              gateway-common（ErrorCode / RequestId）
//!        ▼
//! （无下游依赖：本 crate 不发起网络请求、不读写配置源）
//! ```
//!
//! # 提供的鉴权机制
//!
//! | 机制 | 读取位置 | 失败状态 | 产生身份 |
//! |---|---|---|---|
//! | IP Allowlist | `client_ip` | 403 | 否 |
//! | IP Denylist | `client_ip` | 403 | 否 |
//! | Basic | `Authorization`（RFC 7617） | 401 + 挑战 | 用户名 |
//! | API Key | Header（可回退 Query） | 401 | `label` |
//! | JWT | `Authorization: Bearer`（可回退 Query） | 401 + 挑战 | `sub` |
//!
//! # 安全约束（贯穿所有子模块）
//!
//! 1. **凭据原文绝不进入日志、错误响应或身份结构**
//! 2. 凭据比较一律使用 `subtle` 的常量时间原语
//! 3. 配置非法时整条策略拒绝加载，绝不"跳过坏配置继续运行"
//! 4. 运行期任何"查不到策略/拿不到必需输入"的情况均 fail closed
//!
//! # 与 P2.2 的关系
//!
//! P2.2 只提供插件链基础设施；本 crate 是第一个真正实现 `Plugin` 的
//! 业务模块。Runtime 在启动期用 [`AuthPlugin::from_configs`] 把
//! `policies.auth` 编译成插件并注册到 `PluginRegistry`。

pub mod api_key;
pub mod basic;
pub mod ip_filter;
pub mod jwt;
pub mod model;
pub mod plugin;
pub mod policy;

// 扁平 re-export：调用方通常只需要这几个类型，
// 不必感知 `model` / `policy` 的模块划分。
pub use model::{AuthIdentity, AuthMechanism, AuthRejection};
pub use plugin::{AuthPlugin, AUTH_PLUGIN_NAME};
pub use policy::{AuthPolicyKind, CompiledAuthPolicies, CompiledAuthPolicy};
