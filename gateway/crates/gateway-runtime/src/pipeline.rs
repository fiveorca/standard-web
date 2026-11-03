//! Pipeline —— Tower Service 组装（占位模块）。
//!
//! 目前 Runtime::handle_request 内联了所有 Pipeline 步骤。
//! Phase 2 开始会引入 gateway-security / gateway-traffic / gateway-resilience /
//! gateway-plugin，那时需要用 Tower 的 Layer 链式组装 Service：
//!
//! ```text
//! Incoming Request
//!    │
//!    ▼
//! RequestIdLayer      ──── 生成 RequestId
//!    │
//!    ▼
//! CancellationTokenLayer ── 支持请求级取消
//!    │
//!    ▼
//! RouteService         ──── 匹配路由
//!    │
//!    ▼
//! AuthService          ──── JWT / API Key（Phase 2）
//!    │
//!    ▼
//! RateLimitService     ──── Token Bucket（Phase 2）
//!    │
//!    ▼
//! UpstreamService      ──── 选端点 + 连接
//!    │
//!    ▼
//! ProxyService         ──── 转发请求
//!    │
//!    ▼
//! AccessLogLayer       ──── 输出访问日志
//!    │
//!    ▼
//! Response
//! ```
//!
//! 这里保留模块占位说明，Phase 2 扩展时开始在此处写 Tower Layer 实现。
