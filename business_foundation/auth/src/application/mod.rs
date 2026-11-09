//! 业务用例层。
//!
//! 每个文件通过 `impl AppState` 提供一组用例，HTTP 层只负责参数解析与响应包装。

pub mod audit;
pub mod events;
pub mod identity;
pub mod mfa;
pub mod rbac;
pub mod session;

/// 请求元信息，用于审计与风控。
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
}

impl RequestMeta {
    pub fn new(ip: Option<String>, user_agent: Option<String>, trace_id: Option<String>) -> Self {
        Self {
            ip,
            user_agent,
            trace_id,
        }
    }
}
