//! Admin API 共享状态。

use std::sync::Arc;

use gateway_control_service::ConfigService;

use crate::auth::AdminAuth;

/// Axum 共享状态。
///
/// `ConfigService` 内部已是 `Arc`（仓储 + 回调），克隆成本很低。
#[derive(Clone)]
pub struct AdminState {
    /// 控制面业务服务
    pub service: ConfigService,
    /// 静态 Bearer Token 认证器
    pub auth: Arc<AdminAuth>,
}

impl AdminState {
    /// 创建共享状态。
    pub fn new(service: ConfigService, auth: AdminAuth) -> Self {
        Self {
            service,
            auth: Arc::new(auth),
        }
    }
}
