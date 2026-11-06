//! 超时配置解析。
//!
//! 支持全局默认值与路由级覆盖，并区分连接、响应与整体请求三个维度。

use std::time::Duration;

use crate::config::model::{RouteTimeoutConfig, ServerTimeouts};

/// 生效的超时配置。
#[derive(Debug, Clone, Copy)]
pub struct EffectiveTimeouts {
    /// 建立到上游的 TCP/TLS 连接超时。
    pub connect: Duration,
    /// 等待上游响应头的超时。
    pub response: Duration,
    /// 整个请求（含流式响应）的总超时。
    pub total: Duration,
}

impl EffectiveTimeouts {
    pub fn resolve(server: &ServerTimeouts, route: Option<&RouteTimeoutConfig>) -> Self {
        let default_connect = server.client_connect;
        let default_response = server.request;
        let default_total = server.request;
        match route {
            None => Self {
                connect: default_connect,
                response: default_response,
                total: default_total,
            },
            Some(route) => Self {
                connect: route.connect.unwrap_or(default_connect),
                response: route.response.unwrap_or(default_response),
                total: route.total.unwrap_or_else(|| {
                    route
                        .response
                        .unwrap_or(default_response)
                        .max(default_response)
                }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_overrides_defaults() {
        let server = ServerTimeouts::default();
        let route = RouteTimeoutConfig {
            connect: Some(Duration::from_secs(1)),
            response: Some(Duration::from_secs(5)),
            total: Some(Duration::from_secs(20)),
        };
        let effective = EffectiveTimeouts::resolve(&server, Some(&route));
        assert_eq!(effective.connect, Duration::from_secs(1));
        assert_eq!(effective.response, Duration::from_secs(5));
        assert_eq!(effective.total, Duration::from_secs(20));
    }
}
