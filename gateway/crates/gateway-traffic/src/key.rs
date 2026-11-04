//! 限流计数键解析。
//!
//! 根据策略配置的 `RateLimitKeySpec`，从请求上下文中提取计数键：
//!   - `client_ip`：客户端 IP（`ctx.client_ip`）
//!   - `global`：固定字符串 `"global"`（所有请求共享一个计数器）
//!   - `header`：指定 Header 的值（例如 `X-API-Key`）
//!   - `route`：路由 ID（`ctx.route.id`）
//!
//! # 键缺失时的行为
//!   - `client_ip` 缺失：返回 `None`（无法限流，放行）
//!   - `header` 缺失：返回 `None`（无法限流，放行）
//!   - `route` 缺失：返回 `None`（无法限流，放行）
//!
//! 返回 `None` 时插件直接放行，不进入限流器。这是 **fail open** 行为：
//! 计数键缺失通常意味着配置错误或请求异常，不应因此拒绝合法流量。

use gateway_core::{RateLimitKeyKind, RateLimitKeySpec};
use gateway_plugin::PluginContext;

/// 从请求上下文提取限流计数键。
///
/// 参数：
/// - `spec`：策略中的键配置
/// - `ctx`：插件上下文
///
/// 返回：
/// - `Some(key)`：成功提取到计数键
/// - `None`：键缺失（放行）
pub fn resolve_key(spec: &RateLimitKeySpec, ctx: &PluginContext<'_>) -> Option<String> {
    match spec.kind {
        // 客户端 IP：直接取 SocketAddr 的 ip 部分
        RateLimitKeyKind::ClientIp => ctx
            .ctx
            .client_ip
            .map(|addr| addr.ip().to_string()),

        // 全局：固定字符串
        RateLimitKeyKind::Global => Some("global".into()),

        // Header：按配置的 Header 名取值
        RateLimitKeyKind::Header => {
            let header_name = spec.header.as_deref()?;
            // HeaderName 已在策略编译期校验过，这里直接解析
            let name = http::HeaderName::from_bytes(header_name.as_bytes()).ok()?;
            ctx.header(&name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        },

        // Route：取路由 ID
        RateLimitKeyKind::Route => ctx.route.as_ref().map(|r| r.id.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::RequestId;
    use gateway_core::RequestContext;
    use http::{HeaderMap, HeaderValue};
    use std::net::SocketAddr;

    /// 辅助：构造带 client_ip 的请求上下文
    fn ctx_with_ip(ip: &str) -> (http::request::Parts, RequestContext) {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static("x-real-ip"),
            HeaderValue::from_str(ip).expect("valid ip"),
        );
        let mut request_ctx = RequestContext::new(RequestId::new());
        // `SocketAddr` 必须带端口；这里固定 80 端口，只关心 ip() 部分
        let addr: SocketAddr = format!("{ip}:80").parse().expect("valid addr");
        request_ctx.client_ip = Some(addr);
        let (parts, _) = http::Request::builder()
            .uri("/")
            .body(())
            .expect("request")
            .into_parts();
        (parts, request_ctx)
    }

    /// client_ip 键正确提取
    #[test]
    fn client_ip_key() {
        let (mut parts, mut ctx) = ctx_with_ip("192.168.1.1");
        let spec = RateLimitKeySpec {
            kind: RateLimitKeyKind::ClientIp,
            header: None,
        };
        let plugin_ctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        assert_eq!(resolve_key(&spec, &plugin_ctx), Some("192.168.1.1".into()));
    }

    /// global 键固定为 "global"
    #[test]
    fn global_key() {
        let (mut parts, mut ctx) = ctx_with_ip("192.168.1.1");
        let spec = RateLimitKeySpec {
            kind: RateLimitKeyKind::Global,
            header: None,
        };
        let plugin_ctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        assert_eq!(resolve_key(&spec, &plugin_ctx), Some("global".into()));
    }

    /// header 键按配置提取
    #[test]
    fn header_key() {
        let (mut parts, mut ctx) = ctx_with_ip("192.168.1.1");
        parts.headers.insert(
            http::header::HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("k-123"),
        );
        let spec = RateLimitKeySpec {
            kind: RateLimitKeyKind::Header,
            header: Some("X-API-Key".into()),
        };
        let plugin_ctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        assert_eq!(resolve_key(&spec, &plugin_ctx), Some("k-123".into()));
    }

    /// header 缺失时返回 None
    #[test]
    fn header_missing_returns_none() {
        let (mut parts, mut ctx) = ctx_with_ip("192.168.1.1");
        let spec = RateLimitKeySpec {
            kind: RateLimitKeyKind::Header,
            header: Some("X-API-Key".into()),
        };
        let plugin_ctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        assert_eq!(resolve_key(&spec, &plugin_ctx), None);
    }
}
