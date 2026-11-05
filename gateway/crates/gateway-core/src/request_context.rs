//! RequestContext —— 贯穿整个请求处理 Pipeline 的上下文对象。
//!
//! 每个进入网关的请求都会创建一个 `RequestContext`，从入口层一路
//! 传递到 Route Engine、Proxy Client，最后在 Access Log 中输出。
//!
//! # 为什么是可变结构体
//!
//! Pipeline 的每个阶段都会往 Context 里填东西：
//!   - Network Listener 填 host、method、path、query、client_ip
//!   - Route Engine 填 matched_route
//!   - Upstream 填 selected_endpoint
//!   - Proxy 填 upstream_duration、status_code
//!   - Observability 填 request_end_time
//!
//! 用 Arc<Mutex<RequestContext>> 或 tower::Service 闭包捕获都可以。
//! Phase 1 先用 tower::Service 闭包内部持有一个 `Arc<RequestContext>`，
//! 在 Service call 中 clone Arc 后写入字段。
//!
//! # 生命周期
//!
//! ```text
//! RequestContext::new()
//!        │
//!        ├── fill_basic(request_id, host, method, path, ...)
//!        │
//!        ├── [Route Matched] matched_route = Some(Arc<RouteConfig>)
//!        ├── [Endpoint Selected] selected_endpoint = Some(Endpoint)
//!        ├── [Upstream Request] upstream_start = Instant::now()
//!        ├── [Upstream Response] upstream_duration = ...
//!        ├── [Proxy Done] status_code = ...
//!        │
//!        └── [Access Log] emit(&ctx)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http::HeaderMap;

use crate::models::{Endpoint, RouteConfig};
use gateway_common::RequestId;

/// 请求上下文。
///
/// 用 `Arc<RequestContext>` 包装后在 Pipeline 的各阶段之间共享。
/// Arc 的 clone 只是 +1 引用计数，开销极小。
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// 请求 ID，入口层生成（或从 X-Request-Id 继承）
    pub request_id: RequestId,
    /// 分布式追踪 ID（从 traceparent Header 提取，Phase 1 暂未生效）
    pub trace_id: Option<String>,

    // ---- 请求基本信息 ---- //
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub client_ip: Option<SocketAddr>,

    /// 原始请求头（Network Listener 阶段从 http::Request<Body> 提取）
    /// 注意：Tower Service 拿到的是 http::Request，我们不能把整个 Request
    /// 塞进 Context（会有生命周期问题），所以在这里拷贝一份 HeaderMap
    pub headers: HeaderMap,

    // ---- 路由阶段填充 ---- //
    /// Route Engine 匹配到的路由。None 表示还没匹配或匹配失败
    pub matched_route: Option<Arc<RouteConfig>>,

    // ---- 上游阶段填充 ---- //
    /// 选中的上游端点
    pub selected_endpoint: Option<Endpoint>,

    // ---- 观测/时间 ---- //
    /// 请求进入网关的时间点（Instant::now()）
    pub request_start: Instant,
    /// 上游连接建立的时间点
    pub upstream_start: Option<Instant>,
    /// 上游响应首字节到达的时间点
    pub upstream_headers_arrived: Option<Instant>,
    /// 请求结束时间点（无论成功或失败）
    pub request_end: Option<Instant>,
    /// 最终返回给客户端的 HTTP 状态码
    pub status_code: Option<u16>,

    // ---- 身份与租户（Phase 7）---- //
    /// 认证后的消费者标识（JWT sub / Basic 用户名 / API Key label）
    pub consumer_id: Option<String>,
    /// 认证身份所属租户（JWT tenant 声明 / API Key 绑定的租户）
    pub tenant_id: Option<String>,

    // ---- 错误（如果有）---- //
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl RequestContext {
    /// 创建新的请求上下文。
    ///
    /// 参数：
    /// - `request_id`：入口层生成的请求 ID（或从 X-Request-Id Header 继承）
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            trace_id: None,
            method: String::new(),
            host: String::new(),
            path: String::new(),
            query: None,
            client_ip: None,
            headers: HeaderMap::new(),
            matched_route: None,
            selected_endpoint: None,
            request_start: Instant::now(),
            upstream_start: None,
            upstream_headers_arrived: None,
            request_end: None,
            status_code: None,
            consumer_id: None,
            tenant_id: None,
            error_code: None,
            error_message: None,
        }
    }

    /// 填充请求基本信息。Network Listener 在解析完 HTTP 请求后调用。
    pub fn fill_basic(
        &mut self,
        method: http::Method,
        host: String,
        path: String,
        query: Option<String>,
        headers: HeaderMap,
        client_ip: Option<SocketAddr>,
    ) {
        self.method = method.as_str().to_string();
        self.host = host;
        self.path = path;
        self.query = query;
        self.headers = headers;
        self.client_ip = client_ip;
    }

    /// 记录匹配到的路由。Route Engine 在匹配成功后调用。
    pub fn set_route(&mut self, route: Arc<RouteConfig>) {
        self.matched_route = Some(route);
    }

    /// 记录选中的上游端点。Upstream Manager 在选出端点后调用。
    pub fn set_endpoint(&mut self, ep: Endpoint) {
        self.selected_endpoint = Some(ep);
    }

    /// 标记请求开始连接上游。
    pub fn mark_upstream_start(&mut self) {
        self.upstream_start = Some(Instant::now());
    }

    /// 标记上游响应首字节到达。
    pub fn mark_upstream_headers(&mut self) {
        self.upstream_headers_arrived = Some(Instant::now());
    }

    /// 标记请求结束并设置状态码。
    pub fn finish(&mut self, status_code: u16) {
        self.request_end = Some(Instant::now());
        self.status_code = Some(status_code);
    }

    /// 标记请求结束并记录错误。
    pub fn finish_with_error(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.request_end = Some(Instant::now());
        self.status_code = Some(502); // 兜底
        self.error_code = Some(code.into());
        self.error_message = Some(message.into());
    }

    /// 计算请求总耗时（毫秒）。
    /// 未结束时返回从开始到现在的毫秒数。
    pub fn total_duration_ms(&self) -> u64 {
        let end = self.request_end.unwrap_or_else(Instant::now);
        end.duration_since(self.request_start).as_millis() as u64
    }

    /// 计算上游耗时（毫秒）。
    /// 如果还没开始或没有响应则返回 0。
    pub fn upstream_duration_ms(&self) -> u64 {
        match (self.upstream_start, self.upstream_headers_arrived) {
            (Some(start), Some(end)) => end.duration_since(start).as_millis() as u64,
            _ => 0,
        }
    }
}
