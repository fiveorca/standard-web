//! ProxyClient —— 流式反向代理核心。
//!
//! # Hyper 1.x / hyper-util 0.1 API 说明
//!
//! hyper 1.x 的 Client 需要显式指定 Request Body 类型。hyper-util 提供了：
//!   - `hyper_util::client::legacy::Client<C, B>` —— 两个泛型：Connector 和 **Request Body**
//!   - `hyper_util::client::legacy::connect::HttpConnector` —— 内置 HTTP Connector
//!   - `hyper_util::rt::TokioExecutor` —— 用 Tokio 驱动 Hyper 的 Executor
//!
//! 我们让 ProxyClient 的 ReqBody 泛型化：
//! - 生产环境：`ProxyClient`（默认 ReqBody = Incoming）
//! - 测试：`ProxyClient::<Full<Bytes>>`（用 Full<Bytes> 构造请求）
//!
//! # Hop-by-Hop Header
//!
//! RFC 7230 规定代理不能转发这些 header，headers.rs 模块做清洗。

use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::time::Duration;

use gateway_common::GatewayError;
use gateway_core::Endpoint;
use http::Uri;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

/// 流式请求体统一错误类型（与 gateway-runtime 的 `BoxError` 语义一致）。
///
/// 镜像请求需要在运行时把 `Incoming` 与自定义 tee body 擦除成同一种类型，
/// 这里单独定义避免 gateway-proxy 依赖 gateway-runtime。
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

use crate::headers::{inject_forwarded_headers, strip_hop_by_hop, strip_response_hop_by_hop};

// ---------------------------------------------------------------------------
// ProxyOptions
// ---------------------------------------------------------------------------

/// ProxyClient 构造选项。
#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// 上游请求超时（从发出请求到收到响应 headers 的时间）
    pub request_timeout: Duration,
    /// 上游 TCP 连接超时（hyper-util 内部 HttpConnector 使用）
    pub connect_timeout: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyClient
// ---------------------------------------------------------------------------

/// 反向代理客户端。
///
/// # 泛型参数 `ReqBody`
///
/// `ReqBody` 是**发往上游的请求体类型**，默认是 `Incoming`：
/// - **生产环境**：网关从 hyper server 收到的请求体是 `Incoming`，
///   直接透传给上游 hyper client
/// - **测试环境**：用 `Full<Bytes>` 或 `Empty<Bytes>` 构造假请求
///
/// Client 内部维护 HTTP/1.1 连接池（keep-alive），多线程安全。
/// 每个 ProxyClient 实例共享同一个 Client，连接池自动复用。
///
/// # hyper-util Client 构造流程
///
/// 1. `HttpConnector::new()` —— TCP 连接器（自动 keep-alive 连接池）
/// 2. `Client::builder(TokioExecutor::new())` —— 指定 Tokio 作为 async Executor
/// 3. `.http1_title_case_headers(true)` —— hyper-util 0.1 要求显式传 bool
/// 4. `.build(connector)` —— 构造 Client，Body 类型由泛型推断
pub struct ProxyClient<ReqBody = Incoming> {
    /// HTTP/1.1 客户端（默认路径）
    client: Client<HttpConnector, ReqBody>,
    /// HTTP/2 (h2c, prior knowledge) 客户端：gRPC 请求走这里
    h2_client: Client<HttpConnector, ReqBody>,
    /// 类型擦除 body 的 HTTP/1.1 客户端。
    ///
    /// 流量镜像需要把一个请求体同时喂给主请求与影子请求，
    /// tee 之后 body 不再是 `Incoming`，只能走 BoxBody 擦除路径。
    boxed_client: Client<HttpConnector, BoxBody<bytes::Bytes, BoxError>>,
    /// 类型擦除 body 的 HTTP/2 客户端（镜像 gRPC 请求时使用）。
    boxed_h2_client: Client<HttpConnector, BoxBody<bytes::Bytes, BoxError>>,
    /// 请求超时等配置
    options: ProxyOptions,
}

// 允许不使用的 Infallible（未来可能用到）
#[allow(dead_code)]
fn _unused(_: Infallible) {}

impl<ReqBody> ProxyClient<ReqBody>
where
    // ReqBody 必须实现 hyper Body trait
    ReqBody: hyper::body::Body + Send + Sync + Unpin + 'static,
    // Body::Error 必须能转成 Box<dyn StdError>（hyper client 的要求）
    ReqBody::Error: Into<Box<dyn StdError + Send + Sync>>,
    // Body::Data 必须 Send（hyper client 内部会跨线程传递）
    ReqBody::Data: Send,
{
    /// 创建新的 ProxyClient。
    ///
    /// # 参数
    /// - `options`：超时等配置
    ///
    /// # 泛型推断
    /// ReqBody 类型通过调用上下文推断：
    /// - runtime 里：`ProxyClient::new(opts)` → ReqBody 默认 `Incoming`
    /// - 测试里：`ProxyClient::<Full<Bytes>>::new(opts)` → 显式指定
    pub fn new(options: ProxyOptions) -> Self {
        // HttpConnector 是 hyper-util 提供的 TCP 连接器
        // 它内部有 keep-alive 连接池，多线程安全
        let connector = HttpConnector::new();

        // Client::builder 创建 hyper-util Client
        // Client 的第二个泛型 Body 从 ReqBody 泛型自动推断
        let client = Client::builder(TokioExecutor::new())
            // http1_title_case_headers：HTTP/1.1 header 名称大小写
            // hyper-util 0.1 版本这个方法需要显式传 bool
            .http1_title_case_headers(true)
            .build::<_, ReqBody>(connector.clone());

        // HTTP/2 client：http2_only = 明文 h2c prior knowledge（不做 ALPN 协商）。
        // 用于透传 gRPC：入站请求版本为 HTTP/2 时改走该 client。
        let h2_client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build::<_, ReqBody>(connector.clone());

        // BoxBody 客户端：流量镜像的 tee body 使用类型擦除后的统一 body
        let boxed_client = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .build::<_, BoxBody<bytes::Bytes, BoxError>>(connector.clone());
        let boxed_h2_client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build::<_, BoxBody<bytes::Bytes, BoxError>>(connector);

        Self {
            client,
            h2_client,
            boxed_client,
            boxed_h2_client,
            options,
        }
    }

    /// 转发一个 body 已类型擦除的请求。
    ///
    /// 供流量镜像使用：tee 后的主请求/影子请求 body 都是
    /// `BoxBody<Bytes, BoxError>`，通过本方法发送。
    ///
    /// 语义与 [`ProxyClient::forward`] 完全一致（头清洗、代理链头、超时）。
    pub async fn forward_boxed(
        &self,
        request: http::Request<BoxBody<bytes::Bytes, BoxError>>,
        endpoint: &Endpoint,
        upstream_path: &str,
        client_ip: Option<SocketAddr>,
        per_request_timeout: Option<Duration>,
    ) -> Result<http::Response<Incoming>, GatewayError> {
        // 与 forward 相同的协议判定：HTTP/2 入站走 h2c client
        let use_h2 = request.version() == http::Version::HTTP_2;
        let uri_str = format!("http://{}{}", endpoint.address(), upstream_path);
        let uri: Uri = uri_str
            .parse()
            .map_err(|e| GatewayError::Internal(format!("invalid upstream uri: {e}")))?;

        let (mut parts, body) = request.into_parts();
        // 请求方向 Hop-by-Hop 清洗（保留 Upgrade / TE: trailers 的规则一致）
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove("host");
        inject_forwarded_headers(&mut parts.headers, client_ip, "http");

        let mut upstream_req = http::Request::from_parts(parts, body);
        *upstream_req.uri_mut() = uri;

        let send_future = if use_h2 {
            self.boxed_h2_client.request(upstream_req)
        } else {
            self.boxed_client.request(upstream_req)
        };
        let timeout = per_request_timeout.unwrap_or(self.options.request_timeout);
        match tokio::time::timeout(timeout, send_future).await {
            Ok(Ok(response)) => {
                let (mut resp_parts, resp_body) = response.into_parts();
                strip_response_hop_by_hop(&mut resp_parts.headers);
                Ok(http::Response::from_parts(resp_parts, resp_body))
            },
            Ok(Err(hyper_err)) => Err(GatewayError::UpstreamConnectionError {
                upstream: endpoint.address(),
                endpoint: endpoint.address(),
                reason: hyper_err.to_string(),
            }),
            Err(_elapsed) => Err(GatewayError::UpstreamTimeout {
                upstream: endpoint.address(),
                endpoint: endpoint.address(),
            }),
        }
    }

    /// 转发请求到上游端点。
    ///
    /// # 参数
    /// - `request`：网关侧原始请求。Body 类型 ReqBody 与 ProxyClient 泛型一致
    /// - `endpoint`：选中的上游端点（host + port）
    /// - `upstream_path`：请求路径（可能经过 path_rewrite）
    /// - `client_ip`：客户端 IP（用于 X-Forwarded-For header）
    ///
    /// # 返回
    /// `Result<http::Response<Incoming>, GatewayError>` ——
    /// 上游响应体总是 `Incoming`（hyper client 的 Response body 固定是 Incoming）
    pub async fn forward(
        &self,
        request: http::Request<ReqBody>,
        endpoint: &Endpoint,
        upstream_path: &str,
        client_ip: Option<SocketAddr>,
        per_request_timeout: Option<Duration>,
    ) -> Result<http::Response<Incoming>, GatewayError> {
        // 入站为 HTTP/2（gRPC）时，上游也必须用 HTTP/2 发送，
        // 否则 gRPC 的 trailers 与 `te: trailers` 语义无法透传。
        let use_h2 = request.version() == http::Version::HTTP_2;

        // =================================================================
        // 1. 构造上游 URI
        // =================================================================
        let uri_str = format!("http://{}{}", endpoint.address(), upstream_path);
        let uri: Uri = uri_str
            .parse()
            .map_err(|e| GatewayError::Internal(format!("invalid upstream uri: {e}")))?;

        // =================================================================
        // 2. 拆开原请求，组装上游请求
        // =================================================================
        let (mut parts, body) = request.into_parts();

        // Hop-by-Hop Header 清洗（请求方向）
        // RFC 7230 规定代理不能转发：Connection / Keep-Alive / Transfer-Encoding 等
        strip_hop_by_hop(&mut parts.headers);
        // Host header 会被 hyper client 根据 URI 自动设置，先移除避免冲突
        parts.headers.remove("host");
        // 注入代理链头：X-Forwarded-For / X-Forwarded-Proto 等
        inject_forwarded_headers(&mut parts.headers, client_ip, "http");

        // 组装新请求：原始 Parts（已清洗）+ 原始 Body
        let mut upstream_req = http::Request::from_parts(parts, body);
        // 覆盖 URI 为真实上游地址（原 URI 可能是网关侧的路径）
        *upstream_req.uri_mut() = uri;

        // =================================================================
        // 3. 带超时发送
        // =================================================================
        // Client::request 返回 ResponseFuture
        let send_future = if use_h2 {
            self.h2_client.request(upstream_req)
        } else {
            self.client.request(upstream_req)
        };
        // 超时：per-request 覆盖优先，fallback 到 ProxyOptions 的兜底值
        let timeout = per_request_timeout.unwrap_or(self.options.request_timeout);
        let result = tokio::time::timeout(timeout, send_future).await;

        match result {
            // hyper client 成功返回 Response
            Ok(Ok(response)) => {
                let (mut resp_parts, resp_body) = response.into_parts();
                // Hop-by-Hop Header 清洗（响应方向）
                strip_response_hop_by_hop(&mut resp_parts.headers);
                Ok(http::Response::from_parts(resp_parts, resp_body))
            },
            // hyper client 连接错误 / 协议错误
            Ok(Err(hyper_err)) => {
                tracing::warn!(
                    upstream = endpoint.address(),
                    error = hyper_err.to_string(),
                    "upstream connection error"
                );
                // hyper::Error 在 hyper 1.x 没有细粒度分类（is_connect/is_timeout 等都没公开）
                // 简化策略：所有 hyper::Error 都映射为 UpstreamConnectionError（502 Bad Gateway）
                Err(GatewayError::UpstreamConnectionError {
                    upstream: endpoint.address(),
                    endpoint: endpoint.address(),
                    reason: hyper_err.to_string(),
                })
            },
            // 超时
            Err(_elapsed) => {
                tracing::warn!(
                    upstream = endpoint.address(),
                    timeout_ms = timeout.as_millis() as u64,
                    "upstream request timeout"
                );
                Err(GatewayError::UpstreamTimeout {
                    upstream: endpoint.address(),
                    endpoint: endpoint.address(),
                })
            },
        }
    }
}

impl<ReqBody> std::fmt::Debug for ProxyClient<ReqBody> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyClient")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 测试：正常转发成功
    #[tokio::test]
    async fn forward_success() {
        // 启动 wiremock mock server（随机端口）
        let mock_server = MockServer::start().await;
        // 注册 mock：GET /hello → 200 "ok"
        Mock::given(method("GET"))
            .and(path("/hello"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        // 从 mock server URI 解析 host + port
        let uri = mock_server.uri();
        let host_port = uri.trim_start_matches("http://");
        let (host, port) = host_port.split_once(':').unwrap();

        // 用 Full<Bytes> 作为 Request Body 类型（测试里不能构造 Incoming）
        let client = ProxyClient::<Full<Bytes>>::new(ProxyOptions::default());

        let endpoint = Endpoint {
            runtime_id: "ep-test".into(),
            host: host.into(),
            port: port.parse().unwrap(),
            weight: 1,
            zone: None,
            status: gateway_core::HealthStatus::Healthy,
        };

        // 构造测试请求：GET /hello，空 body
        let request = http::Request::builder().method("GET").body(Full::new(Bytes::new())).unwrap();

        let response = client
            .forward(request, &endpoint, "/hello", None, None)
            .await
            .expect("should succeed");

        assert_eq!(response.status(), http::StatusCode::OK);
    }

    /// 测试：上游连接错误（连 127.0.0.1:1 会被拒绝）
    #[tokio::test]
    async fn forward_connection_error() {
        let client = ProxyClient::<Full<Bytes>>::new(ProxyOptions {
            connect_timeout: Duration::from_millis(100),
            request_timeout: Duration::from_millis(500),
        });

        let endpoint = Endpoint {
            runtime_id: "ep-bad".into(),
            host: "127.0.0.1".into(),
            port: 1, // 特权端口，正常用户无法监听
            weight: 1,
            zone: None,
            status: gateway_core::HealthStatus::Healthy,
        };

        let request = http::Request::builder().method("GET").body(Full::new(Bytes::new())).unwrap();

        let err = client
            .forward(request, &endpoint, "/", None, None)
            .await
            .expect_err("should fail");

        assert!(matches!(err, GatewayError::UpstreamConnectionError { .. }));
    }
}
