//! HttpServer —— Hyper HTTP 服务封装（简化版）。
//!
//! 同时支持 HTTP/1.1 与 HTTP/2（h2c，prior knowledge）：
//! `hyper_util::server::conn::auto` 会在连接建立时自动识别协议，
//! 因此同一端口可以同时服务 REST（HTTP/1.1）与 gRPC（HTTP/2）。
//! TLS（ALPN）在 Phase 6 后续的 TLS 监听器中完成。
//!
//! # 并发限制（Bulkhead）
//!
//! tokio::sync::Semaphore::try_acquire_owned() 做 Bulkhead。超过
//! max_concurrent_requests 时立即返回 503（`GATEWAY_BULKHEAD_FULL`），
//! 不阻塞不排队。每个请求获取一个 permit，处理完自动 drop 释放。
//! Bulkhead 由调用方（Runtime 层）在 handle_request 入口处执行。
//!
//! # 请求体大小限制
//!
//! Content-Length 头超过 max_request_body_size 时返回 413
//! （`GATEWAY_REQUEST_TOO_LARGE`）。在 Runtime 层 handle_request 入口检查。
//! Chunked transfer-encoding（无 Content-Length）场景无法提前拦截，
//! 需 runtime 层配合流式读取时做限制。
//!
//! # 优雅关闭
//!
//! CancellationToken 在收到 SIGTERM/SIGINT 时触发。accept loop 被取消，
//! 在途请求继续处理完后退出。
//!
//! # 泛型 Body 设计
//!
//! handler 的返回类型 `Response<ResBody>` 中 `ResBody` 是泛型的。
//! P2.0 起，gateway-runtime 统一使用
//! `http_body_util::combinators::BoxBody<Bytes, BoxError>`（类型擦除）：
//! - 成功路径（上游代理）：上游 `Incoming` 经 `BodyExt::boxed()` 流式透传
//! - 错误路径（404/502 等）：内存构造的 `Full<Bytes>` JSON 经 `boxed()` 统一
//!
//! 约束 `hyper::body::Body + Send + Sync + 'static`
//! 以及 `Body::Error: Into<Box<dyn StdError + Send + Sync>>` 均满足。
//!
//! # 客户端地址注入（P2.0 新增）
//!
//! accept 连接后，对端 `SocketAddr` 会被写入 request extensions，
//! handler 通过 `req.extensions().get::<SocketAddr>()` 提取 client_ip，
//! 用于 AccessLog 与 X-Forwarded-For。

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::net::SocketAddr;

use gateway_common::GatewayError;
use http::Request;
use hyper::body::{Body, Incoming};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;

// ---------------------------------------------------------------------------
// 构造选项
// ---------------------------------------------------------------------------

/// HttpServer 构造选项。
///
/// 这些参数在 Runtime 启动时从 GatewayConfig 读取。
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// 最大并发请求数（Bulkhead）。超过时新请求立即 503。
    pub max_concurrent_requests: u32,
    /// 最大请求体大小（字节）。超过时返回 413。
    pub max_request_body_size: u64,
    /// 优雅关闭等待时间（秒）。shutdown 信号收到后最多等这么久。
    pub graceful_shutdown_timeout_secs: u64,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 5_000,
            max_request_body_size: 10 * 1024 * 1024,
            graceful_shutdown_timeout_secs: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// HttpServer 主体
// ---------------------------------------------------------------------------

/// Hyper HTTP Server 封装。
///
/// # 职责边界
///
/// HttpServer 只做 IO：绑定端口、accept 连接、hyper server 驱动。
/// 业务逻辑（Bulkhead、请求体限制、路由匹配、上游转发、错误处理）
/// 全部通过 `service` 闭包注入（Runtime 层负责）。
pub struct HttpServer {
    /// 监听地址（IP + Port），例如 `0.0.0.0:8080`
    addr: SocketAddr,
    /// 构造选项（并发限制、超时等）。
    /// Bulkhead 和 body limit 已移到 Runtime 层，ServerOptions 保留用于
    /// 未来扩展（如 TLS 配置、连接 keep-alive 参数等）。
    #[allow(dead_code)]
    options: ServerOptions,
}

impl HttpServer {
    /// 创建新的 HttpServer。
    ///
    /// # 参数
    /// - `addr`：要绑定的监听地址
    /// - `options`：ServerOptions 配置（默认值用 `ServerOptions::default()`）
    pub fn new(addr: SocketAddr, options: ServerOptions) -> Self {
        Self { addr, options }
    }

    /// 启动 HTTP Server，阻塞直到 shutdown 信号。
    ///
    /// # 泛型参数说明
    /// - `F`：handler 闭包类型。要求 `Fn(Request<Incoming>) -> Fut`，
    ///   即接受一个 hyper server 端的 Request，返回一个 Future。
    /// - `Fut`：handler 返回的 Future 类型。resolve 后必须是
    ///   `Result<http::Response<ResBody>, Infallible>`。
    /// - `ResBody`：响应 Body 类型。runtime 层统一用 BoxBody（类型擦除）。
    ///
    /// # hyper 1.x / hyper-util 0.1 API 调用链
    ///
    /// ```text
    /// HttpServer::serve
    ///   ├── tokio::net::TcpListener::bind      ← 绑定端口
    ///   ├── (accept loop)
    ///   │     ├── listener.accept()             ← accept 新连接
    ///   │     ├── hyper_util::rt::TokioIo::new ← 把 TcpStream 转成 hyper 兼容 IO
    ///   │     ├── tower::service_fn(handler)   ← 闭包 → Tower Service
    ///   │     ├── TowerToHyperService::new     ← Tower Service → hyper Service
    ///   │     └── http1::Builder::serve_connection(io, svc)  ← 启动连接处理
    ///   └── CancellationToken::cancelled()    ← 监听 shutdown
    /// ```
    pub async fn serve<F, Fut, ResBody>(
        self,
        service: F,
        shutdown: CancellationToken,
    ) -> Result<(), GatewayError>
    where
        // F：handler 闭包。Fn 而不是 FnMut——因为 Clone 后可能被多线程并发调用
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + Clone + 'static,
        // Fut：handler 返回的 Future。Send 是因为 .await 跨越线程边界
        Fut: Future<Output = Result<http::Response<ResBody>, Infallible>> + Send + 'static,
        // ResBody：响应 Body 类型。Body trait 来自 http-body crate（hyper re-export）
        ResBody: Body + Send + Sync + 'static,
        // Body::Data 也必须 Send——因为 hyper 内部会把 body 的 Data 跨线程传递
        ResBody::Data: Send,
        // Body::Error 必须能转成 Box<dyn StdError>。
        ResBody::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        // =================================================================
        // 1. 绑定 TcpListener
        // =================================================================
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|e| GatewayError::Internal(format!("failed to bind {}: {e}", self.addr)))?;

        let actual = listener
            .local_addr()
            .map_err(|e| GatewayError::Internal(format!("failed to get local addr: {e}")))?;
        tracing::info!(target: "http_server", "listening on {}", actual);

        // =================================================================
        // 2. Accept Loop
        // =================================================================
        loop {
            tokio::select! {
                // 分支 A：收到 shutdown 信号 → 退出 accept loop
                _ = shutdown.cancelled() => {
                    tracing::info!(target: "http_server", "shutdown signal received");
                    break;
                }
                // 分支 B：有新连接 → accept 并 spawn 处理
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = match accept_res {
                        Ok(v) => v,
                        Err(e) => {
                            // accept 错误通常是临时的（如文件描述符耗尽），
                            // 记录后继续下一轮
                            tracing::error!(
                                target: "http_server",
                                error = e.to_string(),
                                "accept error"
                            );
                            continue;
                        }
                    };

                    // TCP_NODELAY：禁用 Nagle 算法，降低小包延迟（代理场景常用）
                    let _ = stream.set_nodelay(true);

                    // TokioIo::new()：把 tokio::net::TcpStream 包装成
                    // hyper 1.x 内部使用的 IO trait（hyper_util 提供）
                    let io = TokioIo::new(stream);

                    let svc = service.clone();

                    // 每个连接一个 spawn task：hyper 的 serve_connection
                    // 内部已经是全异步的，不需要我们再做线程池管理
                    tokio::spawn(async move {
                        let svc = svc.clone();

                        // tower::service_fn：接受一个 async 闭包，生成 Tower Service。
                        // Tower Service 的核心 trait 是 tower::Service<Request> → Future<Response>。
                        // 我们的 handler 闭包签名 Fn(Request<Incoming>) -> Fut 恰好匹配。
                        let tower_svc = tower::service_fn(move |mut req: Request<Incoming>| {
                            let svc = svc.clone();
                            // 把客户端对端地址注入 request extensions（P2.0 新增）。
                            // handler（Runtime::handle_request）从这里取 client_ip，
                            // 用于 AccessLog 的 client_ip 字段和 X-Forwarded-For 头。
                            // extensions_mut() 返回 &mut Extensions，insert 存任意 Send+Sync 类型。
                            req.extensions_mut().insert(peer_addr);
                            // 直接调用闭包得到 Future，service_fn 会 .await 它
                            svc(req)
                        });

                        // TowerToHyperService：把 Tower Service 转成 hyper 1.x 的 Service trait。
                        // hyper 和 Tower 的 Service trait 签名略有不同，这个适配器统一了两者。
                        let hyper_svc = TowerToHyperService::new(tower_svc);

                        // auto::Builder 根据客户端协议自动选择 HTTP/1.1 或 HTTP/2（h2c）：
                        //   - 普通 HTTP/1.1 请求走 http1
                        //   - gRPC / HTTP/2 prior-knowledge 请求走 h2c
                        // 这样同一个监听端口即可同时承载 REST 与 gRPC。
                        let result = auto::Builder::new(TokioExecutor::new())
                            .serve_connection(io, hyper_svc)
                            .await;

                        // 连接级错误（协议错误、客户端断连等），不影响其他连接
                        if let Err(e) = result {
                            tracing::debug!(
                                target: "http_server",
                                peer = peer_addr.to_string(),
                                error = e.to_string(),
                                "connection error"
                            );
                        }
                    });
                }
            }
        }

        tracing::info!(target: "http_server", "exited cleanly");
        Ok(())
    }
}
