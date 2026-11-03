//! HttpServer —— Hyper HTTP 服务封装（简化版）。
//!
//! Phase 1 只支持 HTTP/1.1。HTTP/2（需要 ALPN + TLS）放到 Phase 2。
//!
//! # 并发限制
//!
//! tokio::sync::Semaphore 做 Bulkhead。超过 max_concurrent_requests
//! 时 try_acquire 失败，立即返回 503，不阻塞。
//! Phase 1 暂不启用（注释中保留），Phase 2 gateway-resilience 统一接入。
//!
//! # 优雅关闭
//!
//! CancellationToken 在收到 SIGTERM/SIGINT 时触发。accept loop 被取消，
//! 在途请求继续处理完后退出。
//!
//! # 泛型 Body 设计
//!
//! handler 的返回类型 `Response<ResBody>` 中 `ResBody` 是泛型的：
//! - 成功路径（上游代理）：`ResBody = hyper::body::Incoming`
//!   （hyper server 端的默认 body 类型，直接透传上游响应流）
//! - 错误路径（404/502 等）：`ResBody = http_body_util::Empty<bytes::Bytes>`
//!   （空 body，不携带 payload）
//!
//! 这两种 Body 类型都满足 `hyper::body::Body + Send + Sync + 'static`
//! 以及 `Body::Error: Into<Box<dyn StdError + Send + Sync>>`。

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use gateway_common::GatewayError;
use http::Request;
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;

// ---------------------------------------------------------------------------
// 构造选项
// ---------------------------------------------------------------------------

/// HttpServer 构造选项。
///
/// 这些参数在 Runtime 启动时从 GatewayConfig 读取。
/// Phase 1 中大部分是透传，Phase 2+ 会逐步启用。
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// 最大并发请求数（Bulkhead）。超过时新请求立即 503。
    pub max_concurrent_requests: u32,
    /// 最大请求体大小（字节）。超过时返回 413。Phase 2 启用。
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
/// 业务逻辑（路由匹配、上游转发、错误处理）通过 `service` 闭包注入。
pub struct HttpServer {
    /// 监听地址（IP + Port），例如 `0.0.0.0:8080`
    addr: SocketAddr,
    /// 构造选项（并发限制、超时等）
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
    /// - `ResBody`：响应 Body 类型。因为成功和错误路径用不同的 Body
    ///   （成功=Incoming，错误=Empty<Bytes>），所以必须泛型化。
    ///
    /// # Body trait bounds 解释
    /// - `ResBody: Body` —— hyper body 抽象 trait（http-body crate 提供）
    /// - `ResBody: Send + Sync + 'static` —— 多线程安全 + 生命周期足够长
    /// - `ResBody::Error: Into<Box<dyn StdError + Send + Sync>>` ——
    ///   hyper 的 `http1::Builder::serve_connection` 要求 Body 的错误能
    ///   转成 Box<dyn StdError>。`Infallible` 满足这个 bound（因为它
    ///   实现了 StdError，且 Into 实现自动推导）。
    ///
    /// # 参数
    /// - `service`：业务处理闭包。签名：
    ///   ```ignore
    ///   Fn(Request<Incoming>) -> impl Future<Output = Result<http::Response<ResBody>, Infallible>>
    ///   ```
    /// - `shutdown`：CancellationToken。调用 `token.cancel()` 触发优雅关闭。
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
        // 对于 Infallible：Infallible 实现 StdError + Send + Sync，所以自动满足。
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
        // 2. 并发限制信号量
        // =================================================================
        // Phase 2 启用：Semaphore::new(N) + try_acquire() 在 service 层限流
        // 目前先创建但不使用，保留扩展点
        let semaphore = Arc::new(Semaphore::new(self.options.max_concurrent_requests as usize));

        // =================================================================
        // 3. Accept Loop
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

                    let sem = semaphore.clone();
                    let svc = service.clone();

                    // 每个连接一个 spawn task：hyper 的 serve_connection
                    // 内部已经是全异步的，不需要我们再做线程池管理
                    tokio::spawn(async move {
                        let svc = svc.clone();
                        // Phase 2 Bulkhead：
                        // let _permit = sem.try_acquire().ok_or_else(|| ...)?;
                        let _ = sem;

                        // tower::service_fn：接受一个 async 闭包，生成 Tower Service。
                        // Tower Service 的核心 trait 是 tower::Service<Request> → Future<Response>。
                        // 我们的 handler 闭包签名 Fn(Request<Incoming>) -> Fut 恰好匹配。
                        let tower_svc = tower::service_fn(move |req: Request<Incoming>| {
                            let svc = svc.clone();
                            // 直接调用闭包得到 Future，service_fn 会 .await 它
                            svc(req)
                        });

                        // TowerToHyperService：把 Tower Service 转成 hyper 1.x 的 Service trait。
                        // hyper 和 Tower 的 Service trait 签名略有不同，这个适配器统一了两者。
                        let hyper_svc = TowerToHyperService::new(tower_svc);

                        // http1::Builder::serve_connection：启动 HTTP/1.1 协议处理。
                        // 参数：
                        // - io：TokioIo<TcpStream>——hyper 直接在这个上面读写
                        // - hyper_svc：转换后的 hyper Service——每个请求调用一次
                        //
                        // 返回的 Future resolve 时代表连接生命周期结束（正常关闭或错误）。
                        let result = http1::Builder::new()
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
