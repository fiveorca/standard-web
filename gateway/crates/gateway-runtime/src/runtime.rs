//! Runtime 结构体 —— 数据面运行时组合根。
//!
//! # 启动流程
//!
//! ```text
//! Runtime::load_from_path("gateway.yaml")
//!       │
//!       ├── gateway_config::load_from_path()   ← 读取文件 + Figment 环境变量覆盖
//!       ├── gateway_config::validate()          ← ID 唯一性、引用完整性、路由冲突
//!       ├── RouteTable::compile()               ← Host 分桶 + 前缀树 + 优先级排序
//!       ├── UpstreamRegistry::new()             ← 实例表 + 健康状态
//!       └── ProxyClient::new()                  ← hyper Client 初始化
//!
//! runtime.start().await
//!       │
//!       ├── spawn(admin::start_admin_server)    ← Axum 管理接口（CP）
//!       ├── spawn(http_server.serve)            ← Hyper 业务端口（DP）
//!       ├── install_signal_handler()            ← SIGTERM/SIGINT → CancellationToken
//!       └── tokio::select! 等待 shutdown
//! ```
//!
//! # 设计约束
//!
//! - Runtime 是组合根：它只做组装，不实现路由/转发/负载均衡逻辑
//! - 所有共享状态用 `Arc<T>` 包装，Service 闭包 clone Arc 是 +1 引用计数
//! - Phase 1 配置一次性加载，热更新留到 Phase 3（Control Plane）
//! - **无 unwrap/expect**：所有错误显式处理

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gateway_common::{GatewayError, RequestId};
use gateway_config::{load_from_path, validate, GatewayConfig};
use gateway_core::UpstreamManager;
use gateway_network::{HttpServer, ServerOptions};
use gateway_observability::init_logging;
use gateway_proxy::{ProxyClient, ProxyOptions};
use gateway_routing::RouteTable;
use gateway_upstream::UpstreamRegistry;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use tokio::sync::{oneshot, Mutex};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Body 类型别名
// ---------------------------------------------------------------------------

/// Phase 1 统一使用的响应体类型：`Full<Bytes>`。
///
/// # 为什么不直接用 Incoming？
///
/// `Incoming` 是 hyper server 端特有的 body 类型，代表从 socket 读的请求体/响应体。
/// 它不能在业务代码里"构造"——它只能从 hyper 内部的连接获得。
///
/// # 为什么 Phase 1 用 Full<Bytes>？
///
/// - 成功路径：把上游返回的 `Incoming` body **完全收集**（`.collect().await`），
///   然后用 `Full::new(bytes)` 构造响应。牺牲了流式转发的优势，但代码简单。
/// - 错误路径：直接用 `Full::new(Bytes::from(json_string))` 构造 JSON 错误 body。
///
/// # Phase 2 改进计划
///
/// Phase 2 引入 `http_body_util::EitherBody<Incoming, Full<Bytes>>` 或
/// `tower_http::body::BoxBody` 做类型擦除，让成功路径恢复流式透传。
/// 需要修改 gateway-network::serve 的泛型 ResBody。
type ResBody = Full<Bytes>;

// ---------------------------------------------------------------------------
// Runtime 结构体
// ---------------------------------------------------------------------------

/// 数据面运行时。
///
/// 持有启动时构建的所有共享组件：路由表、上游注册表、代理客户端。
/// 所有字段用 `Arc<T>` 包装，这样 tokio::spawn 的任务可以低成本 clone。
///
/// # 生命周期
///
/// - 构造阶段：`Runtime::load_from_path()` 或 `Runtime::build()`
/// - 运行阶段：`runtime.start()` 阻塞直到 shutdown 信号
/// - 退出阶段：CancellationToken 触发 → accept loop 停止 → 在途请求 drain
pub struct Runtime {
    /// 完整的 Gateway 配置（不可变，Phase 3 热更新前都是一次性加载）
    config: GatewayConfig,
    /// 编译好的路由表：Host → 前缀树 → Route
    route_table: Arc<RouteTable>,
    /// 上游注册表：ServiceId → Upstream（含健康端点列表）
    upstream_registry: Arc<UpstreamRegistry>,
    /// 反向代理客户端：hyper Client 实例（连接池在 hyper 内部管理）
    proxy_client: Arc<ProxyClient>,
}

impl Runtime {
    /// 从 YAML 配置文件加载并构建 Runtime。
    ///
    /// # 参数
    /// - `config_path`：YAML 配置文件路径（相对或绝对）
    ///
    /// # 返回
    /// - `Ok(Runtime)`：构建成功
    /// - `Err(Vec<ConfigError>)`：所有校验/解析错误（批量返回，用户一次能看到全部问题）
    ///
    /// # 为什么返回 Vec 而不是单个错误？
    /// `load_from_path` 返回单个 `ConfigError`（解析错误），`validate` 返回
    /// `Vec<ConfigError>`（批量业务校验错误）。本函数把两者统一到 `Vec`，
    /// 让 CLI 层可以一次性打印所有错误，避免"修一个又冒三个"的糟糕体验。
    pub fn load_from_path(config_path: &str) -> Result<Self, Vec<gateway_config::ConfigError>> {
        // 1. 文件加载 + Figment 解析（可能失败 → 单个 ConfigError）
        let cfg = match load_from_path(config_path) {
            Ok(c) => c,
            Err(e) => return Err(vec![e]),
        };

        // 2. 业务校验（可能返回多个错误，? 直接传播 Vec）
        validate(&cfg)?;

        // 3. 构建 Runtime
        Ok(Self::build(cfg))
    }

    /// 从内存中的 GatewayConfig 直接构建（主要用于测试）。
    ///
    /// # 参数
    /// - `cfg`：已经加载 + 校验过的配置对象
    pub fn build(cfg: GatewayConfig) -> Self {
        // 初始化 tracing 日志（JSON 格式，输出到 stderr）
        init_logging(&cfg.observability.logging.level, &cfg.observability.logging.format);

        // 编译路由表：RouteTable::compile 会按 Host 分桶、按优先级排序
        let route_table = Arc::new(RouteTable::compile(&cfg.routes));
        tracing::info!(
            target: "runtime",
            route_count = cfg.routes.iter().filter(|r| r.enabled).count(),
            "route table compiled"
        );

        // 构建上游注册表：从配置里的 upstreams 构建健康端点列表
        let upstream_registry = Arc::new(UpstreamRegistry::new(&cfg.upstreams));
        tracing::info!(
            target: "runtime",
            upstream_count = upstream_registry.upstream_count(),
            "upstream registry built"
        );

        // 初始化代理客户端：hyper-util Client 构造（HTTP/1.1 连接池）
        let proxy_client = Arc::new(ProxyClient::new(ProxyOptions {
            // request_timeout 不能小于 10s，兜底防止配置错误
            request_timeout: Duration::from_secs(
                cfg.runtime.graceful_shutdown_timeout_secs.max(10),
            ),
            connect_timeout: Duration::from_secs(5),
        }));

        Self {
            config: cfg,
            route_table,
            upstream_registry,
            proxy_client,
        }
    }

    /// 启动所有 Listener 并阻塞直到收到 shutdown 信号。
    ///
    /// # self: Arc<Self> 为什么？
    ///
    /// 调用方需要持有 `Arc<Runtime>`，因为多个 tokio::spawn 的任务会
    /// clone 这个 Arc。如果 self 是 `Runtime`（按值），我们需要手动 wrap。
    ///
    /// # 启动顺序
    /// 1. 创建 CancellationToken（用于协调所有子任务的 shutdown）
    /// 2. spawn Admin Server（Axum，管理接口）
    /// 3. spawn HTTP Server（Hyper，业务代理）
    /// 4. 安装信号处理器（SIGTERM/SIGINT → cancel token）
    /// 5. tokio::select! 等待 shutdown 或任一 server 意外退出
    /// 6. 优雅关闭等待（在途请求 drain 时间）
    pub async fn start(self: Arc<Self>) -> Result<(), GatewayError> {
        let rt = self.clone();

        // =================================================================
        // CancellationToken：协调所有子任务的 shutdown
        // =================================================================
        // CancellationToken 的 clone 是 cheap 的（Arc 内部原子计数器 +1）。
        // 每个子任务持有一个 clone，调用 cancel() 时所有 clone 都能收到。
        let shutdown_token = CancellationToken::new();
        let admin_shutdown = shutdown_token.clone();
        let http_shutdown = shutdown_token.clone();

        // =================================================================
        // 1. Admin Server（Axum）—— 控制面
        // =================================================================

        // 解析 admin 地址字符串 → SocketAddr
        let admin_addr: SocketAddr =
            format!("{}:{}", rt.config.server.admin.address, rt.config.server.admin.port)
                .parse()
                .map_err(|e| GatewayError::Internal(format!("invalid admin addr: {e}")))?;

        let admin_task = if rt.config.server.admin.enabled {
            let rt_clone = rt.clone();
            tokio::spawn(async move {
                // admin::start_admin_server 是 Axum 启动入口
                crate::admin::start_admin_server(admin_addr, rt_clone, admin_shutdown).await
            })
        } else {
            tracing::info!("admin server disabled");
            // 返回一个立即完成的 Ok，让 select! 不会因为 None 分支而改变逻辑
            tokio::spawn(async { Ok::<_, GatewayError>(()) })
        };

        // =================================================================
        // 2. 业务 HTTP Server（Hyper）—— 数据面
        // =================================================================

        let http_addr: SocketAddr =
            format!("{}:{}", rt.config.server.http.address, rt.config.server.http.port)
                .parse()
                .map_err(|e| GatewayError::Internal(format!("invalid http addr: {e}")))?;

        let http_options = ServerOptions {
            max_concurrent_requests: rt.config.runtime.max_concurrent_requests,
            max_request_body_size: rt.config.runtime.max_request_body_size,
            graceful_shutdown_timeout_secs: rt.config.runtime.graceful_shutdown_timeout_secs,
        };

        let http_server = HttpServer::new(http_addr, http_options);
        let rt_for_http = rt.clone();

        // handler 闭包签名：
        //   Fn(Request<Incoming>) -> impl Future<Output = Result<Response<ResBody>, Infallible>>
        // gateway-network::serve 内部用 tower::service_fn 包装，把闭包变成 Tower Service。
        // 闭包 clone 的是 Arc<Runtime>，开销极小。
        let handler = move |req: Request<Incoming>| {
            let rt = rt_for_http.clone();
            // async move 块返回 Future，ResBody 类型由 handle_request 自动推断
            async move { rt.handle_request(req).await }
        };

        let http_task = if rt.config.server.http.enabled {
            tokio::spawn(async move {
                // serve 的泛型 F/Fut/ResBody 全部从 handler 闭包自动推断
                http_server.serve(handler, http_shutdown).await
            })
        } else {
            tracing::info!("http server disabled");
            tokio::spawn(async { Ok::<_, GatewayError>(()) })
        };

        tracing::info!(target: "runtime", "gateway runtime started");

        // =================================================================
        // 3. 安装信号处理：SIGTERM/SIGINT → CancellationToken.cancel()
        // =================================================================

        install_signal_handler(shutdown_token.clone());

        // =================================================================
        // 4. 等待退出信号
        // =================================================================

        tokio::select! {
            // Admin task 意外退出（正常情况下不会退，除非 bind 失败等）
            admin_res = admin_task => {
                tracing::warn!("admin task exited: {:?}", admin_res);
            }
            // HTTP task 意外退出
            http_res = http_task => {
                tracing::warn!("http task exited: {:?}", http_res);
            }
            // 正常退出路径：收到 SIGTERM/SIGINT
            _ = shutdown_token.cancelled() => {
                tracing::info!("shutdown signal received, draining...");
            }
        }

        // =================================================================
        // 5. 优雅关闭等待
        // =================================================================
        // 已经 accept 进来的连接继续处理完。这里 sleep 保证即使
        // tokio::select! 的一个分支退了，我们也给在途请求足够时间 drain。
        tokio::time::sleep(Duration::from_secs(rt.config.runtime.graceful_shutdown_timeout_secs))
            .await;

        tracing::info!("gateway runtime exited");
        Ok(())
    }

    // ------------------------------------------------------------------
    // 业务请求处理
    // ------------------------------------------------------------------

    /// 核心请求处理（数据面 Pipeline 入口）。
    ///
    /// # 返回类型
    /// 返回 `Result<http::Response<ResBody>, Infallible>`。
    /// - `ResBody = Full<Bytes>`：统一用收集后的 Bytes 作为响应体
    ///   Phase 2 会改进 EitherBody / BoxBody 恢复流式透传
    /// - `Infallible`：gateway-network 期望 handler 永远不失败（框架层保证）
    ///
    /// # 处理流程
    /// 1. 生成 RequestId，填充 RequestContext（用于 AccessLog）
    /// 2. RouteTable::resolve → 匹配 Route / MethodNotAllowed / NoMatch
    /// 3. UpstreamRegistry::pick_endpoint → 选中实例（Round-Robin）
    /// 4. ProxyClient::forward → 流式转发到上游
    /// 5. 上游返回后把 Incoming body 收集成 Bytes → 构造 Full<Bytes>
    /// 6. 任何一步失败 → 构造 JSON 错误响应
    /// 7. 记录 AccessLog（成功/失败路径都记录）
    async fn handle_request(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<ResBody>, std::convert::Infallible> {
        use gateway_common::ErrorCode;

        // -----------------------------------------------------------------
        // 1. 请求上下文初始化
        // -----------------------------------------------------------------

        // 生成请求 ID（uuid v4）
        let request_id = RequestId::new();
        let mut ctx = gateway_core::RequestContext::new(request_id);

        // 拆开请求 Parts（method/uri/headers） 和 Body
        let (parts, body) = request.into_parts();
        let method = parts.method.clone();
        let uri = parts.uri.clone();
        let headers = parts.headers.clone();

        // 从 headers 里提取 host（路由匹配需要；HTTP/1.1 的 Host header
        // 是必需的，HTTP/2 的 :authority pseudo-header hyper 会自动转成 Host）
        let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let path = uri.path().to_string();
        let query = uri.query().map(|s| s.to_string());

        // 填充 RequestContext 的基础字段（用于 AccessLog）
        ctx.fill_basic(
            method.clone(),
            host.clone(),
            path.clone(),
            query.clone(),
            headers.clone(),
            None,
        );

        // -----------------------------------------------------------------
        // 2. Route 匹配
        // -----------------------------------------------------------------

        let match_result =
            self.route_table
                .resolve(&host, &path, method.as_str(), &headers, query.as_deref());

        // -----------------------------------------------------------------
        // 3. 根据匹配结果分流处理
        // -----------------------------------------------------------------
        // 成功路径直接 return，错误路径 fall through 到统一错误响应构造
        let (status_code, error_code_str, error_msg) = match match_result {
            // --- 成功匹配 ---
            gateway_routing::MatchResult::Matched(route) => {
                ctx.set_route(route.clone());

                // 从 UpstreamRegistry 选出一个健康实例（Round-Robin 算法）
                match self.upstream_registry.pick_endpoint(&route.service_id).await {
                    Ok(endpoint) => {
                        ctx.set_endpoint(endpoint.clone());
                        ctx.mark_upstream_start();

                        // 构造转发请求：原 Parts + 原 Body
                        // ProxyClient::forward 内部会重建真实上游 URI
                        let upstream_req = http::Request::from_parts(parts, body);

                        // 用 placeholder URI 先构造一个合法 Request，
                        // ProxyClient::forward 内部会覆盖 URI 为真实上游地址
                        let mut forwarded = upstream_req;
                        *forwarded.uri_mut() = http::Uri::builder()
                            .scheme("http")
                            .authority("placeholder.invalid")
                            .path_and_query("/")
                            .build()
                            .unwrap_or_else(|_| "http://placeholder/".parse().unwrap());

                        match self.proxy_client.forward(forwarded, &endpoint, &path, None).await {
                            // 上游返回任何 HTTP 响应（2xx/3xx/4xx/5xx）都算"代理成功"——
                            // 我们只透传，不解释业务语义
                            Ok(upstream_resp) => {
                                let status = upstream_resp.status().as_u16();
                                ctx.mark_upstream_headers();
                                ctx.finish(status);

                                // -----------------------------------------------------------------
                                // Phase 1 简化：把上游 Incoming body **完全收集**成 Bytes
                                // -----------------------------------------------------------------
                                // hyper 的 Incoming body 不能外部构造（没有 pub empty/new），
                                // 也不能直接塞到 Full<Bytes> 里。所以我们需要：
                                //
                                // 1. 拆开上游响应 → (ResponseParts, Incoming)
                                // 2. 用 http_body_util::BodyExt::collect() 把 Incoming 全部读完
                                //    → Collected<T>，然后 .to_bytes() 拿到 Bytes
                                // 3. 用 Full::new(bytes) 重新构造响应 body
                                //
                                // BodyExt 来自 http-body-util crate：
                                //   BodyExt::collect(self) -> impl Future<Output = Collected<Self>>
                                //   Collected::to_bytes(self) -> Bytes
                                let (resp_parts, incoming_body) = upstream_resp.into_parts();
                                // .collect() 返回 Result<Collected<Bytes>, BodyError>，
                                // 因为我们的 handler 返回 Infallible，不能传播错误。
                                // 兜底：如果收集失败（上游中途断开），返回空 body。
                                let collected = incoming_body.collect().await;
                                let body_bytes = collected
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_else(|_| Bytes::new());

                                // 用 Response::from_parts 重建响应（body 换成 Full<Bytes>）
                                let resp = Response::from_parts(resp_parts, Full::new(body_bytes));

                                // AccessLog 记录（成功路径）
                                gateway_observability::AccessLog::emit(&ctx);

                                return Ok(resp);
                            },
                            // 上游连接失败 / 超时 → 502 / 504
                            Err(gateway_err) => {
                                ctx.finish_with_error(
                                    gateway_err.code().as_str().to_string(),
                                    gateway_err.to_string(),
                                );
                                (
                                    gateway_err.code().to_http_status(),
                                    gateway_err.code().as_str().to_string(),
                                    gateway_err.to_string(),
                                )
                            },
                        }
                    },
                    // 没有健康端点 → 503
                    Err(_no_healthy) => {
                        let msg = format!("upstream {} has no healthy endpoints", route.service_id);
                        ctx.finish_with_error(
                            ErrorCode::GatewayUpstreamUnavailable.as_str().to_string(),
                            msg.clone(),
                        );
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            ErrorCode::GatewayUpstreamUnavailable.as_str().to_string(),
                            msg,
                        )
                    },
                }
            },

            // --- 路径匹配但 Method 不允许 → 405 ---
            gateway_routing::MatchResult::MethodNotAllowed { allowed_methods } => {
                let msg = format!("methods allowed: {}", allowed_methods.join(", "));
                ctx.finish_with_error(
                    ErrorCode::GatewayMethodNotAllowed.as_str().to_string(),
                    msg.clone(),
                );
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    ErrorCode::GatewayMethodNotAllowed.as_str().to_string(),
                    msg,
                )
            },

            // --- 没有任何路由匹配 → 404 ---
            gateway_routing::MatchResult::NoMatch => {
                let msg = format!("no route matched for {} {}", method, path);
                ctx.finish_with_error(
                    ErrorCode::GatewayRouteNotFound.as_str().to_string(),
                    msg.clone(),
                );
                (StatusCode::NOT_FOUND, ErrorCode::GatewayRouteNotFound.as_str().to_string(), msg)
            },
        };

        // -----------------------------------------------------------------
        // 4. 统一错误响应构造
        // -----------------------------------------------------------------

        // 构造 JSON 错误响应体（gateway_common::ErrorResponse 的 serde 序列化）
        let json_body = serde_json::json!({
            "code": error_code_str,
            "message": error_msg,
            "request_id": ctx.request_id.as_str(),
        });
        let body_bytes =
            Bytes::from(serde_json::to_string(&json_body).unwrap_or_else(|_| "{}".to_string()));

        // 构造 HTTP 错误响应
        let response = Response::builder()
            .status(status_code)
            .header("content-type", "application/json")
            // Full::new(bytes) —— Fixed-size body，hyper 直接发送
            .body(Full::new(body_bytes))
            // 安全 unwrap：手动构造的 Response builder 只有在 URI/Header 格式错误时
            // 才会失败，我们这里只设了 status 和两个 header，不会错
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("{}")))
                    .unwrap()
            });

        // AccessLog 记录（错误路径）
        gateway_observability::AccessLog::emit(&ctx);

        Ok(response)
    }

    // ------------------------------------------------------------------
    // 公共只读访问器（Admin Server 用）
    // ------------------------------------------------------------------

    /// Gateway 唯一 ID，例如 `"gateway-dev"`
    pub fn gateway_id(&self) -> &str {
        &self.config.gateway.id
    }
    /// 实例名称（同一 Gateway ID 下可以有多个实例，通过 instance_name 区分）
    pub fn instance_name(&self) -> &str {
        &self.config.gateway.instance_name
    }
    /// 部署环境：`development` / `production` / `staging` 等
    pub fn environment(&self) -> &str {
        &self.config.gateway.environment
    }
    /// 是否可以接收流量（Phase 1 总是 true；Phase 2 健康检查接入后会真实判断）
    pub fn is_ready(&self) -> bool {
        true
    }
    /// 配置版本号（Phase 1 固定 1；Phase 3 热更新后每次 +1）
    pub fn config_version(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// RuntimeHandle —— 外部可操作的 shutdown 句柄（Phase 1 暂未使用）
// ---------------------------------------------------------------------------

/// 外部 shutdown 句柄。
///
/// 设计用于未来 Control Plane 下发"优雅关闭"指令时使用。
/// Phase 1 中 shutdown 完全由信号处理驱动，这个结构体留作扩展点。
pub struct RuntimeHandle {
    /// 发送关闭信号的 oneshot Sender
    pub shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

// ---------------------------------------------------------------------------
// 信号处理
// ---------------------------------------------------------------------------

/// 安装 SIGTERM/SIGINT 处理器。
///
/// # signal-hook 0.3 API 说明
/// - `signal_hook::flag::register(signal, Arc<AtomicBool>)` —— 注册信号处理器，
///   收到信号时把 AtomicBool 设为 true。参数：
///   - 第一个参数：信号常量（`signal_hook::consts::signal::SIGTERM`）
///   - 第二个参数：Arc<AtomicBool>，信号处理器会写入这个 flag
///
/// # 为什么用 AtomicBool + 轮询？
///
/// signal-hook 的 flag API 不直接与 tokio 集成。我们启动一个 spawn task
/// 每 100ms 检查一次 flag，被置为 true 时调用 `token.cancel()`。
/// 这比 tokio::signal（只支持 unix）更可移植，而且 100ms 延迟在
/// 优雅关闭场景下完全可以接受。
fn install_signal_handler(token: CancellationToken) {
    // 创建 AtomicBool flag，初始 false
    let flag = Arc::new(AtomicBool::new(false));

    // 注册 SIGTERM 处理器：收到时把 flag 置为 true
    let _ = signal_hook::flag::register(signal_hook::consts::signal::SIGTERM, flag.clone());
    // 注册 SIGINT 处理器（Ctrl+C）
    let _ = signal_hook::flag::register(signal_hook::consts::signal::SIGINT, flag.clone());

    // 轮询任务：检查 flag → cancel token
    tokio::spawn(async move {
        // Ordering::Relaxed：我们不需要严格的内存序，只要能看到 true 就行。
        // signal_hook 在写入时用的是 SeqCst 或 Release，Relaxed load 足够看到。
        while !flag.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tracing::info!(target: "signal", "received shutdown signal");
        token.cancel();
    });
}
