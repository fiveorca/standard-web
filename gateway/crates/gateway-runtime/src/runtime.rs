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
use gateway_config::{load_from_path, validate, CompiledSnapshot, GatewayConfig};
use gateway_core::UpstreamManager;
use gateway_network::{HttpServer, ServerOptions};
use gateway_observability::init_logging;
use gateway_plugin::{PluginContext, PluginDecision, PluginPhase, PluginResponse};
use gateway_proxy::{ProxyClient, ProxyOptions};

use http::header::HeaderValue;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use tokio::sync::{oneshot, Mutex};
use tokio_util::sync::CancellationToken;

use crate::body::{self, boxed, ResBody};
use crate::state::{SnapshotApplyError, SnapshotStore, INITIAL_CONFIG_VERSION};

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
    /// 完整的 Gateway 配置。
    ///
    /// 只保存与"运行时环境"相关的部分（server/runtime/observability/gateway
    /// 元信息）；可变资源（routes/services/upstreams/policies）在
    /// [`SnapshotStore`] 中以快照形式保存，支持热更新。
    config: GatewayConfig,
    /// 配置快照存储：路由表 / 上游注册表 / Service→Upstream 映射
    snapshots: Arc<SnapshotStore>,
    /// 反向代理客户端：hyper Client 实例（连接池在 hyper 内部管理）
    proxy_client: Arc<ProxyClient>,
    /// Bulkhead 并发限制信号量。超过 max_concurrent_requests
    /// 时 try_acquire_owned() 失败，handle_request 立即返回 503，不阻塞排队。
    /// permit 在请求处理完成（函数返回）时自动 drop 释放。
    bulkhead: Arc<tokio::sync::Semaphore>,
    /// 最大请求体大小（字节）。Content-Length 超过此值时返回 413。
    /// Chunked transfer-encoding（无 Content-Length）场景下无法提前拦截。
    max_body_size: u64,
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
        Self::build(cfg)
    }

    /// 从内存中的 GatewayConfig 直接构建（主要用于测试）。
    ///
    /// # 参数
    /// - `cfg`：已经加载 + 校验过的配置对象
    ///
    /// # 返回
    /// - `Ok(Runtime)`：构建成功
    /// - `Err(Vec<ConfigError>)`：快照编译失败（当前只可能是 checksum 序列化错误）
    pub fn build(cfg: GatewayConfig) -> Result<Self, Vec<gateway_config::ConfigError>> {
        // 初始化 tracing 日志（JSON 格式，输出到 stderr）
        init_logging(&cfg.observability.logging.level, &cfg.observability.logging.format);

        // 构建初始配置快照：编译路由表 + 上游注册表 + Service 映射，
        // 后续热更新通过 SnapshotStore::apply 原子替换。
        //
        // 控制面模式下本地 YAML 只是引导配置，版本号置 0，避免与控制面
        // 的版本空间（从 1 开始）冲突导致首个快照被判为 stale。
        let initial_version = if cfg.control_plane.enabled {
            0
        } else {
            INITIAL_CONFIG_VERSION
        };
        let snapshots = Arc::new(
            SnapshotStore::from_config_with_version(&cfg, initial_version)
                .map_err(|e| vec![e])?,
        );
        tracing::info!(
            target: "runtime",
            route_count = cfg.routes.iter().filter(|r| r.enabled).count(),
            "route table compiled"
        );

        // 初始化代理客户端：hyper-util Client 构造（HTTP/1.1 连接池）
        let proxy_client = Arc::new(ProxyClient::new(ProxyOptions {
            // request_timeout 不能小于 10s，兜底防止配置错误
            request_timeout: Duration::from_secs(
                cfg.runtime.graceful_shutdown_timeout_secs.max(10),
            ),
            connect_timeout: Duration::from_secs(5),
        }));

        // Bulkhead：用 RuntimeConfig.max_concurrent_requests 初始化
        // Semaphore 大小；Arc 让多线程（handle_request 被 hyper service_fn 调用）
        // 共享同一个限流槽位池
        let bulkhead = Arc::new(tokio::sync::Semaphore::new(
            cfg.runtime.max_concurrent_requests as usize,
        ));
        // 在 move cfg 到 Self 之前提前取出 max_body_size（避免 move 后再访问）
        let max_body_size = cfg.runtime.max_request_body_size;

        Ok(Self {
            config: cfg,
            snapshots,
            proxy_client,
            bulkhead,
            max_body_size,
        })
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
        self.start_with_admin(None).await
    }

    /// 启动所有 Listener，并把额外的管理路由挂载到 Admin 端口。
    ///
    /// `extra_admin` 用于 integrated 模式：`apps/gateway` 构建控制面
    /// Admin API（`/api/admin/v1`）后通过本参数挂载，实现同一个进程内
    /// "控制面写入 → 数据面热更新"。独立部署时传 `None`。
    pub async fn start_with_admin(
        self: Arc<Self>,
        extra_admin: Option<axum::Router>,
    ) -> Result<(), GatewayError> {
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
                // admin::start_admin_server 是 Axum 启动入口；
                // extra_admin 为控制面路由（integrated 模式）
                crate::admin::start_admin_server(
                    admin_addr,
                    rt_clone,
                    admin_shutdown,
                    extra_admin,
                )
                .await
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
        // 2.5 动态服务发现后台任务（Phase 6）
        // =================================================================
        // 对配置了 upstreams[].discovery 的上游定期刷新端点。
        // 未配置 discovery 时该任务只做空转 tick，开销可忽略。
        crate::discovery::spawn(rt.snapshots.clone());

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
    /// - `ResBody = BoxBody<Bytes, BoxError>`（P2.0 起）：
    ///   成功路径是上游 `Incoming` 的流式透传（零拷贝），
    ///   错误路径是内存构造的 `Full<Bytes>` JSON，两者统一类型擦除
    /// - `Infallible`：gateway-network 期望 handler 永远不失败（框架层保证）
    ///
    /// # 处理流程
    /// 1. 生成 RequestId，填充 RequestContext（用于 AccessLog）
    /// 2. RouteTable::resolve → 匹配 Route / MethodNotAllowed / NoMatch
    /// 3. UpstreamRegistry::pick_endpoint → 选中实例（Round-Robin）
    /// 4. ProxyClient::forward → 流式转发到上游
    /// 5. 上游响应 Incoming body 经 `body::boxed()` 类型擦除后直接透传
    /// 6. 任何一步失败 → `body::error_response()` 构造 JSON 错误响应
    /// 7. 统一经 `body::observe()` 包装：AccessLog 在 body 流结束/断开时输出，
    ///    保证 request_duration_ms 统计的是完整流式传输时间
    async fn handle_request(
        &self,
        mut request: Request<Incoming>,
    ) -> Result<Response<ResBody>, std::convert::Infallible> {
        use gateway_common::ErrorCode;

        // WebSocket / HTTP Upgrade：在 request 被拆解前取出客户端侧升级句柄。
        // 普通请求不会触发升级，OnUpgrade 在函数结束时自动丢弃。
        let client_on_upgrade = hyper::upgrade::on(&mut request);

        // -----------------------------------------------------------------
        // 1. 请求上下文初始化
        // -----------------------------------------------------------------

        // 生成请求 ID（uuid v4）
        let request_id = RequestId::new();
        let mut ctx = gateway_core::RequestContext::new(request_id);

        // -----------------------------------------------------------------
        // Bulkhead + 请求体大小限制（业务层入口限流 + 安全拦截）
        // -----------------------------------------------------------------
        // 在拆 parts/body 之前先做两类检查：
        // 1. Bulkhead try_acquire_owned——并发槽位耗尽立即 503，不阻塞
        // 2. Content-Length 超过 max_body_size 立即 413——超大体量请求在 header
        //    层面就被拦截，Incoming body 不进入后续插件链/路由匹配
        // permit 被 move 到函数作用域末尾 drop——请求处理完自动释放槽位
        //
        // 为什么在拆 parts 之前做？因为 Content-Length 在 Request 上可见，
        // Request 本身不需要拆 parts 就能拿到 headers
        let _bulkhead_permit = match self.bulkhead.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_sem_err) => {
                // 超过并发上限 → 立即 503，不排队
                tracing::warn!(
                    target: "runtime",
                    request_id = %ctx.request_id,
                    "bulkhead reject: max concurrent requests reached"
                );
                ctx.finish_with_error(
                    ErrorCode::GatewayResourceExhausted.as_str().to_string(),
                    "server overloaded".to_string(),
                );
                let resp = body::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::GatewayResourceExhausted.as_str(),
                    "server overloaded (bulkhead full)",
                    ctx.request_id.as_str(),
                );
                return Ok(resp);
            },
        };

        // max_request_body_size：Content-Length 头超过限制 → 413
        // Chunked transfer-encoding（无 Content-Length）无法提前拦截，
        // 留给下游 Incoming body 实际读取时（暂未实现流式限流）
        if let Some(cl) = request.headers().get("content-length") {
            if let Some(len) = cl.to_str().ok().and_then(|s| s.parse::<u64>().ok()) {
                if len > self.max_body_size {
                    tracing::warn!(
                        target: "runtime",
                        request_id = %ctx.request_id,
                        content_length = len,
                        max_allowed = self.max_body_size,
                        "request body exceeds size limit"
                    );
                    ctx.finish_with_error(
                        ErrorCode::GatewayRequestTooLarge.as_str().to_string(),
                        "request body exceeds max size limit".to_string(),
                    );
                    let resp = body::error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        ErrorCode::GatewayRequestTooLarge.as_str(),
                        &format!(
                            "request body size {} exceeds limit {}",
                            len, self.max_body_size
                        ),
                        ctx.request_id.as_str(),
                    );
                    return Ok(resp);
                }
            }
        }

        // 拆开请求 Parts（method/uri/headers/extensions） 和 Body
        // parts 必须是 mut：插件链会修改 headers（request_transform 注入代理链头等）
        let (mut parts, body) = request.into_parts();
        let method = parts.method.clone();
        let uri = parts.uri.clone();
        let headers = parts.headers.clone();

        // 从 request extensions 提取客户端对端地址。
        // gateway-network::serve 在 accept 连接后把 peer_addr（SocketAddr）
        // 注入 extensions；SocketAddr 实现了 Copy，copied() 直接取值。
        // 若注入缺失（如单元测试直接调用 handler），退化为 None。
        let client_ip = parts.extensions.get::<SocketAddr>().copied();

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
            client_ip,
        );

        // -----------------------------------------------------------------
        // 2. Route 匹配
        // -----------------------------------------------------------------

        // 每个请求只读取一次当前快照：后续路由/上游解析都基于同一份
        // `Arc<RuntimeState>`，即使并发热更新也不会出现撕裂读
        let state = self.snapshots.current();

        let match_result =
            state
                .route_table
                .resolve(&host, &path, method.as_str(), &headers, query.as_deref());

        // -----------------------------------------------------------------
        // 3. 根据匹配结果分流处理
        // -----------------------------------------------------------------
        // 成功路径直接 return，错误路径 fall through 到统一错误响应构造
        let (status_code, error_code_str, error_msg) = match match_result {
            // --- 成功匹配 ---
            gateway_routing::MatchResult::Matched(route) => {
                ctx.set_route(route.clone());

                // ============================================================
                // Phase 2 插件链（请求方向）
                // ============================================================
                // 设计文档 4.12：插件按阶段串行执行，短路立即返回。
                // 关键安全保证：认证阶段返回 ShortCircuit(401/403) 时，
                // 不会进入后续的 Service→Upstream→ProxyClient 路径——
                // 认证失败的请求绝对访问不到上游。

                // Stage 1: RequestPostRoute —— rate_limit（429 短路）+ cors_request（OPTIONS 预检 204/403/405）
                // 插件按 (priority, name) 升序执行；空链 run() 直接返回 Continue
                let mut pctx = PluginContext::new(
                    &mut parts,
                    &mut ctx,
                    Some(route.clone()),
                    None,
                );
                match state.chain(PluginPhase::RequestPostRoute).run(&mut pctx).await {
                    Ok(PluginDecision::Continue) => {},
                    Ok(PluginDecision::ShortCircuit(resp)) => {
                        // 插件短路：请求被拦截（如限流、OPTIONS 预检直接响应）
                        ctx.finish_with_error(
                            "GATEWAY_PLUGIN_SHORT_CIRCUIT".to_string(),
                            "request rejected by plugin".to_string(),
                        );
                        let short_circuit_code = resp.status.as_u16();
                        let final_resp = plugin_response_to_response(resp);
                        ctx.status_code = Some(short_circuit_code);
                        return Ok(body::observe(final_resp, ctx));
                    },
                    Err(plugin_err) => {
                        // 插件内部故障 → fail closed → 500
                        tracing::error!(target: "plugin", error = %plugin_err, "plugin error in request_post_route");
                        let final_resp = plugin_error_to_response(
                            plugin_err,
                            ctx.request_id.as_str(),
                        );
                        ctx.status_code = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                        return Ok(body::observe(final_resp, ctx));
                    },
                }
                // pctx 在此块结束时 Drop，parts/ctx 的可变借用释放，
                // 下一个阶段可以重新构造 PluginContext 继续使用

                // Stage 2: Authentication —— auth（JWT/API Key/Basic/IP 过滤 → 401/403 短路）
                let mut pctx = PluginContext::new(
                    &mut parts,
                    &mut ctx,
                    Some(route.clone()),
                    None,
                );
                match state.chain(PluginPhase::Authentication).run(&mut pctx).await {
                    Ok(PluginDecision::Continue) => {},
                    Ok(PluginDecision::ShortCircuit(resp)) => {
                        // 认证失败短路：核心安全保证——不允许认证失败的请求访问上游
                        ctx.finish_with_error(
                            "GATEWAY_AUTHENTICATION_FAILED".to_string(),
                            "authentication denied".to_string(),
                        );
                        let short_circuit_code = resp.status.as_u16();
                        let final_resp = plugin_response_to_response(resp);
                        ctx.status_code = Some(short_circuit_code);
                        return Ok(body::observe(final_resp, ctx));
                    },
                    Err(plugin_err) => {
                        tracing::error!(target: "plugin", error = %plugin_err, "plugin error in authentication");
                        let final_resp = plugin_error_to_response(
                            plugin_err,
                            ctx.request_id.as_str(),
                        );
                        ctx.status_code = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                        return Ok(body::observe(final_resp, ctx));
                    },
                }

                // Stage 3: RequestPreUpstream —— request_transform（改写 headers）+ circuit_breaker_guard（熔断拦截）
                let mut pctx = PluginContext::new(
                    &mut parts,
                    &mut ctx,
                    Some(route.clone()),
                    None,
                );
                match state.chain(PluginPhase::RequestPreUpstream).run(&mut pctx).await {
                    Ok(PluginDecision::Continue) => {},
                    Ok(PluginDecision::ShortCircuit(resp)) => {
                        ctx.finish_with_error(
                            "GATEWAY_PLUGIN_SHORT_CIRCUIT".to_string(),
                            "request rejected by plugin before upstream".to_string(),
                        );
                        let short_circuit_code = resp.status.as_u16();
                        let final_resp = plugin_response_to_response(resp);
                        ctx.status_code = Some(short_circuit_code);
                        return Ok(body::observe(final_resp, ctx));
                    },
                    Err(plugin_err) => {
                        tracing::error!(target: "plugin", error = %plugin_err, "plugin error in request_pre_upstream");
                        let final_resp = plugin_error_to_response(
                            plugin_err,
                            ctx.request_id.as_str(),
                        );
                        ctx.status_code = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                        return Ok(body::observe(final_resp, ctx));
                    },
                }

                // ============================================================
                // 继续：选上游 + 转发（原有逻辑）
                // ============================================================
                // 到这里 parts 可能已被 request_transform 改写（加了/改了请求头），
                // ctx 可能已被 auth 插件写入 identity。后续 ProxyClient 会
                // 使用这个被修改过的 parts，保证插件链的改动真实生效。
                // 灰度 / 蓝绿 / 加权路由：按 traffic_split 权重选择目标 Service，
                // 未配置时退化为 route.service_id
                let effective_service_id = select_service_target(&route);
                let upstream_id = state.service_upstreams.get(&effective_service_id).cloned();

                match upstream_id {
                    // Service → Upstream 映射缺失（配置内部错误）→ 500
                    None => {
                        let msg = format!(
                            "service '{}' has no upstream mapping (config bug)",
                            effective_service_id
                        );
                        ctx.finish_with_error(
                            ErrorCode::GatewayInternalError.as_str().to_string(),
                            msg.clone(),
                        );
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            ErrorCode::GatewayInternalError.as_str().to_string(),
                            msg,
                        )
                    },
                    Some(upstream_id) => {
                        // =================================================================
                        // Retry 策略预处理（幂等方法 + retry_policy_id）
                        // =================================================================
                        // Retry 安全边界：
                        // - 只做 "endpoint selection 层" 的重试（pick_endpoint 失败时
                        //   换健康实例重试）——Incoming body 不可重播，forward 失败后
                        //   不能安全重试（设计文档 4.6："不允许不安全重试"）
                        // - 非幂等方法也不允许重试（即使 endpoint selection 层）
                        // - retry policy 只在 max_attempts > 1 时启用，默认 1
                        let method_upper = parts.method.as_str().to_ascii_uppercase();
                        let is_idempotent = matches!(method_upper.as_str(), "GET" | "HEAD" | "PUT" | "DELETE");
                        let retry_policy = route
                            .retry_policy_id
                            .as_deref()
                            .and_then(|id| state.retries.get(id))
                            .filter(|p| p.enabled && is_idempotent);
                        let max_attempts = retry_policy.map(|p| p.max_attempts.max(1)).unwrap_or(1);

                        // 计算 per-request 超时（从 Route → state.timeouts 查）
                        let per_timeout = route
                            .timeout_policy_id
                            .as_deref()
                            .and_then(|id| state.timeouts.get(id).copied());

                        // 在任何 move 之前 clone 一份 parts 给响应方向插件用
                        // （响应方向插件如 cors_response 要读 Origin 请求头）
                        let mut parts_for_response = parts.clone();

                        // =================================================================
                        // X-Request-Id 注入（Phase 2 核心——请求 ID 透传到上游）
                        // =================================================================
                        // 设计文档 4.10：网关生成的 request_id 必须透传到上游，
                        // 让后端可以在日志 / trace 里关联请求。
                        // - 如果 parts 里已经有 X-Request-Id（客户端自己传的），保留原值
                        // - 没有则注入网关生成的 ctx.request_id
                        // - 同时注入 X-Request-ID（大写，有些上游规范用这个）
                        if !parts.headers.contains_key("x-request-id") {
                            // HeaderValue::from_str 不允许 NUL/CRLF；网关生成的
                            // request_id 是 UUID（无特殊字符），理论上不会失败。
                            // 用 match 代替 expect 保证无 unwrap。
                            if let Ok(rv) = HeaderValue::from_str(ctx.request_id.as_str()) {
                                parts.headers.insert("x-request-id", rv.clone());
                                parts.headers.insert("X-Request-Id", rv);
                            } else {
                                tracing::warn!(
                                    target: "runtime",
                                    request_id = %ctx.request_id,
                                    "generated request_id failed HeaderValue conversion (unexpected)"
                                );
                            }
                        }

                        // =================================================================
                        // Pick Endpoint Retry Loop + Forward
                        // =================================================================
                        // 会话键：优先 X-Client-Zone（区域感知），
                        // 否则退化为客户端 IP（IP Hash / 一致性哈希）。
                        let session_key: Option<String> = parts
                            .headers
                            .get("x-client-zone")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                            .or_else(|| client_ip.map(|ip| ip.to_string()));

                        let mut endpoint: Option<gateway_core::Endpoint> = None;

                        // 重试选 endpoint：第一次选不到健康实例时，按 retry policy
                        // 退避等待后再选（最多 max_attempts 次）
                        for attempt in 1..=max_attempts {
                            match state
                                .upstream_registry
                                .pick_endpoint_with_key(&upstream_id, session_key.as_deref())
                                .await
                            {
                                Ok(ep) => {
                                    endpoint = Some(ep);
                                    break;
                                },
                                Err(_pick_err) => {
                                    // 还有 retry 机会 → 退避等待后重选
                                    if attempt < max_attempts {
                                        let delay = retry_policy
                                            .map(|p| p.retry_delay(attempt))
                                            .unwrap_or(std::time::Duration::ZERO);
                                        tracing::warn!(
                                            target: "runtime",
                                            retry_attempt = attempt,
                                            retry_max = max_attempts,
                                            retry_backoff_ms = delay.as_millis() as u64,
                                            upstream_id = %upstream_id,
                                            "endpoint not available, retrying"
                                        );
                                        tokio::time::sleep(delay).await;
                                        continue;
                                    }
                                    // 最后一次也选不到 → 直接走 503
                                    let msg = format!(
                                        "upstream {upstream_id} has no healthy endpoints (after {max_attempts} attempts)"
                                    );
                                    ctx.finish_with_error(
                                        ErrorCode::GatewayUpstreamUnavailable.as_str().to_string(),
                                        msg.clone(),
                                    );
                                    let status_code = StatusCode::SERVICE_UNAVAILABLE;
                                    let error_code_str =
                                        ErrorCode::GatewayUpstreamUnavailable.as_str().to_string();
                                    let error_msg = msg;
                                    ctx.status_code = Some(status_code.as_u16());
                                    let resp = body::error_response(
                                        status_code,
                                        &error_code_str,
                                        &error_msg,
                                        ctx.request_id.as_str(),
                                    );
                                    return Ok(body::observe(resp, ctx));
                                },
                            }
                        }

                        // 保证 endpoint 一定是 Some（如果是 None 说明 max_attempts=0 或逻辑 bug）
                        // 这种情况兜底 503，绝不能崩溃
                        let endpoint = match endpoint {
                            Some(ep) => ep,
                            None => {
                                tracing::error!(
                                    target: "runtime",
                                    "pick endpoint retry loop produced no endpoint (logic bug)"
                                );
                                let msg = format!(
                                    "upstream {upstream_id} has no healthy endpoints"
                                );
                                ctx.finish_with_error(
                                    ErrorCode::GatewayUpstreamUnavailable.as_str().to_string(),
                                    msg.clone(),
                                );
                                let resp = body::error_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    ErrorCode::GatewayUpstreamUnavailable.as_str(),
                                    &msg,
                                    ctx.request_id.as_str(),
                                );
                                return Ok(body::observe(resp, ctx));
                            }
                        };

                        ctx.set_endpoint(endpoint.clone());
                        ctx.mark_upstream_start();

                        // =================================================================
                        // 流量镜像（Phase 6）
                        // =================================================================
                        // 位置约束：必须在认证阶段之后、转发之前。认证失败的请求
                        // 已在更早阶段短路返回，不会走到这里，也就不会被镜像。
                        //
                        // 采样命中后：
                        //   1. 用 TeeBody 把请求体分叉（Bytes 克隆，不复制内存）
                        //   2. 主请求继续走原路径（此处改用 BoxBody 擦除客户端）
                        //   3. 影子请求在独立 task 中异步发送，失败只记日志
                        let mirror_shadow_service: Option<String> = route.mirror.as_ref().and_then(|m| {
                            if !crate::mirror::sampled(m.percentage) {
                                return None;
                            }
                            Some(m.service_id.clone())
                        });

                        // Least Connections：转发前占用端点，响应头返回后释放
                        state
                            .upstream_registry
                            .on_connection_start(&upstream_id, &endpoint.runtime_id);

                        let forward_result = if let Some(shadow_service_id) = mirror_shadow_service {
                            // ---- 有镜像：主/影子共享同一份 tee 出来的请求体 ----
                            let (main_body, shadow_body) = crate::mirror::tee(body);
                            let main_req = http::Request::from_parts(
                                parts,
                                crate::mirror::boxed_tee(main_body),
                            );
                            // 影子请求使用与主请求相同的 parts（认证后的最终请求头）
                            let shadow_req = http::Request::from_parts(
                                parts_for_response.clone(),
                                crate::mirror::boxed_channel(shadow_body),
                            );

                            let state_for_mirror = state.clone();
                            let proxy_for_mirror = self.proxy_client.clone();
                            let shadow_path = path.clone();
                            let request_id = ctx.request_id.to_string();
                            // 影子任务独立 spawn：镜像永远不阻塞主请求
                            tokio::spawn(async move {
                                match state_for_mirror
                                    .upstream_registry
                                    .pick_endpoint_with_key(&shadow_service_id, None)
                                    .await
                                {
                                    Ok(shadow_endpoint) => {
                                        crate::mirror::send_shadow(
                                            proxy_for_mirror,
                                            shadow_req,
                                            shadow_endpoint,
                                            shadow_path,
                                            client_ip,
                                            per_timeout,
                                            request_id,
                                        )
                                        .await;
                                    },
                                    Err(err) => {
                                        tracing::warn!(
                                            target: "mirror",
                                            request_id = %request_id,
                                            shadow_service = %shadow_service_id,
                                            error = %err,
                                            "mirror skipped: no shadow endpoint"
                                        );
                                    },
                                }
                            });

                            self.proxy_client
                                .forward_boxed(main_req, &endpoint, &path, client_ip, per_timeout)
                                .await
                        } else {
                            // ---- 无镜像：原路径，Incoming 直接流式透传 ----
                            let upstream_req = http::Request::from_parts(parts, body);
                            self.proxy_client
                                .forward(upstream_req, &endpoint, &path, client_ip, per_timeout)
                                .await
                        };

                        // 响应头/错误返回即释放占用（流式 body 继续传输不阻塞选择）
                        state
                            .upstream_registry
                            .on_connection_end(&upstream_id, &endpoint.runtime_id);

                        match forward_result
                        {
                                    // 上游返回任何 HTTP 响应（2xx/3xx/4xx/5xx）都算"代理成功"——
                                    // 我们只透传，不解释业务语义
                                    Ok(mut upstream_resp) => {
                                        ctx.mark_upstream_headers();

                                        // WebSocket / HTTP Upgrade：上游返回 101 时，
                                        // 把客户端与上游两条已升级的连接桥接起来，
                                        // 之后的双向帧透传由 copy_bidirectional 完成。
                                        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                                            let upstream_on_upgrade =
                                                hyper::upgrade::on(&mut upstream_resp);
                                            tokio::spawn(bridge_upgrade(client_on_upgrade, upstream_on_upgrade));
                                        }

                                        // 构造响应方向插件可见的 ResponseParts 视图
                                        // （status + headers 是可写副本；body 不暴露给插件，
                                        // 保持 Incoming 流式透传零拷贝）
                                        let mut response_parts = gateway_plugin::ResponseParts::new(
                                            upstream_resp.status(),
                                            upstream_resp.headers().clone(),
                                        );

                                        // Stage 4: UpstreamResponse —— circuit_breaker_record（熔断结果记账）
                                        // 此阶段插件只做"观测/记账"，理论上不应短路；
                                        // 若插件短路则直接返回短路响应（极端场景）
                                        {
                                            let mut pctx = PluginContext::new(
                                                &mut parts_for_response,
                                                &mut ctx,
                                                Some(route.clone()),
                                                Some(&mut response_parts),
                                            );
                                            match state
                                                .chain(PluginPhase::UpstreamResponse)
                                                .run(&mut pctx)
                                                .await
                                            {
                                                Ok(PluginDecision::Continue) => {},
                                                Ok(PluginDecision::ShortCircuit(resp)) => {
                                                    // 罕见：插件决定吞掉上游响应自己返回
                                                    let final_resp = plugin_response_to_response(resp);
                                                    ctx.status_code = Some(final_resp.status().as_u16());
                                                    return Ok(body::observe(final_resp, ctx));
                                                },
                                                Err(plugin_err) => {
                                                    tracing::error!(target: "plugin", error = %plugin_err, "plugin error in upstream_response");
                                                    let final_resp = plugin_error_to_response(
                                                        plugin_err,
                                                        ctx.request_id.as_str(),
                                                    );
                                                    ctx.status_code = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                                                    return Ok(body::observe(final_resp, ctx));
                                                },
                                            }
                                        }

                                        // Stage 5: ResponsePreClient —— response_transform（改写响应头）+ cors_response（追加 CORS 头）
                                        // 此阶段插件主要修改 response_parts.headers，例如：
                                        //   - response_transform：注入自定义响应头、删除敏感头
                                        //   - cors_response：追加 Access-Control-Allow-Origin / Allow-Credentials / Expose-Headers / Vary
                                        {
                                            let mut pctx = PluginContext::new(
                                                &mut parts_for_response,
                                                &mut ctx,
                                                Some(route.clone()),
                                                Some(&mut response_parts),
                                            );
                                            match state
                                                .chain(PluginPhase::ResponsePreClient)
                                                .run(&mut pctx)
                                                .await
                                            {
                                                Ok(PluginDecision::Continue) => {},
                                                Ok(PluginDecision::ShortCircuit(resp)) => {
                                                    let final_resp = plugin_response_to_response(resp);
                                                    ctx.status_code = Some(final_resp.status().as_u16());
                                                    return Ok(body::observe(final_resp, ctx));
                                                },
                                                Err(plugin_err) => {
                                                    tracing::error!(target: "plugin", error = %plugin_err, "plugin error in response_pre_client");
                                                    let final_resp = plugin_error_to_response(
                                                        plugin_err,
                                                        ctx.request_id.as_str(),
                                                    );
                                                    ctx.status_code = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                                                    return Ok(body::observe(final_resp, ctx));
                                                },
                                            }
                                        }

                                        // 把插件修改后的 status / headers 原地写回 upstream_resp
                                        // ResponseParts::status / headers 都是插件可写的，
                                        // upstream_resp 的 Incoming body 保持不变，继续流式透传
                                        *upstream_resp.status_mut() = response_parts.status;
                                        *upstream_resp.headers_mut() = response_parts.headers;

                                        // Phase 7：已废弃 API 的弃用标记（RFC 8594）
                                        if route.lifecycle == gateway_core::LifecycleStatus::Deprecated {
                                            upstream_resp.headers_mut().insert(
                                                "deprecation",
                                                HeaderValue::from_static("true"),
                                            );
                                            // 中文语义的附加头，便于非标准客户端识别
                                            upstream_resp.headers_mut().insert(
                                                "x-api-deprecated",
                                                HeaderValue::from_static("true"),
                                            );
                                        }

                                        // 状态码写入 ctx；request_end 由 ObservedBody
                                        // 在 body 流结束/断开时写入，保证总耗时统计准确
                                        ctx.status_code = Some(response_parts.status.as_u16());

                                        // 流式透传（P2.0 核心）：
                                        //   Incoming --body::boxed()--> BoxBody<Bytes, BoxError>
                                        //   零拷贝，不在网关内存中聚合整个响应
                                        let resp = upstream_resp.map(body::boxed);

                                        // 包装 ObservedBody：body 流结束/断开时输出 AccessLog
                                        return Ok(body::observe(resp, ctx));
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

        // 把真实 HTTP 状态码写入 ctx（finish_with_error 的 status_code 字段
        // 固定兜底为 502，这里用实际返回码覆盖，保证 AccessLog 准确）
        ctx.status_code = Some(status_code.as_u16());

        // body::error_response 内部用 Response::new + status_mut/headers_mut
        // 原地写入构造，全程无 unwrap/expect（满足生产代码约束）
        let resp =
            body::error_response(status_code, &error_code_str, &error_msg, ctx.request_id.as_str());

        // 错误路径同样用 ObservedBody 包装：AccessLog 在错误 body
        // 发送完成或客户端断开时输出（错误 body 很小，与立即输出差别不大，
        // 但保持两条路径的日志时序语义一致）
        Ok(body::observe(resp, ctx))
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
    /// 管理端口是否启用（integrated 模式挂载控制面前提）。
    pub fn admin_enabled(&self) -> bool {
        self.config.server.admin.enabled
    }

    /// Prometheus Metrics 端点是否启用（observability.metrics.enabled）。
    pub fn metrics_enabled(&self) -> bool {
        self.config.observability.metrics.enabled
    }

    /// Metrics 端点的路径（observability.metrics.path，默认 `/metrics`）。
    pub fn metrics_path(&self) -> &str {
        &self.config.observability.metrics.path
    }

    /// 控制面连接配置（数据面 gRPC 同步任务使用）。
    pub fn control_plane(&self) -> &gateway_config::config::ControlPlaneConfig {
        &self.config.control_plane
    }

    /// 配置版本号（YAML 启动为 1；控制面发布后随快照递增）
    pub fn config_version(&self) -> u64 {
        self.snapshots.config_version()
    }

    /// 当前生效配置的 checksum。
    pub fn config_checksum(&self) -> String {
        self.snapshots.checksum()
    }

    /// 获取快照存储句柄（integrated 模式的控制面回调使用）。
    pub fn snapshot_store(&self) -> Arc<SnapshotStore> {
        self.snapshots.clone()
    }

    /// 应用控制面发布的快照（原子热更新）。
    ///
    /// 失败时旧配置继续生效；调用方（控制面服务）负责把失败记录为
    /// 实例应用失败。
    pub fn apply_snapshot(
        &self,
        snapshot: &CompiledSnapshot,
    ) -> Result<u64, SnapshotApplyError> {
        self.snapshots.apply(snapshot)
    }
}

// ---------------------------------------------------------------------------
// 插件响应辅助函数（runtime.rs 内部使用）
// ---------------------------------------------------------------------------

/// 把插件短路时返回的纯数据 [`PluginResponse`] 转成真正的 HTTP [`Response`]。
///
/// # 为什么需要这个转换
/// `PluginResponse` 是插件层与 runtime 之间的"纯数据"接口——它不依赖具体 body 类型
/// （只持有 `Bytes`），也不依赖 `hyper`。runtime 接到它后要转成 `Response<ResBody>`，
/// 因为 hyper server handler 必须返回 `Response<ResBody>`。
///
/// # 无 unwrap 设计
/// - `Response::new(body)` 直接构造（无 builder），无失败分支；
/// - `HeaderValue::from_bytes` 可能失败（非法字节如 NUL/CRLF），
///   失败时跳过该头——插件写非法头属于插件 bug，不能让网关崩溃。
/// - `body` 是 `Bytes`（已完整缓冲），`Full::new(body)` 无失败。
fn plugin_response_to_response(resp: PluginResponse) -> Response<ResBody> {
    // 构造带内存 body 的响应（插件短路 body 通常很小，如 JWT 错误 JSON）
    let mut response = Response::new(boxed(Full::new(resp.body)));
    *response.status_mut() = resp.status;

    // 逐头写入：非法字节跳过，不让 panic 影响网关
    for (name, value) in resp.headers.iter() {
        if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
            response.headers_mut().insert(name.clone(), hv);
        }
    }
    response
}

/// 把插件内部故障错误转成 500 响应（fail closed）。
///
/// 插件返回 `Err(PluginError)` 表示系统故障（存储故障/内部不一致），
/// 不是预期业务结果。fail closed 映射为 500，而不是放行——
/// 这是设计文档 4.12 的安全约束："插件层不允许静默降级"。
///
/// # 参数
/// - `plugin_err`：插件层错误
/// - `request_id`：当前请求 ID（用于错误响应 JSON 中的关联字段）
fn plugin_error_to_response(
    plugin_err: gateway_plugin::PluginError,
    request_id: &str,
) -> Response<ResBody> {
    // PluginError::to_gateway_error() 已把 ExecutionFailed / Timeout 映射为
    // GatewayError::Internal，后者的 code() 是 GATEWAY_INTERNAL_ERROR
    let gw_err = plugin_err.to_gateway_error();
    body::error_response(
        gw_err.code().to_http_status(),
        gw_err.code().as_str(),
        &gw_err.to_string(),
        request_id,
    )
}

/// 按 `traffic_split` 权重选择目标 Service（Phase 6）。
///
/// 使用全局轮询计数器做确定性加权分发：
///   - 便于测试（同一序列可复现分流比例）
///   - 避免引入随机数依赖
///
/// 未配置 traffic_split 或所有权重为 0 时回退到 `route.service_id`。
fn select_service_target(route: &gateway_core::RouteConfig) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    // 进程级计数器：所有 Route 共享。它只影响分配节奏，不影响正确性。
    static SPLIT_COUNTER: AtomicU64 = AtomicU64::new(0);

    let Some(split) = route.traffic_split.as_ref() else {
        return route.service_id.clone();
    };

    let targets: Vec<&gateway_core::TrafficTarget> =
        split.targets.iter().filter(|t| t.weight > 0).collect();
    if targets.is_empty() {
        return route.service_id.clone();
    }

    let total: u64 = targets.iter().map(|t| u64::from(t.weight)).sum();
    if total == 0 {
        return route.service_id.clone();
    }

    let pos = SPLIT_COUNTER.fetch_add(1, Ordering::Relaxed) % total;
    let mut accum: u64 = 0;
    for target in targets {
        accum += u64::from(target.weight);
        if pos < accum {
            return target.service_id.clone();
        }
    }

    route.service_id.clone()
}

/// 桥接 WebSocket / HTTP Upgrade 双方连接，直到任一端关闭。
async fn bridge_upgrade(client: hyper::upgrade::OnUpgrade, upstream: hyper::upgrade::OnUpgrade) {
    match tokio::try_join!(client, upstream) {
        Ok((client_io, upstream_io)) => {
            // TokioIo 把 hyper 的 Upgraded（实现 hyper::rt::Read/Write）
            // 适配成 tokio::io::{AsyncRead, AsyncWrite}
            let mut client_io = hyper_util::rt::TokioIo::new(client_io);
            let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_io);
            if let Err(err) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                tracing::debug!(error = %err, "upgraded connection closed");
            }
        },
        Err(err) => tracing::debug!(error = %err, "connection upgrade failed"),
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
