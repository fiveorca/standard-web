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
use gateway_proxy::{ProxyClient, ProxyOptions};

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use tokio::sync::{oneshot, Mutex};
use tokio_util::sync::CancellationToken;

use crate::body::{self, ResBody};
use crate::state::{SnapshotApplyError, SnapshotStore};

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
        // 后续热更新通过 SnapshotStore::apply 原子替换
        let snapshots = Arc::new(
            SnapshotStore::from_config(&cfg).map_err(|e| vec![e])?,
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

        Ok(Self {
            config: cfg,
            snapshots,
            proxy_client,
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
        request: Request<Incoming>,
    ) -> Result<Response<ResBody>, std::convert::Infallible> {
        use gateway_common::ErrorCode;

        // -----------------------------------------------------------------
        // 1. 请求上下文初始化
        // -----------------------------------------------------------------

        // 生成请求 ID（uuid v4）
        let request_id = RequestId::new();
        let mut ctx = gateway_core::RequestContext::new(request_id);

        // 拆开请求 Parts（method/uri/headers/extensions） 和 Body
        let (parts, body) = request.into_parts();
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

                // Route → Service → Upstream 引用解析：
                // Route 引用的是 service_id，而 UpstreamRegistry 以 upstream_id
                // 为键，先查 service_upstreams 映射表拿到 upstream_id。
                // validate() 已保证引用完整，查不到属于内部错误 → 500。
                let upstream_id = state.service_upstreams.get(&route.service_id).cloned();

                match upstream_id {
                    // Service → Upstream 映射缺失（配置内部错误）→ 500
                    None => {
                        let msg = format!(
                            "service '{}' has no upstream mapping (config bug)",
                            route.service_id
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
                        // 从 UpstreamRegistry 选出一个健康实例（Round-Robin 算法）
                        match state.upstream_registry.pick_endpoint(&upstream_id).await {
                            Ok(endpoint) => {
                                ctx.set_endpoint(endpoint.clone());
                                ctx.mark_upstream_start();

                                // 构造转发请求：原 Parts + 原 Body（流式，不收集）。
                                // ProxyClient::forward 内部会把 URI 覆盖为真实上游地址，
                                // 并注入 X-Forwarded-For 等代理链头
                                let upstream_req = http::Request::from_parts(parts, body);

                                match self
                                    .proxy_client
                                    .forward(upstream_req, &endpoint, &path, client_ip)
                                    .await
                                {
                                    // 上游返回任何 HTTP 响应（2xx/3xx/4xx/5xx）都算"代理成功"——
                                    // 我们只透传，不解释业务语义
                                    Ok(upstream_resp) => {
                                        let status = upstream_resp.status().as_u16();
                                        // 记录"上游响应头到达"时间点
                                        // （upstream_duration_ms 统计口径：发起上游请求 → 首包到达）
                                        ctx.mark_upstream_headers();
                                        // 状态码现在写入 ctx；request_end 由 ObservedBody
                                        // 在 body 流结束/断开时写入，保证总耗时统计准确
                                        ctx.status_code = Some(status);

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
                            // 没有健康端点 → 503
                            Err(_pick_err) => {
                                let msg =
                                    format!("upstream {upstream_id} has no healthy endpoints");
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
