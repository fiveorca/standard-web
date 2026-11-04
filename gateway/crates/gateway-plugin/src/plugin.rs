//! 插件接口、执行上下文与执行结果。
//!
//! # 核心抽象
//!
//! ```text
//! Plugin（trait）
//!    ├── 元数据：name / version / phase / priority
//!    ├── 配置：config_schema / validate_config
//!    ├── 生命周期：init / shutdown
//!    ├── 超时：timeout
//!    └── 执行：execute(&mut PluginContext) -> PluginDecision
//!
//! PluginContext（每次执行新建的借用视图）
//!    ├── parts：&mut Request<...>::Parts  ← 可改 method/uri/headers
//!    ├── ctx：&mut RequestContext         ← 观测字段与命中路由
//!    ├── route：Option<Arc<RouteConfig>>  ← 命中路由（PostRoute 之后才有）
//!    └── response：Option<&mut ResponseParts> ← 响应阶段才有的状态/头
//!
//! PluginDecision
//!    ├── Continue                        ← 交给下一个插件
//!    └── ShortCircuit(PluginResponse)    ← 立即返回响应，后续插件与上游全部跳过
//! ```
//!
//! # 为什么 execute 是 `&mut PluginContext` 而不是 `Request -> Response`
//!
//! 网关的请求/响应 body 是流式的（`Incoming` / `BoxBody`），插件绝大多数
//! 只关心 method/uri/headers 与观测字段，不需要拥有 body。让插件操作
//! `Parts` + 独立的 `ResponseParts`，可以避免为每个插件引入 body 泛型，
//! 也避免插件意外把流式 body 读进内存。
//!
//! 需要读 body 的插件（请求体校验、响应体改写）在 P2.5 由 Runtime 先
//! 缓冲 body 再以 `Bytes` 形式供给，届时扩展上下文即可，不影响本接口。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use gateway_common::ErrorResponse;
use gateway_core::{RequestContext, RouteConfig};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue, StatusCode};

use crate::error::PluginError;
use crate::phase::PluginPhase;

// ---------------------------------------------------------------------------
// 响应状态（响应方向插件可见的视图）
// ---------------------------------------------------------------------------

/// 响应方向插件可见的响应视图。
///
/// 只暴露 `status` 与 `headers`，**不暴露 body**：
/// 响应体是流式的，插件若需要改写 body 必须先由 Runtime 缓冲
/// （Phase 2.5 的 response transform 场景才会用到）。
///
/// Runtime 在调用响应方向阶段前，从 `Response<ResBody>` 中拆出
/// status/headers 构造本结构；插件执行完成后再写回响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseParts {
    /// HTTP 状态码
    pub status: StatusCode,
    /// 响应头（可增删改）
    pub headers: HeaderMap,
}

impl ResponseParts {
    /// 构造响应视图。
    ///
    /// 参数：
    /// - `status`：上游或网关返回的状态码
    /// - `headers`：响应头副本（Runtime 负责 clone，插件拿到的是可写副本）
    pub fn new(status: StatusCode, headers: HeaderMap) -> Self {
        Self { status, headers }
    }
}

// ---------------------------------------------------------------------------
// 插件执行上下文
// ---------------------------------------------------------------------------

/// 插件执行上下文。
///
/// # 生命周期
/// `'a` 是一次插件链执行的借用生命周期。Runtime 在栈上构造本结构，
/// 交给 `PluginChain::run`，执行结束后立即失效——因此**插件不能保存
/// 上下文引用**（编译器会阻止）。
///
/// # 字段可变性
/// - `parts`：`&mut` —— 插件可以改写 method/uri/headers（如重写、注入头）
/// - `ctx`：`&mut` —— 插件可以写观测字段（如认证主体、错误码）
/// - `route`：值（`Arc` clone 很便宜）—— 命中路由，只读
/// - `response`：`Option<&mut>` —— 仅响应方向阶段为 `Some`
pub struct PluginContext<'a> {
    /// 请求的非 body 部分：method / uri / version / headers / extensions
    pub parts: &'a mut http::request::Parts,
    /// 贯穿 Pipeline 的请求上下文（观测、错误、路由引用）
    pub ctx: &'a mut RequestContext,
    /// 命中的路由。`RequestPreRoute` 阶段为 `None`，之后为 `Some`
    pub route: Option<Arc<RouteConfig>>,
    /// 响应方向阶段可写的响应视图；请求方向阶段为 `None`
    pub response: Option<&'a mut ResponseParts>,
}

impl<'a> PluginContext<'a> {
    /// 构造插件上下文。
    ///
    /// 参数：
    /// - `parts`：请求 Parts 的可变借用
    /// - `ctx`：请求上下文的可变借用
    /// - `route`：可选命中路由
    /// - `response`：可选响应视图（仅响应方向阶段传入）
    pub fn new(
        parts: &'a mut http::request::Parts,
        ctx: &'a mut RequestContext,
        route: Option<Arc<RouteConfig>>,
        response: Option<&'a mut ResponseParts>,
    ) -> Self {
        Self {
            parts,
            ctx,
            route,
            response,
        }
    }

    /// 当前请求 ID（用于错误响应与日志关联）。
    pub fn request_id(&self) -> &str {
        self.ctx.request_id.as_str()
    }

    /// 客户端 IP（Network 层注入，可能为 None）。
    pub fn client_ip(&self) -> Option<SocketAddr> {
        self.ctx.client_ip
    }

    /// 读取请求头。
    ///
    /// 参数：
    /// - `name`：Header 名称（`HeaderName` 是已校验的小写规范化类型）
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.parts.headers.get(name)
    }

    /// 读取响应视图（仅响应方向阶段返回 `Some`）。
    ///
    /// 请求方向插件调用时会拿到 `None`——用这种方式在开发期就能发现
    /// "在错误阶段访问响应"的误用。
    pub fn response_mut(&mut self) -> Option<&mut ResponseParts> {
        // `Option<&'a mut T>::as_mut()` 得到 `Option<&mut &'a mut T>`，
        // 再通过 `&mut **` 对内部引用做**重借用**：返回的 `&mut T`
        // 生命周期收缩到 `&mut self`，不会把 `'a` 的独占借用泄漏出去。
        match self.response.as_mut() {
            Some(inner) => Some(&mut **inner),
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 插件响应
// ---------------------------------------------------------------------------

/// 插件短路时返回的响应。
///
/// 用"纯数据"描述而不是 `http::Response<B>`，是为了让 `gateway-plugin`
/// 不依赖具体 body 类型：Runtime 负责把它转换成 `Response<ResBody>`。
#[derive(Debug, Clone)]
pub struct PluginResponse {
    /// HTTP 状态码（例如 401 / 403 / 429 / 200）
    pub status: StatusCode,
    /// 响应头（必须包含 `content-type` 之类必要头时才设置）
    pub headers: HeaderMap,
    /// 响应体（已完整缓冲在内存中）
    pub body: Bytes,
}

impl PluginResponse {
    /// 构造空 body 的响应（例如 204 预检响应）。
    ///
    /// 参数：
    /// - `status`：状态码
    pub fn empty(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    /// 构造 JSON 响应（自动设置 `content-type: application/json`）。
    ///
    /// 参数：
    /// - `status`：状态码
    /// - `body`：已序列化好的 JSON 字节
    pub fn json(status: StatusCode, body: Bytes) -> Self {
        // 空 HeaderMap 上 insert 一定成功；`HeaderValue::from_static` 为编译期校验
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Self {
            status,
            headers,
            body,
        }
    }

    /// 构造统一格式的 JSON 错误响应。
    ///
    /// 输出结构与 Runtime 的错误响应完全一致（复用
    /// `gateway_common::ErrorResponse` 作为唯一序列化来源）：
    /// ```json
    /// {"code":"...","message":"...","request_id":"..."}
    /// ```
    ///
    /// 参数：
    /// - `status`：HTTP 状态码
    /// - `code`：稳定错误码字符串（例如 `"GATEWAY_AUTHENTICATION_FAILED"`）
    /// - `message`：人类可读描述（**不得包含密钥、内部堆栈**）
    /// - `request_id`：当前请求 ID，用于日志关联
    ///
    /// # 无 panic 路径
    /// `serde_json::to_vec` 理论上不会失败（`ErrorResponse` 全为字符串字段），
    /// 但仍用 `unwrap_or_else` 兜底为空对象字节，杜绝 unwrap。
    pub fn from_error(
        status: StatusCode,
        code: &str,
        message: &str,
        request_id: Option<&str>,
    ) -> Self {
        let payload = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
            request_id: request_id.map(str::to_string),
            trace_id: None,
        };
        let body = serde_json::to_vec(&payload)
            .map(Bytes::from)
            .unwrap_or_else(|_| Bytes::from_static(b"{}"));
        Self::json(status, body)
    }
}

// ---------------------------------------------------------------------------
// 插件执行结果
// ---------------------------------------------------------------------------

/// 插件执行结果。
///
/// # 短路语义
/// `ShortCircuit` 会让 `PluginChain::run` **立即停止**：
///   1. 不再执行后续插件（包括后续的安全插件）
///   2. Runtime 不再继续 Pipeline（不会转发上游）
///
/// 这正是设计文档 4.12 要求的"认证失败后不再继续执行上游代理"。
#[derive(Debug, Clone)]
pub enum PluginDecision {
    /// 继续执行下一个插件 / 继续 Pipeline
    Continue,
    /// 短路：立即返回该响应
    ShortCircuit(PluginResponse),
}

impl PluginDecision {
    /// 是否继续。
    pub fn is_continue(&self) -> bool {
        matches!(self, PluginDecision::Continue)
    }

    /// 是否是短路。
    pub fn is_short_circuit(&self) -> bool {
        matches!(self, PluginDecision::ShortCircuit(_))
    }

    /// 取出短路响应（非短路时返回 None）。
    ///
    /// 用 `Option::take` 风格的消费语义：调用方通常只需要一次。
    pub fn into_response(self) -> Option<PluginResponse> {
        match self {
            PluginDecision::Continue => None,
            PluginDecision::ShortCircuit(resp) => Some(resp),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// 插件接口。
///
/// 对应设计文档 4.12 "插件接口必须包括"的 9 项内容：
/// 名称、版本、配置 Schema、初始化、配置校验、执行、生命周期、错误、超时。
///
/// # 默认实现
/// 除 `name` / `phase` / `execute` 外的全部方法都提供了安全默认值，
/// 内置插件通常只需实现这三个方法。
///
/// # Send + Sync
/// 插件会被 `Arc` 共享并在多个连接任务中并发调用，
/// 因此必须 `Send + Sync`。有状态的插件请使用原子类型或
/// `tokio::sync::Mutex`，不要在 `&self` 上做可变借用。
///
/// # 错误处理约定
/// - "凭据无效 / 限流命中"属于**预期业务结果** → 返回
///   `Ok(PluginDecision::ShortCircuit(..))`
/// - "存储故障 / 内部不一致"属于**系统故障** → 返回 `Err(PluginError)`
///   由 Runtime 映射为 500 并记录日志
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    /// 插件唯一名称（注册表的键，也是同优先级下的排序键）。
    ///
    /// 要求 `&'static str`：插件在编译期注册，名称必须稳定且零分配。
    fn name(&self) -> &'static str;

    /// 插件版本（日志、审计与灰度排查用）。
    fn version(&self) -> &'static str {
        "0.1.0"
    }

    /// 插件所属执行阶段。
    fn phase(&self) -> PluginPhase;

    /// 执行优先级：**数值越小越先执行**。
    ///
    /// 同一阶段内按 `(priority, name)` 升序排序，保证执行顺序确定。
    /// 安全插件应使用较小的值（例如 10），业务插件使用较大的值（默认 100）。
    fn priority(&self) -> i32 {
        100
    }

    /// 单次执行超时。返回 `None` 表示不限制。
    ///
    /// 由 `PluginChain::run` 用 `tokio::time::timeout` 实施；
    /// 超时后返回 [`PluginError::Timeout`]，Runtime 映射为 500。
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// 配置 JSON Schema（字符串形式，Phase 3 的管理界面/校验器使用）。
    ///
    /// Phase 2 的内置插件由各自的策略配置驱动，因此默认 `None`。
    fn config_schema(&self) -> Option<&'static str> {
        None
    }

    /// 校验插件配置。
    ///
    /// 在启动阶段（注册后、接流量前）调用；返回 `Err` 会阻止网关启动。
    ///
    /// 参数：
    /// - `config`：插件配置的通用 JSON 表示（Phase 2 通常为空对象）
    fn validate_config(&self, _config: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }

    /// 初始化插件（分配连接池、预编译正则等）。
    ///
    /// 在 `PluginRegistry::init_all` 中被调用一次；返回 `Err` 阻止启动。
    async fn init(&self) -> Result<(), PluginError> {
        Ok(())
    }

    /// 关闭插件，释放资源。优雅关闭时由 `PluginRegistry::shutdown_all` 调用。
    async fn shutdown(&self) {}

    /// 执行插件逻辑。
    ///
    /// 参数：
    /// - `ctx`：本次请求的插件上下文（可变借用）
    ///
    /// 返回：
    /// - `Ok(PluginDecision::Continue)`：继续
    /// - `Ok(PluginDecision::ShortCircuit(..))`：短路
    /// - `Err(PluginError)`：系统故障，短路并由 Runtime 映射为 500
    async fn execute(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError>;
}
