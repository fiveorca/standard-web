//! Body —— 数据面响应体类型抽象与观测包装（P2.0 核心模块）。
//!
//! # 为什么需要这个模块
//!
//! Phase 1 的响应体类型是 `Full<Bytes>`：成功路径会把上游返回的
//! `Incoming` body **完整收集**到内存（`.collect().await`）再一次性返回。
//! 这有三个问题：
//!   1. 大响应（文件下载 / SSE / 流式 LLM 输出）导致内存暴涨；
//!   2. 客户端首字节延迟（TTFB）被拉长到"上游完整响应时间"；
//!   3. 无法支持 SSE / 流式 API 等长连接场景。
//!
//! P2.0 引入 `BoxBody<Bytes, BoxError>` 做类型擦除（type erasure）：
//!   - 成功路径：`Incoming.map_err(...).boxed()` —— 零拷贝流式透传
//!   - 错误路径：`Full<Bytes>.map_err(...).boxed()` —— 内存构造 JSON
//!
//! 两条路径统一成同一个 `ResBody` 类型，满足 hyper server 对单一
//! 响应 Body 类型的要求。
//!
//! # 为什么不直接用 `EitherBody`
//!
//! `http_body_util::EitherBody` 在 http-body-util 0.1.5 中不存在，
//! 只有 `BodyExt::boxed()` / `boxed_unsync()`。`boxed()` 要求
//! `Self: Send + Sync + 'static`，产物 `BoxBody<Bytes, E>` 同时满足
//! hyper server 的 `ResBody: Body + Send + Sync` 约束。
//!
//! # AccessLog 时序问题
//!
//! 流式透传之后，handler 返回的时刻只是"上游响应头到达"时刻。
//! 如果此时立刻写 AccessLog，`request_duration_ms` 统计的是
//! "首包时间"而不是"完整请求时间"（对 SSE 可能差几个小时）。
//!
//! 解决方案：`ObservedBody` 包装响应 body，在以下三个时机之一
//! 输出 AccessLog（以先到者为准，且只输出一次）：
//!   1. body 流正常读完（`poll_frame` 返回 `Ready(None)`）
//!   2. body 流传输出错（`poll_frame` 返回 `Some(Err(_))`）
//!   3. body 被提前 Drop（客户端断连 / hyper 主动放弃）

use std::error::Error as StdError;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use gateway_core::RequestContext;
use gateway_observability::AccessLog;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

// ---------------------------------------------------------------------------
// 类型别名
// ---------------------------------------------------------------------------

/// 统一的 Boxed 错误类型。
///
/// hyper server 要求 `ResBody::Error: Into<Box<dyn StdError + Send + Sync>>`。
/// 上游 body 的错误是 `hyper::Error`，错误响应 body 的错误是 `Infallible`，
/// 两者都实现了 `StdError + Send + Sync`，因此统一装箱成 trait object 后，
/// `Into<BoxError>` 就是恒等转换（identity conversion），自动满足约束。
pub type BoxError = Box<dyn StdError + Send + Sync>;

/// 数据面统一响应体类型：`BoxBody<Bytes, BoxError>`。
///
/// - 成功路径来自上游的 `Incoming`（流式）
/// - 错误路径来自内存构造的 `Full<Bytes>`（一次性）
///
/// `BoxBody` 由 http-body-util 提供，内部是
/// `Pin<Box<dyn Body<Data = Bytes, Error = BoxError> + Send + Sync>>`。
/// `Pin<Box<T>>` 对任意 `T` 都是 `Unpin`（移动 Box 指针不会移动堆上目标），
/// 因此 `BoxBody` 本身是 `Unpin`——下面 `ObservedBody` 的手工 `Body`
/// 实现依赖这一点。
pub type ResBody = BoxBody<Bytes, BoxError>;

// ---------------------------------------------------------------------------
// Body 类型擦除 helper
// ---------------------------------------------------------------------------

/// 把任意满足约束的 Body 擦除成统一的 `ResBody`。
///
/// # 泛型约束
/// - `B: Body<Data = Bytes>` —— hyper 的 `Incoming` 和 `Full<Bytes>` 的
///   Data 都是 `Bytes`
/// - `B: Send + Sync + 'static` —— `BodyExt::boxed()` 的硬性要求
///   （BoxBody 内部 trait object 带 `Send + Sync` bound）
/// - `B::Error: StdError + Send + Sync + 'static` —— 才能装箱成 `BoxError`；
///   `hyper::Error` 与 `Infallible` 都满足
///
/// # 调用链
/// ```text
/// body.map_err(|e| Box::new(e) as BoxError)   ← 错误类型装箱（零成本，仅错误时发生）
///     .boxed()                                 ← BodyExt::boxed()，内部 Box::pin
/// ```
pub fn boxed<B>(body: B) -> ResBody
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: StdError + Send + Sync + 'static,
{
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

// ---------------------------------------------------------------------------
// 错误响应构造 helper
// ---------------------------------------------------------------------------

/// 构造统一格式的 JSON 错误响应。
///
/// # 返回格式
/// ```json
/// { "code": "GATEWAY_ROUTE_NOT_FOUND", "message": "...", "request_id": "..." }
/// ```
///
/// # 为什么可以保证无 unwrap
/// - `serde_json::to_string` 对 `serde_json::Value` 几乎不会失败
///   （Value 已经是内存中的合法 JSON 树），但仍用 `unwrap_or_else`
///   兜底为 `"{}"`，避免任何 panic 路径；
/// - `Response::new(body)` 直接构造响应（不走 `Response::builder()`），
///   `Response::new` 没有失败分支；status / header 通过 `status_mut()` /
///   `headers_mut()` 原地写入，`HeaderValue::from_static` 对编译期字面量
///   是 const 校验，同样无运行时失败。
pub fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
) -> Response<ResBody> {
    // serde_json::json! 宏构造 Value 对象
    let json_body = serde_json::json!({
        "code": code,
        "message": message,
        "request_id": request_id,
    });
    // Value → JSON 字符串 → Bytes；序列化失败兜底为空 JSON 对象
    let body_bytes =
        Bytes::from(serde_json::to_string(&json_body).unwrap_or_else(|_| "{}".to_string()));

    // Response::new 直接构造（无 builder、无失败分支）
    let mut resp = Response::new(boxed(Full::new(body_bytes)));
    // 原地写入状态码
    *resp.status_mut() = status;
    // 写入 Content-Type；from_static 对字面量做编译期合法性保证
    resp.headers_mut()
        .insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

// ---------------------------------------------------------------------------
// ObservedBody —— 流结束/断开时触发 AccessLog 的观测包装
// ---------------------------------------------------------------------------

/// 观测型响应体包装：在 body 流结束、出错或被 Drop 时输出 AccessLog。
///
/// # 为什么 AccessLog 要挂到 body 生命周期上
///
/// 流式透传下，handler 返回 `Response` 时 hyper 才刚开始往客户端写数据。
/// 整个 body 可能持续传输数秒甚至数小时（SSE）。把日志输出挂到 body 的
/// 生命周期上，`request_duration_ms` 才是真实的"客户端视角总耗时"。
///
/// # Unpin 说明
///
/// `ObservedBody` 的两个字段都是 `Unpin`：
///   - `ResBody = BoxBody<Bytes, BoxError>`：内部是 `Pin<Box<dyn ...>>`，
///     `Pin<Box<T>>` 对任意 `T` 恒为 `Unpin`
///   - `Option<RequestContext>`：RequestContext 全是普通数据字段
///
/// 因此手工实现 `Body` trait 时可以用 `Pin::get_mut()` 安全地取到
/// `&mut Self`，不需要 pin-project 宏，也不需要 unsafe。
pub struct ObservedBody {
    /// 被包装的内部 body（已经过 `boxed()` 类型擦除）
    inner: ResBody,
    /// 请求上下文。输出日志后 `take()` 置 None，保证只输出一次
    ctx: Option<RequestContext>,
}

impl ObservedBody {
    /// 输出 AccessLog（幂等：只有第一次调用真正生效）。
    ///
    /// `Option::take()` 把 ctx 拿走并留下 None；
    /// 后续重复调用（如 Ready(None) 之后又 Drop）会因为 None 而直接返回。
    fn emit_access_log(&mut self) {
        if let Some(mut ctx) = self.ctx.take() {
            // 把 request_end 覆盖为 body 流真正结束/断开的时刻。
            // 注意：此时 status_code / error_code 等字段早已由 handler 写入。
            ctx.request_end = Some(Instant::now());
            AccessLog::emit(&ctx);
        }
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 驱动内部 body 的下一帧。
    ///
    /// # Body::poll_frame 契约（http-body crate）
    /// - `Poll::Ready(Some(Ok(frame)))`：产出一帧数据或 trailers
    /// - `Poll::Ready(Some(Err(e)))`：流出错，hyper 会中止本次响应写出
    /// - `Poll::Ready(None)`：流正常结束
    /// - `Poll::Pending`：暂无数据，唤醒后重试
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // ObservedBody: Unpin（见结构体文档），get_mut 安全
        let this = self.as_mut().get_mut();
        // Pin::new 要求目标 Unpin；BoxBody 是 Unpin（Pin<Box<dyn ...>>）
        match Pin::new(&mut this.inner).poll_frame(cx) {
            // 流正常读完 → 输出 AccessLog
            Poll::Ready(None) => {
                this.emit_access_log();
                Poll::Ready(None)
            },
            // 流中途出错（如上游断连）→ 同样输出 AccessLog，再把错误透传给 hyper
            Poll::Ready(Some(Err(e))) => {
                this.emit_access_log();
                Poll::Ready(Some(Err(e)))
            },
            // 数据帧 / Pending → 原样透传
            other => other,
        }
    }

    /// 是否已确定没有更多数据。委托给内部 body。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 剩余数据大小提示（用于 Content-Length / 分块编码决策）。委托给内部 body。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedBody {
    /// 客户端断连或 hyper 提前放弃 body 时触发。
    ///
    /// 若日志已通过正常结束路径输出过（ctx 已被 take 为 None），
    /// 这里不会重复输出。
    fn drop(&mut self) {
        self.emit_access_log();
    }
}

/// 把一个 `Response<ResBody>` 的 body 包装成 `ObservedBody`，
/// 并再次 `boxed()` 回 `ResBody`，对外保持类型不变。
///
/// # 参数
/// - `resp`：已构造好的响应（body 必须是 `ResBody`）
/// - `ctx`：本请求的 RequestContext（所有权移交，日志输出后销毁）
pub fn observe(resp: Response<ResBody>, ctx: RequestContext) -> Response<ResBody> {
    resp.map(|inner| {
        // ObservedBody 的错误类型已经是 BoxError，
        // 直接 .boxed() 即得 ResBody，无需再 map_err
        ObservedBody {
            inner,
            ctx: Some(ctx),
        }
        .boxed()
    })
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试：boxed() 能把 Full<Bytes> 擦除成 ResBody，且数据完整读出
    #[tokio::test]
    async fn boxed_full_body_roundtrip() {
        let body = boxed(Full::new(Bytes::from("hello")));
        // collect 把 Body 全部读成 Collected，再 to_bytes 取 Bytes
        let collected = body.collect().await.unwrap_or_else(|_| panic!("collect should succeed"));
        assert_eq!(collected.to_bytes(), Bytes::from("hello"));
    }

    /// 测试：error_response 构造的响应状态码、Content-Type、JSON 字段正确
    #[tokio::test]
    async fn error_response_format() {
        let resp =
            error_response(StatusCode::NOT_FOUND, "GATEWAY_ROUTE_NOT_FOUND", "no route", "req-123");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        let collected = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|_| panic!("collect should succeed"));
        let body_bytes = collected.to_bytes();
        let text = String::from_utf8_lossy(&body_bytes);
        assert!(text.contains("GATEWAY_ROUTE_NOT_FOUND"));
        assert!(text.contains("no route"));
        assert!(text.contains("req-123"));
    }

    /// 测试：ObservedBody 正常读完流后 ctx 被消费（日志只输出一次）
    #[tokio::test]
    async fn observed_body_consumes_ctx_on_end() {
        let ctx = RequestContext::new(gateway_common::RequestId::new());
        let mut body = ObservedBody {
            inner: boxed(Full::new(Bytes::from("data"))),
            ctx: Some(ctx),
        };
        // 读第一帧（数据帧）
        let first = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(matches!(first, Some(Ok(_))));
        // 读到流结束 → 应触发日志输出并消费 ctx
        let end = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(end.is_none());
        assert!(body.ctx.is_none(), "ctx should be taken after stream end");
    }
}
