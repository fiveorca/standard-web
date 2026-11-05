//! 流量镜像（Traffic Mirroring，Phase 6）。
//!
//! # 语义
//!
//! 主请求照常转发并返回客户端；按配置比例抽样出的请求**副本**异步
//! 发送到影子 Service，影子响应被丢弃，失败只记录日志。
//!
//! # 为什么需要 tee body
//!
//! 请求体是流式 `Incoming`，不可复制。若只镜像 headers 而丢掉 body，
//! 影子服务看到的请求与真实流量不一致，镜像就失去意义。
//!
//! 因此本模块实现 [`TeeBody`]：主请求每读出一帧数据，就把同一份
//! `Bytes` 的克隆通过有界 channel 交给影子请求。`Bytes` 克隆是引用
//! 计数增加，不复制内存。
//!
//! # 隔离约束
//!
//! - channel 容量固定（[`MIRROR_CHANNEL_CAPACITY`]），写满即丢弃后续帧：
//!   镜像永远不能反向阻塞主请求。
//! - 影子请求在独立 tokio task 中执行，结果不进入客户端响应。
//! - 镜像只在认证阶段之后触发，认证失败的请求不会被镜像到影子服务。

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use tokio::sync::mpsc;

use crate::body::{boxed, BoxError};

/// 镜像 channel 容量（帧数）。
///
/// 选 16 帧：常见请求体远小于此值，几乎不会触发丢弃；
/// 同时又给主请求一个明确的内存上界，避免慢影子服务拖垮网关。
pub const MIRROR_CHANNEL_CAPACITY: usize = 16;

/// 按百分比采样是否命中。
///
/// 使用进程级原子计数器取模，保证比例精确且可复现（便于测试），
/// 不引入随机数依赖。`percentage >= 100` 时恒命中。
pub fn sampled(percentage: u8) -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};

    // 全局镜像计数器
    static MIRROR_COUNTER: AtomicU64 = AtomicU64::new(0);

    if percentage >= 100 {
        return true;
    }
    if percentage == 0 {
        return false;
    }
    let pos = MIRROR_COUNTER.fetch_add(1, Ordering::Relaxed) % 100;
    pos < u64::from(percentage)
}

/// 主请求 body：透传 `Incoming` 帧，同时把数据帧克隆一份给镜像。
pub struct TeeBody {
    /// 原始请求体
    inner: Incoming,
    /// 镜像侧接收通道
    tx: mpsc::Sender<Frame<Bytes>>,
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        // TeeBody 的两个字段都是 Unpin，可以安全取 &mut
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 区分数据帧与 trailers 帧：
                // - 数据帧：克隆 Bytes（引用计数 +1，不复制内容）
                // - trailers：克隆 HeaderMap
                // try_send 失败（channel 满 / 影子已断开）时静默丢弃，
                // 绝不阻塞主请求。
                let mirror_frame = match frame.into_data() {
                    Ok(data) => {
                        let _ = this.tx.try_send(Frame::data(data.clone()));
                        Frame::data(data)
                    },
                    Err(non_data) => match non_data.into_trailers() {
                        Ok(trailers) => {
                            let _ = this.tx.try_send(Frame::trailers(trailers.clone()));
                            Frame::trailers(trailers)
                        },
                        Err(other) => other,
                    },
                };
                Poll::Ready(Some(Ok(mirror_frame)))
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// 镜像请求 body：从 channel 读取 tee 出来的帧。
pub struct ChannelBody {
    /// 接收通道
    rx: mpsc::Receiver<Frame<Bytes>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// 把一个 `Incoming` 拆成"主请求 body + 镜像请求 body"。
pub fn tee(body: Incoming) -> (TeeBody, ChannelBody) {
    let (tx, rx) = mpsc::channel(MIRROR_CHANNEL_CAPACITY);
    (TeeBody { inner: body, tx }, ChannelBody { rx })
}

/// 把主请求 body 擦除成代理客户端可接受的统一类型。
pub fn boxed_tee(body: TeeBody) -> crate::body::ResBody {
    boxed(body)
}

/// 把镜像 body 擦除成代理客户端可接受的统一类型。
pub fn boxed_channel(body: ChannelBody) -> http_body_util::combinators::BoxBody<Bytes, BoxError> {
    body.map_err(|e| e as BoxError).boxed()
}

/// 影子请求发送入口（在独立 task 中执行）。
///
/// 参数：
/// - `client`：代理客户端（Arc 共享）
/// - `request`：已构造好的影子请求（parts 克隆 + ChannelBody）
/// - `endpoint`：影子 Service 选中的端点
/// - `path`：上游路径
/// - `client_ip`：客户端 IP（代理链头）
/// - `timeout`：影子请求超时
/// - `request_id`：主请求 ID（日志关联）
pub async fn send_shadow(
    client: std::sync::Arc<gateway_proxy::ProxyClient>,
    request: http::Request<http_body_util::combinators::BoxBody<Bytes, BoxError>>,
    endpoint: gateway_core::Endpoint,
    path: String,
    client_ip: Option<std::net::SocketAddr>,
    timeout: Option<Duration>,
    request_id: String,
) {
    match client.forward_boxed(request, &endpoint, &path, client_ip, timeout).await {
        Ok(resp) => {
            let status = resp.status();
            // 必须消费完响应 body，否则连接不会回到 hyper 连接池
            let collected = resp.into_body().collect().await;
            let bytes = collected.map(|c| c.to_bytes().len()).unwrap_or(0);
            tracing::debug!(
                target: "mirror",
                request_id = %request_id,
                upstream = %endpoint.address(),
                status = status.as_u16(),
                body_bytes = bytes,
                "mirror request completed"
            );
        },
        Err(err) => {
            // 镜像失败只记录日志，不影响主链路
            tracing::warn!(
                target: "mirror",
                request_id = %request_id,
                upstream = %endpoint.address(),
                error = %err,
                "mirror request failed"
            );
        },
    }
}

/// 空 body 的便捷构造（镜像无 body 请求时使用）。
pub fn empty_boxed_body() -> http_body_util::combinators::BoxBody<Bytes, BoxError> {
    boxed(Full::new(Bytes::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 采样率 0 恒不命中，100 恒命中
    #[test]
    fn sampling_bounds() {
        for _ in 0..10 {
            assert!(!sampled(0));
            assert!(sampled(100));
        }
    }

    /// 50% 采样在 100 次内应命中约一半（宽松断言，避免不稳定测试）
    #[test]
    fn sampling_ratio_is_reasonable() {
        let hits = (0..100).filter(|_| sampled(50)).count();
        assert!((30..=70).contains(&hits), "unexpected hit count: {hits}");
    }
}
