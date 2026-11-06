//! 健康检查基础设施。
//!
//! # 两类检查
//!
//! - **主动**：[`probe`] 周期性地对端点发起 TCP 连接或 HTTP GET，
//!   由 [`HealthTracker`] 依据"连续失败/成功阈值"决定是否迁移状态。
//! - **被动**：真实请求的失败（连接失败 / 超时 / 5xx）与成功也喂给
//!   同一个 [`HealthTracker`]（独立实例），实现异常实例自动摘流与恢复。
//!
//! # 为什么不在这里读配置
//!
//! 本模块只关心"探测 + 阈值判定"，配置来源（YAML / 控制面快照）与调度
//! 由 `gateway-runtime` 负责，方便单独测试状态机。

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use gateway_core::{HealthCheckConfig, HealthCheckKind, HealthStatus};

/// 单次主动探测。返回 `true` 表示探测成功。
///
/// 探测失败（连接拒绝、超时、非预期状态码）统一返回 `false`，
/// 调用方只关心二值结果。
pub async fn probe(host: &str, port: u16, cfg: &HealthCheckConfig) -> bool {
    let timeout = Duration::from_secs(cfg.timeout_secs.max(1));
    match cfg.kind {
        HealthCheckKind::Tcp => {
            matches!(
                tokio::time::timeout(timeout, TcpStream::connect((host, port))).await,
                Ok(Ok(_))
            )
        },
        HealthCheckKind::Http => {
            let path = if cfg.path.starts_with('/') {
                cfg.path.as_str()
            } else {
                "/"
            };
            match http_status(host, port, path, timeout).await {
                Some(status) => {
                    gateway_core::status_matches(cfg.expected_status.as_deref(), status)
                },
                None => false,
            }
        },
    }
}

/// 发起一个最小 HTTP/1.1 GET 并读取状态码。
///
/// 不引入 HTTP 客户端依赖：健康检查只需要状态行，直接走 TCP 更轻量。
async fn http_status(host: &str, port: u16, path: &str, timeout: Duration) -> Option<u16> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gateway-health-check\r\nConnection: close\r\n\r\n"
    );

    let exchange = async {
        let mut stream = TcpStream::connect((host, port)).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;

        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let mut chunk = [0u8; 256];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            // 状态行以 CRLF 结束，读到即可停止
            if buf.windows(2).any(|w| w == b"\r\n") || buf.len() >= 4096 {
                break;
            }
        }
        parse_status_line(&buf)
    };

    tokio::time::timeout(timeout, exchange).await.ok().flatten()
}

/// 从响应首行解析状态码：`HTTP/1.1 200 OK` → `Some(200)`。
fn parse_status_line(buf: &[u8]) -> Option<u16> {
    let end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..end]).ok()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

// ---------------------------------------------------------------------------
// HealthTracker —— 连续阈值状态机
// ---------------------------------------------------------------------------

/// 单个端点的连续计数。
#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    consecutive_failures: u32,
    consecutive_successes: u32,
}

/// 端点健康状态判定器。
///
/// 记录每个端点连续成功/失败次数，达到阈值且与当前状态不同的时候
/// 返回目标状态；否则返回 `None`。主动检查与被动检查各自持有一个实例，
/// 互不干扰。
#[derive(Debug, Default)]
pub struct HealthTracker {
    entries: HashMap<(String, String), Counters>,
}

impl HealthTracker {
    /// 新建空判定器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次探测/请求结果，返回需要迁移到的状态。
    ///
    /// - `current`：端点当前状态，用于避免重复迁移（相同状态不返回）
    /// - 成功达到 `healthy_threshold` → `HEALTHY`
    /// - 失败达到 `unhealthy_threshold` → `UNHEALTHY`
    ///
    /// `DRAINING` 是人工摘流状态，健康检查不会把它改回 `HEALTHY`。
    pub fn record(
        &mut self,
        upstream_id: &str,
        endpoint_id: &str,
        success: bool,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
        current: HealthStatus,
    ) -> Option<HealthStatus> {
        let counters = self
            .entries
            .entry((upstream_id.to_string(), endpoint_id.to_string()))
            .or_default();

        if success {
            counters.consecutive_successes = counters.consecutive_successes.saturating_add(1);
            counters.consecutive_failures = 0;
            if current == HealthStatus::Draining {
                return None;
            }
            if counters.consecutive_successes >= healthy_threshold.max(1)
                && current != HealthStatus::Healthy
            {
                return Some(HealthStatus::Healthy);
            }
        } else {
            counters.consecutive_failures = counters.consecutive_failures.saturating_add(1);
            counters.consecutive_successes = 0;
            if counters.consecutive_failures >= unhealthy_threshold.max(1)
                && current != HealthStatus::Unhealthy
            {
                return Some(HealthStatus::Unhealthy);
            }
        }
        None
    }

    /// 清理某个上游下已不存在的端点计数（端点被服务发现刷新掉）。
    pub fn retain_upstream(&mut self, upstream_id: &str, valid_endpoint_ids: &[String]) {
        self.entries.retain(|(upstream, endpoint), _| {
            upstream != upstream_id || valid_endpoint_ids.iter().any(|id| id == endpoint)
        });
    }

    /// 清理已从配置中删除的上游。
    pub fn retain_upstreams(&mut self, valid_upstream_ids: &[String]) {
        self.entries
            .retain(|(upstream, _), _| valid_upstream_ids.iter().any(|id| id == upstream));
    }

    /// 当前跟踪的端点数量（测试/调试用）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_line() {
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(parse_status_line(b"HTTP/1.0 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(parse_status_line(b"garbage"), None);
        assert_eq!(parse_status_line(b""), None);
    }

    #[test]
    fn consecutive_failures_trigger_unhealthy_once() {
        let mut tracker = HealthTracker::new();
        // 阈值 2：第一次失败不迁移
        assert_eq!(tracker.record("u1", "ep-0", false, 2, 2, HealthStatus::Healthy), None);
        // 第二次失败 → UNHEALTHY
        assert_eq!(
            tracker.record("u1", "ep-0", false, 2, 2, HealthStatus::Healthy),
            Some(HealthStatus::Unhealthy)
        );
        // 已经是 UNHEALTHY，不再重复迁移
        assert_eq!(tracker.record("u1", "ep-0", false, 2, 2, HealthStatus::Unhealthy), None);
    }

    #[test]
    fn consecutive_successes_restore_health() {
        let mut tracker = HealthTracker::new();
        assert_eq!(tracker.record("u1", "ep-0", true, 2, 2, HealthStatus::Unhealthy), None);
        assert_eq!(
            tracker.record("u1", "ep-0", true, 2, 2, HealthStatus::Unhealthy),
            Some(HealthStatus::Healthy)
        );
    }

    #[test]
    fn success_resets_failure_counter() {
        let mut tracker = HealthTracker::new();
        tracker.record("u1", "ep-0", false, 2, 3, HealthStatus::Healthy);
        tracker.record("u1", "ep-0", false, 2, 3, HealthStatus::Healthy);
        // 一次成功把失败计数清零，之后需要重新累计 3 次失败
        tracker.record("u1", "ep-0", true, 2, 3, HealthStatus::Healthy);
        assert_eq!(tracker.record("u1", "ep-0", false, 2, 3, HealthStatus::Healthy), None);
        assert_eq!(tracker.record("u1", "ep-0", false, 2, 3, HealthStatus::Healthy), None);
        assert_eq!(
            tracker.record("u1", "ep-0", false, 2, 3, HealthStatus::Healthy),
            Some(HealthStatus::Unhealthy)
        );
    }

    #[test]
    fn draining_is_not_reverted_by_health_check() {
        let mut tracker = HealthTracker::new();
        assert_eq!(tracker.record("u1", "ep-0", true, 1, 1, HealthStatus::Draining), None);
    }

    #[test]
    fn retain_prunes_stale_entries() {
        let mut tracker = HealthTracker::new();
        tracker.record("u1", "ep-0", true, 1, 1, HealthStatus::Unknown);
        tracker.record("u1", "ep-1", true, 1, 1, HealthStatus::Unknown);
        tracker.record("u2", "ep-9", true, 1, 1, HealthStatus::Unknown);

        tracker.retain_upstream("u1", &["ep-0".to_string()]);
        assert_eq!(tracker.len(), 2);

        tracker.retain_upstreams(&["u1".to_string()]);
        assert_eq!(tracker.len(), 1);
    }

    #[tokio::test]
    async fn tcp_probe_detects_closed_port() {
        // 绑定一个随机端口后立即释放，连接必然被拒绝
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let cfg = HealthCheckConfig {
            kind: HealthCheckKind::Tcp,
            timeout_secs: 1,
            ..Default::default()
        };
        assert!(!probe("127.0.0.1", port, &cfg).await);
    }
}
