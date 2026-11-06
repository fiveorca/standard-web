//! 健康检查调度（主动）+ 请求结果驱动的被动检查。
//!
//! # 主动检查
//!
//! 后台任务每秒 tick 一次，按 `upstreams[].health_check.interval_secs`
//! 决定每个上游是否到期；到期的端点探测任务进入跨上游共享的 [`JoinSet`]，
//! 由 [`Semaphore`] 限制全局并发探测数（[`MAX_CONCURRENT_PROBES`]），
//! 防止大量上游同时到期时产生探测风暴。探测结果由计数器
//! [`HealthTracker`] 判定，达到阈值即写回 [`UpstreamRegistry`]。
//!
//! # 被动检查
//!
//! 真实请求结果（连接失败 / 超时 / 5xx 记为失败，其余记为成功）由
//! [`PassiveHealth`] 记录；与主动检查使用独立计数器，互不干扰。
//!
//! # 与热更新的关系
//!
//! 探测目标每次 tick 都从 `SnapshotStore::current()` 重新读取，
//! 控制面发布新配置后自动生效；配置版本变化时清理已删除上游的计数。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gateway_core::{
    Endpoint, HealthCheckConfig, HealthStatus, PassiveHealthConfig, UpstreamManager,
};
use gateway_upstream::{probe, HealthTracker, UpstreamRegistry};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::state::SnapshotStore;

/// 调度 tick 间隔。
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// 主动探测的全局并发上限。
///
/// 大量上游同时到期时，未完成的探测会排队等待信号量，避免瞬间打满
/// 文件描述符或把探测流量放大成对后端的风暴。64 对绝大多数部署足够。
const MAX_CONCURRENT_PROBES: usize = 64;

/// 一次完成的探测结果。
struct ProbeOutcome {
    upstream_id: String,
    endpoint: Endpoint,
    ok: bool,
    config: HealthCheckConfig,
}

/// 启动主动健康检查后台任务。
pub fn spawn(store: Arc<SnapshotStore>, shutdown: CancellationToken) {
    tokio::spawn(async move { run(store, shutdown).await });
}

/// 后台循环。
async fn run(store: Arc<SnapshotStore>, shutdown: CancellationToken) {
    let mut tracker = HealthTracker::new();
    // upstream_id → 下次允许探测的时刻
    let mut next_probe: HashMap<String, Instant> = HashMap::new();
    let mut cached_version: Option<u64> = None;
    // 跨上游共享的探测任务集合与并发信号量
    let mut probes: JoinSet<ProbeOutcome> = JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let state = store.current();
        if cached_version != Some(state.config_version) {
            // 配置热更新：清空调度时间表与已删除上游的计数
            next_probe.clear();
            cached_version = Some(state.config_version);
            let ids: Vec<String> =
                state.upstream_configs.iter().map(|cfg| cfg.id.clone()).collect();
            tracker.retain_upstreams(&ids);
        }

        // -------------------------------------------------------------
        // 1. 收割上一轮已完成的探测（非阻塞）
        // -------------------------------------------------------------
        while let Some(joined) = probes.try_join_next() {
            let Ok(outcome) = joined else { continue };
            apply_probe_outcome(&state, &mut tracker, &outcome).await;
        }

        // -------------------------------------------------------------
        // 2. 派发本轮到期的探测（受全局信号量限制）
        // -------------------------------------------------------------
        for cfg in state.upstream_configs.iter() {
            if !cfg.enabled {
                continue;
            }
            let Some(health) = cfg.health_check.as_ref().filter(|h| h.enabled) else {
                continue;
            };

            let interval = Duration::from_secs(health.interval_secs.max(1));
            let due = next_probe.get(&cfg.id).is_none_or(|at| Instant::now() >= *at);
            if !due {
                continue;
            }
            next_probe.insert(cfg.id.clone(), Instant::now() + interval);

            let endpoints = state.upstream_registry.endpoints_of(&cfg.id).await;
            let valid_ids: Vec<String> = endpoints.iter().map(|ep| ep.runtime_id.clone()).collect();
            tracker.retain_upstream(&cfg.id, &valid_ids);

            for endpoint in endpoints {
                // DRAINING 是人工摘流，不做探测也不自动恢复
                if endpoint.status == HealthStatus::Draining {
                    continue;
                }
                let health_cfg = health.clone();
                let upstream_id = cfg.id.clone();
                let permits = permits.clone();
                probes.spawn(async move {
                    // 信号量满了就排队；permit 在作用域结束时自动释放
                    let _permit = permits.acquire().await.ok();
                    let ok = probe(&endpoint.host, endpoint.port, &health_cfg).await;
                    ProbeOutcome {
                        upstream_id,
                        endpoint,
                        ok,
                        config: health_cfg,
                    }
                });
            }
        }

        // -------------------------------------------------------------
        // 3. 等待下一个事件：shutdown / tick / 任一探测完成
        // -------------------------------------------------------------
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(TICK_INTERVAL) => {},
            // 有探测在跑时，任何一个完成都立即唤醒收割，避免结果延迟到下个 tick
            joined = probes.join_next(), if !probes.is_empty() => {
                if let Some(Ok(outcome)) = joined {
                    apply_probe_outcome(&state, &mut tracker, &outcome).await;
                }
            },
        }
    }

    probes.abort_all();
    tracing::info!(target: "health", "active health checker stopped");
}

/// 把一次探测结果写入计数器与注册表，并记录指标/日志。
async fn apply_probe_outcome(
    state: &crate::state::RuntimeState,
    tracker: &mut HealthTracker,
    outcome: &ProbeOutcome,
) {
    let metrics = gateway_observability::Metrics::global();
    metrics.inc_counter(
        "gateway_health_check_total",
        &[
            ("upstream", outcome.upstream_id.as_str()),
            ("result", if outcome.ok { "success" } else { "failure" }),
        ],
    );

    // 当前状态以注册表为准（被动检查可能已改过）
    let Some(current) = state
        .upstream_registry
        .endpoint_status(&outcome.upstream_id, &outcome.endpoint.runtime_id)
        .await
    else {
        return;
    };

    let next = tracker.record(
        &outcome.upstream_id,
        &outcome.endpoint.runtime_id,
        outcome.ok,
        outcome.config.healthy_threshold,
        outcome.config.unhealthy_threshold,
        current,
    );
    if let Some(next) = next {
        state
            .upstream_registry
            .update_health(&outcome.upstream_id, &outcome.endpoint.runtime_id, next)
            .await;
        let status_label = next.to_string();
        metrics.inc_counter(
            "gateway_endpoint_health_transitions_total",
            &[
                ("upstream", outcome.upstream_id.as_str()),
                ("status", status_label.as_str()),
            ],
        );
        // 状态迁移时同步刷新 gauge
        metrics.set_gauge(
            "gateway_endpoint_healthy",
            &[
                ("upstream", outcome.upstream_id.as_str()),
                ("endpoint", outcome.endpoint.runtime_id.as_str()),
            ],
            health_gauge_value(next),
        );
        tracing::info!(
            target: "health",
            upstream_id = %outcome.upstream_id,
            endpoint = %outcome.endpoint.address(),
            status = %status_label,
            "endpoint health status changed"
        );
    }
}

/// 端点健康状态 → gauge 数值。
///
/// `Healthy = 1`，其余（`Unknown` / `Unhealthy` / `Draining`）= 0，
/// 这样 PromQL 直接 `avg` 就能得到可用端点比例。
fn health_gauge_value(status: HealthStatus) -> u64 {
    match status {
        HealthStatus::Healthy => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// 被动健康检查
// ---------------------------------------------------------------------------

/// 被动健康检查记录器。
///
/// 由请求路径在拿到上游结果后调用；计数器与主动检查完全独立。
pub struct PassiveHealth {
    tracker: Mutex<HealthTracker>,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveHealth {
    /// 新建被动检查记录器。
    pub fn new() -> Self {
        Self {
            tracker: Mutex::new(HealthTracker::new()),
        }
    }

    /// 记录一次上游请求结果，命中阈值时直接更新注册表。
    ///
    /// - `success = false`：连接失败 / 超时 / 5xx
    /// - `success = true`：拿到非 5xx 响应
    pub async fn record(
        &self,
        registry: &UpstreamRegistry,
        upstream_id: &str,
        endpoint: &Endpoint,
        success: bool,
        cfg: &PassiveHealthConfig,
    ) {
        if !cfg.enabled {
            return;
        }
        // 当前状态从注册表读取（主动检查可能已经改过状态）
        let Some(current) = registry.endpoint_status(upstream_id, &endpoint.runtime_id).await
        else {
            return;
        };

        let next = {
            let Ok(mut tracker) = self.tracker.lock() else {
                return;
            };
            tracker.record(
                upstream_id,
                &endpoint.runtime_id,
                success,
                cfg.recovery_threshold,
                cfg.failure_threshold,
                current,
            )
        };

        if let Some(next) = next {
            registry.update_health(upstream_id, &endpoint.runtime_id, next).await;
            gateway_observability::Metrics::global().set_gauge(
                "gateway_endpoint_healthy",
                &[
                    ("upstream", upstream_id),
                    ("endpoint", endpoint.runtime_id.as_str()),
                ],
                health_gauge_value(next),
            );
            tracing::warn!(
                target: "health",
                upstream_id = %upstream_id,
                endpoint = %endpoint.address(),
                status = %next,
                "endpoint status changed by passive health check"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{
        EndpointConfig, HealthCheckConfig, HealthCheckKind, LoadBalanceAlgorithm, UpstreamConfig,
    };

    fn upstream_cfg(id: &str, port: u16, health: HealthCheckConfig) -> UpstreamConfig {
        UpstreamConfig {
            id: id.to_string(),
            name: None,
            tenant_id: None,
            cluster_id: None,
            enabled: true,
            algorithm: LoadBalanceAlgorithm::RoundRobin,
            endpoints: vec![EndpointConfig {
                id: None,
                host: "127.0.0.1".into(),
                port,
                weight: 1,
                zone: None,
                region: None,
            }],
            discovery: None,
            health_check: Some(health),
        }
    }

    /// 被动检查：连续失败达到阈值 → UNHEALTHY；连续成功达到阈值 → 恢复
    #[tokio::test]
    async fn passive_check_marks_unhealthy_then_recovers() {
        let registry = UpstreamRegistry::new(&[upstream_cfg(
            "u1",
            9000,
            HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        )]);
        let passive = PassiveHealth::new();
        let cfg = PassiveHealthConfig {
            enabled: true,
            failure_threshold: 2,
            recovery_threshold: 2,
            ..Default::default()
        };
        let endpoint = registry.endpoints_of("u1").await.remove(0);

        passive.record(&registry, "u1", &endpoint, false, &cfg).await;
        assert_eq!(
            registry.endpoint_status("u1", &endpoint.runtime_id).await,
            Some(HealthStatus::Unknown)
        );

        passive.record(&registry, "u1", &endpoint, false, &cfg).await;
        assert_eq!(
            registry.endpoint_status("u1", &endpoint.runtime_id).await,
            Some(HealthStatus::Unhealthy)
        );

        passive.record(&registry, "u1", &endpoint, true, &cfg).await;
        passive.record(&registry, "u1", &endpoint, true, &cfg).await;
        assert_eq!(
            registry.endpoint_status("u1", &endpoint.runtime_id).await,
            Some(HealthStatus::Healthy)
        );
    }

    /// 被动检查关闭时不改变端点状态
    #[tokio::test]
    async fn passive_check_disabled_is_noop() {
        let registry = UpstreamRegistry::new(&[upstream_cfg(
            "u1",
            9000,
            HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        )]);
        let passive = PassiveHealth::new();
        let cfg = PassiveHealthConfig {
            enabled: false,
            failure_threshold: 1,
            ..Default::default()
        };
        let endpoint = registry.endpoints_of("u1").await.remove(0);
        passive.record(&registry, "u1", &endpoint, false, &cfg).await;
        assert_eq!(
            registry.endpoint_status("u1", &endpoint.runtime_id).await,
            Some(HealthStatus::Unknown)
        );
    }

    /// 主动检查：探测失败达到阈值后端点被摘流
    #[tokio::test]
    async fn active_check_marks_closed_port_unhealthy() {
        use gateway_config::{CompiledSnapshot, PoliciesConfig, ResourceBundle};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let health = HealthCheckConfig {
            enabled: true,
            kind: HealthCheckKind::Tcp,
            interval_secs: 1,
            timeout_secs: 1,
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            ..Default::default()
        };
        let snapshot = CompiledSnapshot::compile(
            ResourceBundle {
                routes: vec![],
                services: vec![],
                upstreams: vec![upstream_cfg("u1", port, health)],
                certificates: vec![],
                policies: PoliciesConfig::default(),
            },
            1,
        )
        .expect("compile snapshot");
        let store = std::sync::Arc::new(
            crate::state::SnapshotStore::from_snapshot(&snapshot).expect("snapshot store"),
        );

        let shutdown = CancellationToken::new();
        let task = tokio::spawn({
            let store = store.clone();
            let token = shutdown.clone();
            async move { run(store, token).await }
        });

        // 等待首个 tick 完成探测（tick 1s + 探测超时 1s，留足余量）
        tokio::time::sleep(Duration::from_millis(2500)).await;
        shutdown.cancel();
        let _ = task.await;

        let current = store.current();
        let status = current.upstream_registry.endpoint_status("u1", "u1-ep-0").await;
        assert_eq!(status, Some(HealthStatus::Unhealthy));
    }
}
