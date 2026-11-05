//! 动态服务发现后台任务（Phase 6）。
//!
//! # 职责
//!
//! 周期性读取当前配置快照里的 `upstreams[].discovery`，调用对应
//! Provider 解析端点，并把结果写回运行时上游注册表。
//!
//! # 调度模型
//!
//! - 单 Task 串行调度（1 秒 tick），每个 upstream 独立计算下次刷新时刻
//! - Provider 实例按 upstream 缓存，配置版本变化时清空（避免持有过期配置）
//! - 解析失败只记录日志，保留注册表里上一轮成功端点（Last Known Good）
//! - 解析结果为空时**不替换**：空列表通常意味着服务瞬时不可用，
//!   直接清空会导致全部 503；保留旧端点等待下一轮恢复

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_core::{
    DiscoveryConfig, DiscoveryProviderKind, DnsRecordKind, ServiceDiscoveryProvider,
    UpstreamConfig,
};
use gateway_discovery::{DnsDiscoveryConfig, DnsDiscoveryProvider, DnsQueryKind, K8sDiscoveryConfig, K8sDiscoveryProvider};

use crate::state::SnapshotStore;

/// 调度 tick 间隔。
///
/// 1 秒足够精确地执行最小刷新间隔；单次 tick 只遍历配置好的 upstream，
/// 开销可忽略。
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// 启动服务发现后台任务。
pub fn spawn(store: Arc<SnapshotStore>) {
    tokio::spawn(async move { run(store).await });
}

/// 后台循环。
async fn run(store: Arc<SnapshotStore>) {
    // upstream_id → 已构建 Provider
    let mut providers: HashMap<String, Arc<dyn ServiceDiscoveryProvider>> = HashMap::new();
    // upstream_id → 下次允许刷新的时刻
    let mut next_refresh: HashMap<String, Instant> = HashMap::new();
    // 最近一次处理的配置版本（变化时清空 Provider 缓存）
    let mut cached_version: Option<u64> = None;

    loop {
        let state = store.current();
        if cached_version != Some(state.config_version) {
            // 配置热更新：旧 Provider 可能绑定了已删除/已修改的上游配置
            providers.clear();
            next_refresh.clear();
            cached_version = Some(state.config_version);
        }

        for cfg in state.upstream_configs.iter() {
            if !cfg.enabled || cfg.discovery.is_none() {
                continue;
            }
            let Some(discovery) = cfg.discovery.as_ref() else {
                continue;
            };

            // 到期判断
            let interval = Duration::from_secs(discovery.refresh_interval_secs.max(1));
            let due = match next_refresh.get(&cfg.id) {
                Some(at) => Instant::now() >= *at,
                None => true,
            };
            if !due {
                continue;
            }
            next_refresh.insert(cfg.id.clone(), Instant::now() + interval);

            // Provider 懒构建
            let provider = match providers.get(&cfg.id) {
                Some(p) => p.clone(),
                None => match build_provider(cfg, discovery) {
                    Ok(p) => {
                        providers.insert(cfg.id.clone(), p.clone());
                        p
                    },
                    Err(err) => {
                        tracing::warn!(
                            target: "discovery",
                            upstream_id = %cfg.id,
                            error = %err,
                            "failed to build discovery provider"
                        );
                        continue;
                    },
                },
            };

            match provider.resolve(&cfg.id).await {
                Ok(endpoints) if !endpoints.is_empty() => {
                    let count = state
                        .upstream_registry
                        .replace_endpoints(&cfg.id, endpoints)
                        .await;
                    tracing::debug!(
                        target: "discovery",
                        upstream_id = %cfg.id,
                        provider = %discovery.provider,
                        endpoint_count = count,
                        "upstream endpoints refreshed"
                    );
                },
                Ok(_) => {
                    tracing::warn!(
                        target: "discovery",
                        upstream_id = %cfg.id,
                        "discovery returned empty endpoint list, keeping previous endpoints"
                    );
                },
                Err(err) => {
                    tracing::warn!(
                        target: "discovery",
                        upstream_id = %cfg.id,
                        error = %err,
                        "discovery resolve failed, keeping previous endpoints"
                    );
                },
            }
        }

        tokio::time::sleep(TICK_INTERVAL).await;
    }
}

/// 根据配置构建 Provider。
fn build_provider(
    upstream: &UpstreamConfig,
    discovery: &DiscoveryConfig,
) -> Result<Arc<dyn ServiceDiscoveryProvider>, String> {
    match discovery.provider {
        DiscoveryProviderKind::Static => {
            // Static 不需要动态刷新；这里不应该被调度到，返回错误让上层跳过
            Err("static provider does not need background refresh".to_string())
        },

        DiscoveryProviderKind::Dns => {
            let domain = discovery
                .domain
                .clone()
                .filter(|d| !d.is_empty())
                .ok_or_else(|| "discovery.domain is required for dns provider".to_string())?;
            let resolver = discovery
                .dns_resolver
                .clone()
                .unwrap_or_else(|| "127.0.0.1:53".to_string())
                .parse::<std::net::SocketAddr>()
                .map_err(|e| format!("invalid dns_resolver: {e}"))?;
            // A 记录模式沿用静态端点里的端口作为默认端口
            let default_port = upstream
                .endpoints
                .first()
                .map(|ep| ep.port)
                .unwrap_or(80);
            let kind = match discovery.dns_record {
                DnsRecordKind::A => DnsQueryKind::Address,
                DnsRecordKind::Srv => DnsQueryKind::Srv,
            };
            Ok(Arc::new(DnsDiscoveryProvider::new(DnsDiscoveryConfig {
                domain,
                default_port,
                resolver,
                timeout: Duration::from_secs(3),
                kind,
            })))
        },

        DiscoveryProviderKind::Kubernetes => {
            let namespace = discovery
                .namespace
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "discovery.namespace is required for kubernetes provider".to_string())?;
            let service = discovery
                .service
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "discovery.service is required for kubernetes provider".to_string())?;

            // 以 in_cluster 的默认值为基线，再用显式配置覆盖
            let mut config = K8sDiscoveryConfig::in_cluster(namespace, service);
            config.port_name = discovery.port_name.clone();
            config.refresh_interval = Duration::from_secs(discovery.refresh_interval_secs.max(1));
            if let Some(api) = discovery.api_server.clone().filter(|v| !v.is_empty()) {
                config.api_server = api;
            }
            if let Some(token) = discovery.token_file.clone().filter(|v| !v.is_empty()) {
                config.token_file = token;
            }
            if let Some(ca) = discovery.ca_file.clone().filter(|v| !v.is_empty()) {
                config.ca_file = Some(ca);
            }

            let provider = K8sDiscoveryProvider::new(config)
                .map_err(|e| format!("k8s provider init failed: {e}"))?;
            Ok(Arc::new(provider))
        },
    }
}
