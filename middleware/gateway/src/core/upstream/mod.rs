//! 上游服务注册表：服务发现、负载均衡、实例健康状态与被动熔断。
//!
//! 该模块把「服务名 → 实例列表 → 具体 HTTP 目标」的解析过程与代理层解耦。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::task::JoinHandle;

use crate::config::model::{GatewayConfig, HealthCheckConfig, LbStrategy, ServiceConfig};
use crate::core::load_balancer::{self, CandidateView, LoadBalancer};
use crate::core::service_discovery::{
    DiscoveryError, DiscoveryProviders, ServiceDiscovery, ServiceInstance,
};
use crate::error::GatewayError;
use crate::observability::metrics::Metrics;
use crate::utils::unix_millis;

/// 运行期实例状态。
#[derive(Debug)]
pub struct InstanceRuntime {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub weight: AtomicU32,
    pub metadata: HashMap<String, String>,
    /// 主动健康检查结果。
    pub healthy: AtomicBool,
    /// 被动熔断：在该时间点之前不再选择该实例。
    pub passive_until_ms: AtomicU64,
    pub in_flight: AtomicUsize,
    pub consecutive_failures: AtomicU32,
    pub consecutive_successes: AtomicU32,
    pub total_requests: AtomicU64,
    pub total_failures: AtomicU64,
}

impl InstanceRuntime {
    pub fn from_instance(instance: &ServiceInstance) -> Self {
        Self {
            id: instance.id.clone(),
            host: instance.host.clone(),
            port: instance.port,
            secure: instance.secure,
            weight: AtomicU32::new(instance.weight.max(1)),
            metadata: instance.metadata.clone(),
            healthy: AtomicBool::new(true),
            passive_until_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn scheme(&self) -> &'static str {
        if self.secure {
            "https"
        } else {
            "http"
        }
    }

    pub fn available(&self, now_ms: u64) -> bool {
        if !self.healthy.load(Ordering::Relaxed) {
            return false;
        }
        now_ms >= self.passive_until_ms.load(Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.passive_until_ms.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self, threshold: u32, recovery: Duration) -> bool {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= threshold.max(1) {
            let until = unix_millis() as u64 + recovery.as_millis() as u64;
            self.passive_until_ms.store(until, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// 增加在途计数，返回 RAII 守卫。
    pub fn acquire(self: &Arc<Self>) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        InFlightGuard {
            instance: self.clone(),
        }
    }
}

/// 在途请求守卫。
pub struct InFlightGuard {
    instance: Arc<InstanceRuntime>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.instance.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 解析后的上游目标。
#[derive(Debug, Clone)]
pub struct Target {
    pub scheme: String,
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub base_path: String,
    pub instance: Option<Arc<InstanceRuntime>>,
    pub service: Option<String>,
}

impl Target {
    /// 组合最终的上游路径。
    pub fn join_path(&self, path: &str) -> String {
        let base = self.base_path.trim_end_matches('/');
        let mut combined = String::with_capacity(base.len() + path.len() + 1);
        combined.push_str(base);
        if !path.starts_with('/') {
            combined.push('/');
        }
        combined.push_str(path);
        if combined.is_empty() {
            combined.push('/');
        }
        combined
    }

    pub fn authority_uri(&self) -> String {
        format!("{}://{}", self.scheme, self.authority)
    }
}

/// 上游服务。
pub struct UpstreamService {
    pub name: String,
    pub consul_service: String,
    pub discovery: Arc<dyn ServiceDiscovery>,
    pub discovery_kind: String,
    instances: ArcSwap<Vec<Arc<InstanceRuntime>>>,
    lbs: DashMap<LbStrategy, Arc<dyn LoadBalancer>>,
    default_strategy: LbStrategy,
    health_check: Option<HealthCheckConfig>,
    last_refresh_at: Mutex<Option<Instant>>,
    last_refresh_ok: AtomicBool,
    last_error: Mutex<Option<String>>,
    discovery_calls: AtomicU64,
}

impl UpstreamService {
    fn new(
        name: String,
        consul_service: String,
        discovery: Arc<dyn ServiceDiscovery>,
        discovery_kind: String,
        strategy: LbStrategy,
        health_check: Option<HealthCheckConfig>,
        instances: Vec<Arc<InstanceRuntime>>,
    ) -> Self {
        let lbs = DashMap::new();
        lbs.insert(strategy, Arc::from(load_balancer::create(strategy)));
        Self {
            name,
            consul_service,
            discovery,
            discovery_kind,
            instances: ArcSwap::from_pointee(instances),
            lbs,
            default_strategy: strategy,
            health_check,
            last_refresh_at: Mutex::new(None),
            last_refresh_ok: AtomicBool::new(true),
            last_error: Mutex::new(None),
            discovery_calls: AtomicU64::new(0),
        }
    }

    pub fn load_balancer(&self, strategy: Option<LbStrategy>) -> Arc<dyn LoadBalancer> {
        let strategy = strategy.unwrap_or(self.default_strategy);
        if let Some(lb) = self.lbs.get(&strategy) {
            return lb.clone();
        }
        let lb: Arc<dyn LoadBalancer> = Arc::from(load_balancer::create(strategy));
        self.lbs.insert(strategy, lb.clone());
        lb
    }

    /// 选择实例。
    pub fn pick(&self, strategy: Option<LbStrategy>) -> Option<Arc<InstanceRuntime>> {
        let instances = self.instances.load_full();
        let now = unix_millis() as u64;
        let available: Vec<Arc<InstanceRuntime>> = instances
            .iter()
            .filter(|i| i.available(now))
            .cloned()
            .collect();
        if available.is_empty() {
            return None;
        }
        let view: Vec<CandidateView> = available
            .iter()
            .map(|i| CandidateView {
                weight: i.weight.load(Ordering::Relaxed),
                in_flight: i.in_flight.load(Ordering::Relaxed),
            })
            .collect();
        let lb = self.load_balancer(strategy);
        lb.pick(&view).map(|idx| available[idx].clone())
    }

    fn apply_discovered(&self, discovered: Vec<ServiceInstance>) {
        let previous = self.instances.load_full();
        let existing: HashMap<&str, &Arc<InstanceRuntime>> =
            previous.iter().map(|i| (i.id.as_str(), i)).collect();
        let mut next = Vec::with_capacity(discovered.len());
        for instance in discovered {
            match existing.get(instance.id.as_str()) {
                Some(existing) => {
                    existing
                        .weight
                        .store(instance.weight.max(1), Ordering::Relaxed);
                    next.push((*existing).clone());
                }
                None => next.push(Arc::new(InstanceRuntime::from_instance(&instance))),
            }
        }
        self.instances.store(Arc::new(next));
        self.last_refresh_ok.store(true, Ordering::Relaxed);
        *self
            .last_refresh_at
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    fn record_discovery_error(&self, err: &DiscoveryError) {
        self.last_refresh_ok.store(false, Ordering::Relaxed);
        *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(err.to_string());
        self.last_refresh_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(Instant::now());
    }

    pub fn healthy_count(&self) -> (usize, usize) {
        let instances = self.instances.load_full();
        let now = unix_millis() as u64;
        let healthy = instances.iter().filter(|i| i.available(now)).count();
        (healthy, instances.len())
    }

    pub fn snapshot(&self) -> UpstreamSnapshot {
        let instances = self.instances.load_full();
        let now = unix_millis() as u64;
        UpstreamSnapshot {
            name: self.name.clone(),
            discovery: self.discovery_kind.clone(),
            strategy: self.default_strategy,
            last_refresh: self
                .last_refresh_at
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .map(|i| i.elapsed().as_secs_f64()),
            healthy: self.last_refresh_ok.load(Ordering::Relaxed),
            error: self
                .last_error
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
            discovery_calls: self.discovery_calls.load(Ordering::Relaxed),
            instances: instances
                .iter()
                .map(|i| InstanceSnapshot {
                    id: i.id.clone(),
                    uri: format!("{}://{}", i.scheme(), i.authority()),
                    weight: i.weight.load(Ordering::Relaxed),
                    healthy: i.available(now),
                    in_flight: i.in_flight.load(Ordering::Relaxed),
                    total_requests: i.total_requests.load(Ordering::Relaxed),
                    total_failures: i.total_failures.load(Ordering::Relaxed),
                })
                .collect(),
        }
    }
}

/// 上游服务快照（管理 API）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpstreamSnapshot {
    pub name: String,
    pub discovery: String,
    pub strategy: LbStrategy,
    pub last_refresh: Option<f64>,
    pub healthy: bool,
    pub error: Option<String>,
    pub discovery_calls: u64,
    pub instances: Vec<InstanceSnapshot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstanceSnapshot {
    pub id: String,
    pub uri: String,
    pub weight: u32,
    pub healthy: bool,
    pub in_flight: usize,
    pub total_requests: u64,
    pub total_failures: u64,
}

/// 上游注册表。
pub struct UpstreamRegistry {
    services: DashMap<String, Arc<UpstreamService>>,
    providers: Arc<DiscoveryProviders>,
    metrics: Arc<Metrics>,
    default_strategy: LbStrategy,
    refresh_interval: Duration,
    passive_failure_threshold: u32,
    passive_recovery: Duration,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown: AtomicBool,
    http_client: reqwest::Client,
}

impl UpstreamRegistry {
    pub async fn new(
        config: &GatewayConfig,
        providers: Arc<DiscoveryProviders>,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<Self>, String> {
        let default_strategy = config.gateway.load_balancer.strategy;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| format!("failed to build health check client: {e}"))?;

        let registry = Arc::new(Self {
            services: DashMap::new(),
            providers,
            metrics,
            default_strategy,
            refresh_interval: config.gateway.service_discovery.refresh_interval,
            passive_failure_threshold: 3,
            passive_recovery: Duration::from_secs(5),
            tasks: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
            http_client: client,
        });

        // 初始化配置中声明的服务。
        for (name, service_config) in &config.gateway.services {
            registry.register_service(name, service_config).await?;
        }

        Ok(registry)
    }

    async fn register_service(
        &self,
        name: &str,
        config: &ServiceConfig,
    ) -> Result<Arc<UpstreamService>, String> {
        let kind = config.discovery.clone();
        let discovery = self
            .providers
            .provider(&kind)
            .ok_or_else(|| format!("service `{name}` uses unsupported discovery `{kind}`"))?;
        let consul_service = config
            .consul_service
            .clone()
            .unwrap_or_else(|| name.to_string());

        let mut initial = Vec::new();
        if kind == "static" {
            let instances = discovery
                .discover(name)
                .await
                .map_err(|e| format!("service `{name}` discovery failed: {e}"))?;
            initial = instances
                .iter()
                .map(|i| Arc::new(InstanceRuntime::from_instance(i)))
                .collect();
        }

        let service = Arc::new(UpstreamService::new(
            name.to_string(),
            consul_service,
            discovery,
            kind,
            config.load_balancer.unwrap_or(self.default_strategy),
            config.health_check.clone(),
            initial,
        ));
        self.services.insert(name.to_string(), service.clone());
        Ok(service)
    }

    /// 启动后台刷新与健康检查任务。
    pub fn start(self: &Arc<Self>) {
        let registry = self.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(registry.refresh_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if registry.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                registry.refresh_all().await;
            }
        });
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(handle);

        let services: Vec<Arc<UpstreamService>> = self
            .services
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for service in services {
            if let Some(cfg) = service.health_check.clone() {
                if cfg.enabled {
                    let handle = spawn_health_check(
                        self.clone(),
                        service.clone(),
                        cfg,
                        self.http_client.clone(),
                    );
                    self.tasks
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(handle);
                }
            }
        }
    }

    pub async fn refresh_all(self: &Arc<Self>) {
        let services: Vec<Arc<UpstreamService>> = self
            .services
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for service in services {
            if service.discovery_kind == "static" {
                continue;
            }
            let _ = self.refresh(&service).await;
        }
    }

    async fn refresh(&self, service: &Arc<UpstreamService>) -> Result<(), DiscoveryError> {
        service.discovery_calls.fetch_add(1, Ordering::Relaxed);
        match service.discovery.discover(&service.consul_service).await {
            Ok(instances) => {
                service.apply_discovered(instances);
                self.metrics.set_discovery_up(&service.name, true);
                let (healthy, total) = service.healthy_count();
                self.metrics
                    .set_service_instances(&service.name, healthy, total);
                Ok(())
            }
            Err(err) => {
                service.record_discovery_error(&err);
                self.metrics.set_discovery_up(&service.name, false);
                Err(err)
            }
        }
    }

    /// 确保服务存在（懒加载 Consul 服务）。
    async fn ensure_service(&self, name: &str) -> Result<Arc<UpstreamService>, GatewayError> {
        if let Some(service) = self.services.get(name) {
            return Ok(service.clone());
        }
        let Some(consul) = &self.providers.consul else {
            return Err(GatewayError::ServiceUnavailable(format!(
                "unknown service `{name}` and no consul discovery configured"
            )));
        };
        let service = Arc::new(UpstreamService::new(
            name.to_string(),
            name.to_string(),
            consul.clone(),
            "consul".to_string(),
            self.default_strategy,
            None,
            Vec::new(),
        ));
        self.services.insert(name.to_string(), service.clone());
        if let Err(err) = self.refresh(&service).await {
            if !matches!(err, DiscoveryError::NotFound(_)) {
                return Err(GatewayError::ServiceUnavailable(format!(
                    "service discovery failed for `{name}`: {err}"
                )));
            }
        }
        Ok(service)
    }

    /// 解析路由 URI 到具体上游目标。
    pub async fn resolve(
        &self,
        uri: &str,
        strategy: Option<LbStrategy>,
    ) -> Result<Target, GatewayError> {
        if let Some(service_name) = uri.strip_prefix("lb://") {
            let service_name = service_name.trim_end_matches('/');
            if service_name.is_empty() {
                return Err(GatewayError::Config(
                    "lb:// uri requires a service name".into(),
                ));
            }
            let service = self.ensure_service(service_name).await?;
            if service.instances.load_full().is_empty() {
                // 立即触发一次刷新，避免首次请求因后台刷新周期而失败。
                let _ = self.refresh(&service).await;
            }
            let instance = service.pick(strategy).ok_or_else(|| {
                GatewayError::ServiceUnavailable(format!(
                    "no healthy instance available for service `{service_name}`"
                ))
            })?;
            return Ok(Target {
                scheme: instance.scheme().to_string(),
                authority: instance.authority(),
                host: instance.host.clone(),
                port: instance.port,
                secure: instance.secure,
                base_path: String::new(),
                instance: Some(instance),
                service: Some(service_name.to_string()),
            });
        }

        let parsed = url::Url::parse(uri)
            .map_err(|e| GatewayError::Config(format!("invalid upstream uri `{uri}`: {e}")))?;
        let scheme = parsed.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(GatewayError::Config(format!(
                "unsupported upstream scheme `{scheme}`"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| GatewayError::Config(format!("upstream uri `{uri}` has no host")))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let base_path = parsed.path().trim_end_matches('/').to_string();
        Ok(Target {
            scheme: scheme.clone(),
            authority,
            host,
            port,
            secure: scheme == "https",
            base_path,
            instance: None,
            service: None,
        })
    }

    /// 直接按服务名选择实例（供健康检查与测试使用）。
    pub fn service(&self, name: &str) -> Option<Arc<UpstreamService>> {
        self.services.get(name).map(|entry| entry.value().clone())
    }

    pub fn snapshots(&self) -> Vec<UpstreamSnapshot> {
        self.services
            .iter()
            .map(|entry| entry.value().snapshot())
            .collect()
    }

    pub fn service_names(&self) -> Vec<String> {
        self.services
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// 记录一次上游调用结果（被动健康检查）。
    pub fn record_result(&self, target: &Target, success: bool) {
        if let Some(instance) = &target.instance {
            if success {
                instance.record_success();
            } else {
                instance.record_failure(self.passive_failure_threshold, self.passive_recovery);
            }
            if let Some(service) = target
                .service
                .as_ref()
                .and_then(|name| self.services.get(name))
            {
                let (healthy, total) = service.healthy_count();
                self.metrics
                    .set_service_instances(&service.name, healthy, total);
            }
        }
        if let Some(service) = &target.service {
            self.metrics.record_upstream_result(service, success);
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

fn spawn_health_check(
    registry: Arc<UpstreamRegistry>,
    service: Arc<UpstreamService>,
    config: HealthCheckConfig,
    client: reqwest::Client,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if registry.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let instances = service.instances.load_full();
            for instance in instances.iter() {
                let ok = if config.tcp_only {
                    tokio::time::timeout(
                        config.timeout,
                        tokio::net::TcpStream::connect((instance.host.as_str(), instance.port)),
                    )
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                } else {
                    let url = format!(
                        "{}://{}{}",
                        instance.scheme(),
                        instance.authority(),
                        config.path
                    );
                    match tokio::time::timeout(config.timeout, client.get(&url).send()).await {
                        Ok(Ok(response)) => response.status().is_success(),
                        _ => false,
                    }
                };

                if ok {
                    instance.consecutive_failures.store(0, Ordering::Relaxed);
                    let successes = instance
                        .consecutive_successes
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    if successes >= config.healthy_threshold.max(1) {
                        instance.healthy.store(true, Ordering::Relaxed);
                    }
                } else {
                    instance.consecutive_successes.store(0, Ordering::Relaxed);
                    let failures = instance
                        .consecutive_failures
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    if failures >= config.unhealthy_threshold.max(1) {
                        instance.healthy.store(false, Ordering::Relaxed);
                    }
                }
            }
            let (healthy, total) = service.healthy_count();
            registry
                .metrics
                .set_service_instances(&service.name, healthy, total);
        }
    })
}
