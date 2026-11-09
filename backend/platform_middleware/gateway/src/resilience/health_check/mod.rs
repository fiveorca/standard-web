//! 健康检查：Liveness / Readiness 与依赖状态。
//!
//! Readiness 检查不会阻塞代理主流程：结果会被短暂缓存，
//! 依赖探测本身带有超时。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::Serialize;

/// 依赖健康检查接口。
#[async_trait]
pub trait HealthCheck: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self) -> Result<(), String>;
}

/// 依赖状态。
#[derive(Debug, Clone, Serialize)]
pub struct DependencyStatus {
    pub name: String,
    pub healthy: bool,
    pub message: Option<String>,
    pub latency_ms: u128,
}

/// 就绪状态。
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessStatus {
    pub ready: bool,
    pub initialized: bool,
    pub draining: bool,
    pub uptime_seconds: u64,
    pub dependencies: Vec<DependencyStatus>,
}

/// 健康检查注册表。
pub struct HealthRegistry {
    started_at: Instant,
    initialized: AtomicBool,
    draining: AtomicBool,
    checks: Vec<Arc<dyn HealthCheck>>,
    cache: DashMap<String, (Instant, DependencyStatus)>,
    cache_ttl: Duration,
    timeout: Duration,
}

use std::sync::Arc;

impl HealthRegistry {
    pub fn new(checks: Vec<Arc<dyn HealthCheck>>) -> Self {
        Self {
            started_at: Instant::now(),
            initialized: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            checks,
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(3),
            timeout: Duration::from_secs(2),
        }
    }

    pub fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::SeqCst);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }

    pub fn mark_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// 存活检查：进程存活即通过。
    pub fn liveness(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "uptime_seconds": self.started_at.elapsed().as_secs(),
        })
    }

    /// 就绪检查：完成初始化且所有依赖可用。
    pub async fn readiness(&self) -> ReadinessStatus {
        let mut dependencies = Vec::with_capacity(self.checks.len());
        for check in &self.checks {
            let name = check.name().to_string();
            if let Some(entry) = self.cache.get(&name) {
                if entry.0.elapsed() < self.cache_ttl {
                    dependencies.push(entry.1.clone());
                    continue;
                }
            }
            let started = Instant::now();
            let result = tokio::time::timeout(self.timeout, check.check()).await;
            let status = match result {
                Ok(Ok(())) => DependencyStatus {
                    name: name.clone(),
                    healthy: true,
                    message: None,
                    latency_ms: started.elapsed().as_millis(),
                },
                Ok(Err(err)) => DependencyStatus {
                    name: name.clone(),
                    healthy: false,
                    message: Some(err),
                    latency_ms: started.elapsed().as_millis(),
                },
                Err(_) => DependencyStatus {
                    name: name.clone(),
                    healthy: false,
                    message: Some("health check timed out".to_string()),
                    latency_ms: started.elapsed().as_millis(),
                },
            };
            self.cache.insert(name, (Instant::now(), status.clone()));
            dependencies.push(status);
        }

        let initialized = self.is_initialized();
        let draining = self.is_draining();
        let ready = initialized && !draining && dependencies.iter().all(|d| d.healthy);
        ReadinessStatus {
            ready,
            initialized,
            draining,
            uptime_seconds: self.started_at.elapsed().as_secs(),
            dependencies,
        }
    }
}

/// 简单的 TCP 连通性检查。
pub struct TcpHealthCheck {
    name: String,
    host: String,
    port: u16,
}

impl TcpHealthCheck {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
        }
    }
}

#[async_trait]
impl HealthCheck for TcpHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> Result<(), String> {
        match tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("tcp connect failed: {err}")),
        }
    }
}

/// 由闭包定义的依赖检查。
pub struct FnHealthCheck {
    name: String,
    check: Box<dyn Fn() -> futures::future::BoxFuture<'static, Result<(), String>> + Send + Sync>,
}

impl FnHealthCheck {
    pub fn new<F, Fut>(name: impl Into<String>, check: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            name: name.into(),
            check: Box::new(move || Box::pin(check())),
        }
    }
}

#[async_trait]
impl HealthCheck for FnHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> Result<(), String> {
        (self.check)().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_requires_initialization() {
        let registry = HealthRegistry::new(vec![]);
        assert!(!registry.readiness().await.ready);
        registry.mark_initialized();
        assert!(registry.readiness().await.ready);
        registry.mark_draining();
        assert!(!registry.readiness().await.ready);
    }

    #[tokio::test]
    async fn failing_dependency_blocks_readiness() {
        let check = FnHealthCheck::new("redis", || async { Err("down".to_string()) });
        let registry = HealthRegistry::new(vec![Arc::new(check)]);
        registry.mark_initialized();
        let status = registry.readiness().await;
        assert!(!status.ready);
        assert!(!status.dependencies[0].healthy);
    }
}
