//! 启动装配：加载配置、初始化可观测性、构建运行时、启动监听与优雅关闭。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::Router;
use tokio::sync::watch;

use crate::admin::{AdminState, ConfigSync};
use crate::config::loader;
use crate::config::model::{GatewayConfig, RedisConfig};
use crate::config::validate::validate;
use crate::core::filter::FilterRegistry;
use crate::core::gateway::{Gateway, GatewayOptions};
use crate::observability::logging;
use crate::observability::metrics::Metrics;
use crate::observability::tracing::{shutdown as shutdown_tracing, TracingState};
use crate::resilience::health_check::{FnHealthCheck, HealthRegistry};
use crate::transport;

/// 运行参数。
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// 配置目录，包含 `gateway.yaml` / `routes.yaml` / `{profile}.yaml`。
    pub config_dir: PathBuf,
    /// 环境 profile。
    pub profile: Option<String>,
    /// 配置文件轮询间隔；`None` 表示关闭热加载轮询。
    pub reload_interval: Option<Duration>,
}

impl RunOptions {
    pub fn new(config_dir: impl Into<PathBuf>, profile: Option<String>) -> Self {
        Self {
            config_dir: config_dir.into(),
            profile,
            reload_interval: Some(Duration::from_secs(5)),
        }
    }
}

/// 启动网关，直到收到关闭信号。
pub async fn run(options: RunOptions) -> Result<()> {
    transport::install_crypto_provider();

    let loaded = loader::load(&options.config_dir, options.profile.as_deref())
        .await
        .context("failed to load configuration")?;
    let config = loaded.config.clone();

    logging::init(&config.gateway.logging);
    tracing::info!(
        version = crate::VERSION,
        config_dir = %loaded.root_dir.display(),
        profile = options.profile.as_deref().unwrap_or("default"),
        "starting rust api gateway"
    );

    let report = validate(&config, &FilterRegistry::builtin());
    for warning in report.warnings() {
        tracing::warn!(field = %warning.field, message = %warning.message, "configuration warning");
    }
    if report.has_errors() {
        let details = report
            .errors()
            .map(|issue| format!("{}: {}", issue.field, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow!("invalid configuration: {details}"));
    }

    let (tracing_state, tracer_provider) = TracingState::init(&config.gateway.tracing);
    let tracing_state = Arc::new(tracing_state);

    let metrics = Metrics::new().context("failed to initialize metrics")?;

    let health = Arc::new(HealthRegistry::new(health_checks(&config).await));
    let gateway = Gateway::build(
        config.clone(),
        GatewayOptions::new(
            metrics.clone(),
            health.clone(),
            tracing_state.clone(),
            loaded.hash.clone(),
        ),
    )
    .await
    .map_err(|e| anyhow!("failed to build gateway: {e}"))?;
    let gateway = Arc::new(gateway);

    let node_id = node_id(&config);
    let sync = if config.gateway.redis.url.trim().is_empty() {
        None
    } else {
        match ConfigSync::new(
            &config.gateway.redis.url,
            &gateway_channel(&config),
            &node_id,
        ) {
            Ok(sync) => {
                let sync = Arc::new(sync);
                sync.clone()
                    .spawn_subscriber(gateway.route_table.clone(), gateway.state.clone());
                Some(sync)
            }
            Err(err) => {
                tracing::warn!(error = %err, "config sync disabled");
                None
            }
        }
    };

    let mut handles: Vec<tokio::task::JoinHandle<Result<()>>> = Vec::new();

    // 业务服务器。
    let business_addr = resolve_addr(&config.gateway.server.host, config.gateway.server.port)?;
    let business_tls = if config.gateway.server.tls.enabled {
        Some(
            transport::build_server_tls(&config.gateway.server.tls)
                .context("failed to build server TLS configuration")?,
        )
    } else {
        None
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    handles.push(tokio::spawn(transport::serve(
        business_addr,
        gateway.router(),
        business_tls,
        metrics.clone(),
        shutdown_rx.clone(),
        config.gateway.server.graceful_shutdown_timeout,
    )));

    // 管理服务器。
    if config.gateway.admin.enabled {
        let admin_state = AdminState::new(
            gateway.state.clone(),
            gateway.route_table.clone(),
            gateway.upstreams.clone(),
            loaded.root_dir.clone(),
            options.profile.clone(),
            sync,
            node_id.clone(),
        );
        let admin_router: Router = crate::admin::router(admin_state);
        let admin_addr = resolve_addr(&config.gateway.admin.host, config.gateway.admin.port)?;
        if admin_addr == business_addr {
            return Err(anyhow!(
                "admin listener must not share the same address as the business listener ({admin_addr})"
            ));
        }
        handles.push(tokio::spawn(transport::serve(
            admin_addr,
            admin_router,
            None,
            metrics.clone(),
            shutdown_rx,
            config.gateway.server.graceful_shutdown_timeout,
        )));
    }

    // 配置文件热加载轮询。
    if let Some(interval) = options.reload_interval {
        let route_table = gateway.route_table.clone();
        let state = gateway.state.clone();
        let root = loaded.root_dir.clone();
        let profile = options.profile.clone();
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match loader::load(&root, profile.as_deref()).await {
                    Ok(next) => {
                        if next.hash == route_table.snapshot().hash {
                            continue;
                        }
                        if validate(&next.config, &FilterRegistry::builtin()).has_errors() {
                            tracing::warn!("configuration file changed but failed validation; keeping current routes");
                            continue;
                        }
                        match route_table.replace(next.config.clone(), next.hash.clone()) {
                            Ok(version) => {
                                if let Err(err) = state.reload_derived(&next.config) {
                                    tracing::warn!(error = %err, "failed to rebuild derived components");
                                }
                                tracing::info!(version, "configuration reloaded from disk");
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to apply reloaded configuration")
                            }
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "configuration reload failed"),
                }
            }
            #[allow(unreachable_code)]
            Ok(())
        }));
    }

    health.mark_initialized();
    tracing::info!(
        address = %business_addr,
        tls = config.gateway.server.tls.enabled,
        admin = config.gateway.admin.enabled,
        routes = gateway.route_table.snapshot().routes.len(),
        "gateway is ready"
    );

    wait_for_shutdown().await;
    tracing::info!("shutdown signal received; draining");

    health.mark_draining();
    let _ = shutdown_tx.send(true);

    let deadline = config.gateway.server.graceful_shutdown_timeout + Duration::from_secs(5);
    for handle in handles {
        match tokio::time::timeout(deadline, handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => tracing::warn!(error = %err, "server stopped with error"),
            Ok(Err(err)) => tracing::warn!(error = %err, "server task failed"),
            Err(_) => tracing::warn!("timed out waiting for server shutdown"),
        }
    }

    gateway.upstreams.shutdown();
    shutdown_tracing(tracer_provider);
    tracing::info!("gateway stopped");
    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// 构建依赖健康检查。
async fn health_checks(
    config: &GatewayConfig,
) -> Vec<Arc<dyn crate::resilience::health_check::HealthCheck>> {
    let mut checks: Vec<Arc<dyn crate::resilience::health_check::HealthCheck>> = Vec::new();

    if !config.gateway.redis.url.trim().is_empty() {
        checks.push(Arc::new(redis_health_check(config.gateway.redis.clone())));
    }

    if let Some(consul) = &config.gateway.service_discovery.consul {
        if let Some((host, port)) = parse_host_port(&consul.address) {
            checks.push(Arc::new(
                crate::resilience::health_check::TcpHealthCheck::new("consul", host, port),
            ));
        }
    }

    checks
}

fn redis_health_check(config: RedisConfig) -> FnHealthCheck {
    FnHealthCheck::new("redis", move || {
        let url = config.url.clone();
        async move {
            let client = redis::Client::open(url).map_err(|e| format!("invalid redis url: {e}"))?;
            let mut conn = tokio::time::timeout(
                Duration::from_secs(2),
                client.get_multiplexed_async_connection(),
            )
            .await
            .map_err(|_| "redis connect timed out".to_string())?
            .map_err(|e| format!("redis connect failed: {e}"))?;
            let pong: String = tokio::time::timeout(
                Duration::from_secs(2),
                redis::cmd("PING").query_async(&mut conn),
            )
            .await
            .map_err(|_| "redis ping timed out".to_string())?
            .map_err(|e| format!("redis ping failed: {e}"))?;
            if pong.eq_ignore_ascii_case("PONG") {
                Ok(())
            } else {
                Err(format!("unexpected redis response: {pong}"))
            }
        }
    })
}

fn gateway_channel(config: &GatewayConfig) -> String {
    if config.gateway.redis.channel.trim().is_empty() {
        "gateway:config".to_string()
    } else {
        config.gateway.redis.channel.clone()
    }
}

fn node_id(config: &GatewayConfig) -> String {
    std::env::var("GATEWAY_NODE_ID").unwrap_or_else(|_| {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "gateway".to_string());
        let port = config.gateway.server.port;
        format!("{host}-{port}")
    })
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .with_context(|| format!("cannot resolve `{host}:{port}`"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address found for `{host}:{port}`"))
}

fn parse_host_port(address: &str) -> Option<(String, u16)> {
    let trimmed = address
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let mut parts = trimmed.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?.to_string();
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_consul_address() {
        assert_eq!(
            parse_host_port("http://127.0.0.1:8500"),
            Some(("127.0.0.1".to_string(), 8500))
        );
        assert_eq!(
            parse_host_port("127.0.0.1:8500/"),
            Some(("127.0.0.1".to_string(), 8500))
        );
    }

    #[test]
    fn default_channel() {
        let config = GatewayConfig::default();
        assert_eq!(gateway_channel(&config), "gateway:config");
    }
}
