//! gateway-control 启动流程。
//!
//! 步骤：
//!   1. 初始化日志
//!   2. 选择仓储（PostgreSQL / 内存）
//!   3. 构建 Admin 认证（静态 Token 清单）
//!   4. 启动 Admin API，等待 Ctrl-C / SIGTERM 优雅关闭

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use gateway_control_api::{build_admin_router, AdminAuth, AdminState, Role};
use gateway_control_service::ConfigService;
use gateway_observability::init_logging;
use gateway_storage::{
    connect_and_migrate, MemoryRepository, PoolSettings, PostgresRepository, SharedRepository,
};

use crate::cli::Cli;

/// 执行启动。
pub async fn run(cli: Cli) -> Result<()> {
    // 1. 日志：JSON 格式输出到 stderr
    init_logging(&cli.log_level, "json");

    // 2. 仓储选择：显式 --memory 才允许无数据库运行，避免误用导致配置丢失
    let repo: SharedRepository = match (&cli.database_url, cli.memory) {
        (Some(url), false) => {
            let pool = connect_and_migrate(url, PoolSettings::default())
                .await
                .context("failed to connect control-plane database")?;
            Arc::new(PostgresRepository::new(pool))
        },
        (None, true) => {
            tracing::warn!("using in-memory repository: configuration is lost on restart");
            Arc::new(MemoryRepository::new())
        },
        (Some(_), true) => {
            return Err(anyhow!(
                "--database-url and --memory are mutually exclusive"
            ))
        },
        (None, false) => {
            return Err(anyhow!(
                "either --database-url (GATEWAY_DATABASE_URL) or --memory is required"
            ))
        },
    };

    // 3. 认证：至少配置一个 admin token；viewer 可选
    let mut auth = AdminAuth::empty();
    if let Some(spec) = &cli.admin_tokens {
        auth.add_spec(spec, "admin", Role::Admin);
    }
    if let Some(spec) = &cli.viewer_tokens {
        auth.add_spec(spec, "viewer", Role::Viewer);
    }
    if !auth.is_configured() {
        return Err(anyhow!(
            "at least one admin token is required (GATEWAY_ADMIN_TOKENS)"
        ));
    }

    // 4. 构建 Router 并启动
    let service = ConfigService::new(repo);
    let app = build_admin_router(AdminState::new(service, auth));

    let addr: SocketAddr = cli
        .bind
        .parse()
        .with_context(|| format!("invalid bind address '{}'", cli.bind))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    tracing::info!(%addr, "gateway-control listening on /api/admin/v1");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("admin server failed")?;

    tracing::info!("gateway-control stopped");
    Ok(())
}

/// 等待 Ctrl-C 或 SIGTERM。
///
/// 控制面是管理进程，必须支持 systemd/容器发送 SIGTERM 后优雅退出。
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to listen for Ctrl-C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            },
            Err(err) => {
                tracing::error!(error = %err, "failed to listen for SIGTERM");
                // 监听失败时保持挂起，避免立即触发关闭
                std::future::pending::<()>().await;
            },
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
