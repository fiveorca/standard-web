// ! Logserver 统一日志服务入口
//
// 支持三种运行模式: api | worker | all

use clap::Parser;
use logserver::application::analytics::AnalyticsService;
use logserver::application::ingestion::IngestionService;
use logserver::application::query::QueryService;
use logserver::config::AppConfig;
use logserver::infrastructure::clickhouse::ClickHouse;
use logserver::infrastructure::kafka::producer::LogProducer;
use logserver::observability;
use logserver::transport::grpc::ingestion::{into_tonic_service, LogIngestionServiceImpl};
use logserver::transport::http::handlers::AppState;
use logserver::transport::http::routes;
use logserver::worker::consumer_loop::run_consumer_loop;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "logserver", version, about = "Unified Log Service")]
struct Cli {
    /// 运行模式: api | worker | all
    #[arg(long, default_value = "all")]
    mode: Option<String>,

    /// 配置文件路径 (TOML)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    observability::init_tracing();
    observability::register_all();

    let cli = Cli::parse();

    let mut cfg = AppConfig::load(cli.config.as_deref())?;
    // CLI mode 覆盖配置文件
    if let Some(m) = cli.mode {
        cfg.server.mode = m;
    }

    info!(mode = %cfg.server.mode, "启动 Logserver");

    let app_cfg = Arc::new(cfg);

    let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

    if app_cfg.is_api_mode() {
        let h = tokio::spawn({
            let cfg = app_cfg.clone();
            async move { run_api(cfg).await }
        });
        handles.push(h);
    }

    if app_cfg.is_worker_mode() {
        let h = tokio::spawn({
            let cfg = app_cfg.clone();
            async move { run_worker(cfg).await }
        });
        handles.push(h);
    }

    if handles.is_empty() {
        anyhow::bail!(
            "mode 无效: {}, 支持 api / worker / all",
            app_cfg.server.mode
        );
    }

    // 等待任一任务结束或 Ctrl+C
    let _result = tokio::select! {
        _ = signal::ctrl_c() => {
            info!("收到 Ctrl+C，退出");
            "ctrl_c"
        }
        _res = futures::future::select_all(handles) => {
            info!("子任务结束");
            "task_done"
        }
    };

    Ok(())
}

async fn run_api(cfg: Arc<AppConfig>) -> anyhow::Result<()> {
    info!("=== API 模式启动 ===");

    // ---- 基础设施 ----
    let producer = LogProducer::new(&cfg.kafka)?;
    let db = Arc::new(ClickHouse::new(&cfg.clickhouse));

    // ClickHouse 启动前 ping (失败不阻塞)
    if let Err(e) = db.ping().await {
        tracing::warn!(?e, "ClickHouse ping 失败 (API 模式)，仍继续启动");
    } else {
        info!("ClickHouse 连通");
    }

    let db_clone: ClickHouse = (*db).clone();

    // ---- Application 层 ----
    let ingestion = IngestionService::new(producer, cfg.security.clone());

    // 泄漏 db 让 repo 拥有 'static 生命周期 (进程内复用，可接受)
    let db_static: &'static ClickHouse = Box::leak(Box::new(db_clone));
    let repo = logserver::infrastructure::clickhouse::repository::LogRepository::new(db_static);

    let query = QueryService::new(repo, cfg.query.clone());
    let analytics = AnalyticsService::new(
        logserver::infrastructure::clickhouse::repository::LogRepository::new(db_static),
    );

    // ---- HTTP ----
    let http_addr: std::net::SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port).parse()?;
    let http_state = AppState {
        query: Arc::new(query),
        analytics: Arc::new(analytics),
    };
    let http_router = routes::build_router(http_state);

    let http_handle = tokio::spawn(async move {
        info!(addr = %http_addr, "Axum HTTP 监听");
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_router).await.unwrap();
    });

    // ---- gRPC ----
    let grpc_addr: std::net::SocketAddr = format!("{}:{}", cfg.grpc.host, cfg.grpc.port).parse()?;
    let grpc_impl = Arc::new(LogIngestionServiceImpl::new(ingestion, cfg.grpc_limits.clone()));
    let grpc_svc = into_tonic_service(grpc_impl);
    let grpc_handle = tokio::spawn(async move {
        info!(addr = %grpc_addr, "Tonic gRPC 监听");
        tonic::transport::Server::builder()
            .add_service(grpc_svc)
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    // ---- Metrics 端点 (单独端口) ----
    let metrics_addr: std::net::SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port + 1)
        .parse()
        .unwrap();
    let metrics_handle = tokio::spawn(async move {
        info!(addr = %metrics_addr, "Prometheus metrics 监听");
        let router = axum::Router::new().route(
            "/metrics",
            axum::routing::get(|| async { observability::encode() }),
        );
        let listener = tokio::net::TcpListener::bind(metrics_addr).await.unwrap();
        axum::serve(listener, router).await.unwrap();
    });

    tokio::select! {
        _ = http_handle => {},
        _ = grpc_handle => {},
        _ = metrics_handle => {},
    }

    Ok(())
}

async fn run_worker(cfg: Arc<AppConfig>) -> anyhow::Result<()> {
    info!("=== Worker 模式启动 ===");
    run_consumer_loop(
        &cfg.kafka,
        &cfg.clickhouse,
        cfg.batch.clone(),
        cfg.security.clone(),
    )
    .await
    .map_err(anyhow::Error::from)
}
