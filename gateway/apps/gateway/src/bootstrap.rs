//! Bootstrap —— Runtime 启动封装。
//!
//! 处理从 CLI 参数到 Runtime 启动之间的所有步骤：
//!   - 解析运行模式（standalone / integrated）
//!   - 加载 + 校验配置
//!   - 执行 --check 模式（只校验不启动）
//!   - integrated 模式装配控制面并挂载到管理端口
//!   - 调用 Runtime::start_with_admin() 阻塞直到退出

use std::sync::Arc;
use std::time::Duration;

use gateway_control_grpc::{SyncClient, SyncOutcome};
use gateway_runtime::Runtime;

use crate::cli::Cli;

/// 执行 CLI 命令对应的动作。
///
/// # 返回
/// - `Ok(())`：正常退出（可能是 graceful shutdown）
/// - `Err(e)`：启动或运行期间发生致命错误
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 校验运行模式
    match cli.mode.as_str() {
        "standalone" | "integrated" => {},
        other => {
            return Err(format!(
                "unsupported mode '{other}' (expected 'standalone' or 'integrated')"
            )
            .into())
        },
    }

    // 2. --check 模式：只加载 + 校验，不启动
    if cli.check {
        return run_check(&cli.config);
    }

    // 3. 正常启动模式
    run_start(&cli.config, &cli.mode).await
}

/// 执行 --check 模式。
///
/// 只做 load + validate，不启动任何 Listener。
fn run_check(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match Runtime::load_from_path(config_path) {
        Ok(_rt) => {
            println!("✓ config valid: {config_path}");
            Ok(())
        },
        Err(errors) => {
            println!("✗ config invalid: {config_path}");
            for e in &errors {
                println!("  - {e}");
            }
            Err(format!("config has {} error(s)", errors.len()).into())
        },
    }
}

/// 执行正常启动。
async fn run_start(
    config_path: &str,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = match Runtime::load_from_path(config_path) {
        Ok(rt) => Arc::new(rt),
        Err(errors) => {
            eprintln!("config invalid:");
            for e in &errors {
                eprintln!("  - {e}");
            }
            return Err(format!("config has {} error(s)", errors.len()).into());
        },
    };

    // integrated 模式：装配控制面 Router，随后与数据面共享同一进程
    let extra_admin = if mode == "integrated" {
        Some(crate::control::build_integrated_router(&runtime).await?)
    } else {
        None
    };

    // 控制面配置分发（Phase 4）：control_plane.enabled 时启动后台同步任务
    if runtime.control_plane().enabled {
        spawn_control_plane_sync(runtime.clone());
    }

    // Runtime::start_with_admin 内部会阻塞直到 shutdown
    // 用 spawn 包一层，以便捕获 JoinError
    let rt_clone = runtime.clone();
    tokio::spawn(async move {
        if let Err(e) = rt_clone.start_with_admin(extra_admin).await {
            tracing::error!("runtime error: {e}");
        }
    })
    .await?;

    Ok(())
}

/// 启动控制面 gRPC 配置同步后台任务（Phase 4）。
///
/// 行为：
///   - 连接失败时按 `reconnect_interval_secs` 重连；
///   - 连接成功后注册实例，随后按 `heartbeat_interval_secs` 心跳；
///   - 有新版本时拉取快照并原子应用，应用失败上报 NACK 并保留旧配置；
///   - 控制面长期不可用不影响数据面继续用本地"最后已知良好配置"转发。
fn spawn_control_plane_sync(runtime: Arc<Runtime>) {
    let control_plane = runtime.control_plane().clone();

    // endpoint 为空说明配置错误，直接跳过而不是无限重试
    let Some(endpoint) = control_plane.endpoint.clone() else {
        tracing::warn!(
            "control_plane.enabled = true but endpoint is not configured; gRPC sync disabled"
        );
        return;
    };
    if endpoint.trim().is_empty() {
        tracing::warn!("control_plane.endpoint is empty; gRPC sync disabled");
        return;
    }

    // 实例标识 = gateway.id + instance_name，保证同一集群内唯一
    let instance_id = format!("{}-{}", runtime.gateway_id(), runtime.instance_name());
    let heartbeat = Duration::from_secs(control_plane.heartbeat_interval_secs.max(1));
    let reconnect = Duration::from_secs(control_plane.reconnect_interval_secs.max(1));

    tokio::spawn(async move {
        // 本地已应用的控制面版本；从 0 开始以便首次必定拉取
        let mut applied_version: u64 = 0;

        loop {
            // 1. 建立连接（失败则退避重连）
            let mut client = match SyncClient::connect(&endpoint, instance_id.clone()).await {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(error = %err, retry_secs = reconnect.as_secs(), "control plane unreachable");
                    tokio::time::sleep(reconnect).await;
                    continue;
                },
            };

            // 2. 注册实例（失败不致命，后续心跳会自动补建记录）
            if let Err(err) = client.register(runtime.gateway_id(), "").await {
                tracing::warn!(error = %err, "control plane register failed");
            }

            // 3. 心跳 → 拉取 → 应用 → ACK/NACK
            loop {
                let rt = runtime.clone();
                let outcome = client
                    .sync_once(applied_version, move |snapshot| {
                        let rt = rt.clone();
                        async move {
                            rt.apply_snapshot(&snapshot)
                                .map(|_| ())
                                .map_err(|err| err.to_string())
                        }
                    })
                    .await;

                match outcome {
                    Ok(SyncOutcome::Applied { version }) => {
                        applied_version = version;
                        tracing::info!(version, "config snapshot applied from control plane");
                    },
                    Ok(SyncOutcome::Rejected { version, message }) => {
                        tracing::warn!(
                            version,
                            %message,
                            "config snapshot rejected; keeping last known good configuration"
                        );
                    },
                    Ok(SyncOutcome::UpToDate { .. }) | Ok(SyncOutcome::NoConfig) => {},
                    Err(err) => {
                        // 连接/协议错误：跳出内层循环，走重连
                        tracing::warn!(error = %err, "control plane sync failed, reconnecting");
                        break;
                    },
                }

                tokio::time::sleep(heartbeat).await;
            }
        }
    });
}
