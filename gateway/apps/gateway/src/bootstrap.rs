//! Bootstrap —— Runtime 启动封装。
//!
//! 处理从 CLI 参数到 Runtime 启动之间的所有步骤：
//!   - 解析运行模式（standalone / integrated）
//!   - 加载 + 校验配置
//!   - 执行 --check 模式（只校验不启动）
//!   - integrated 模式装配控制面并挂载到管理端口
//!   - 调用 Runtime::start_with_admin() 阻塞直到退出

use std::sync::Arc;

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
