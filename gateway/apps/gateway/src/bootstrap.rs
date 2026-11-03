//! Bootstrap —— Runtime 启动封装。
//!
//! 处理从 CLI 参数到 Runtime 启动之间的所有步骤：
//!   - 解析模式（standalone 只启 Data Plane）
//!   - 加载 + 校验配置
//!   - 执行 --check 模式（只校验不启动）
//!   - 调用 Runtime::start() 阻塞直到退出

use std::sync::Arc;

use gateway_runtime::Runtime;

use crate::cli::Cli;

/// 执行 CLI 命令对应的动作。
///
/// # 返回
/// - `Ok(())`：正常退出（可能是 graceful shutdown）
/// - `Err(e)`：启动或运行期间发生致命错误
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 检查模式（Phase 1 只支持 standalone）
    let _mode = cli.mode; // 目前只 standalone，后续 Phase 3+ 加 integrated / distributed

    // 2. --check 模式：只加载 + 校验，不启动
    if cli.check {
        return run_check(&cli.config);
    }

    // 3. 正常启动模式
    run_start(&cli.config).await
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
async fn run_start(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = match Runtime::load_from_path(config_path) {
        Ok(rt) => Arc::new(rt),
        Err(errors) => {
            eprintln!("config invalid:");
            for e in &errors {
                eprintln!("  - {e}");
            }
            std::process::exit(1);
        },
    };

    // Runtime::start 内部会阻塞直到 shutdown
    // 我们用 spawn 包一层，以便捕获 JoinError
    let rt_clone = runtime.clone();
    tokio::spawn(async move {
        if let Err(e) = rt_clone.start().await {
            tracing::error!("runtime error: {e}");
        }
    })
    .await?;

    Ok(())
}
