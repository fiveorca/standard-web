//! gateway-control 可执行程序入口。
//!
//! main.rs 只负责创建 Tokio Runtime 并调用 bootstrap::run；
//! 所有启动逻辑在 bootstrap.rs。

mod bootstrap;
mod cli;

fn main() {
    // 解析命令行参数
    let cli = cli::Cli::parse_args();

    // 构建多线程 Tokio Runtime（与数据面保持一致）
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("failed to build tokio runtime: {err}");
            std::process::exit(1);
        },
    };

    runtime.block_on(async move {
        if let Err(err) = bootstrap::run(cli).await {
            // 致命错误：打印到 stderr 后退出（错误链由 anyhow 格式化）
            eprintln!("gateway-control exited with error: {err:#}");
            std::process::exit(1);
        }
    });
}
