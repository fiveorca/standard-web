//! gateway 可执行程序入口。
//!
//! # 职责
//!
//! main.rs 只有两件事：
//!   1. 创建 Tokio Runtime（全特性：rt_multi_thread 是生产推荐配置）
//!   2. 在 Runtime 内调用 bootstrap::run(cli::Cli::parse_args())
//!
//! 所有业务逻辑（配置加载、路由表编译、Server 启动、优雅关闭）
//! 都在 `gateway-runtime` 里完成。main.rs 是纯粹的入口胶水。
//!
//! # Tokio Runtime 配置
//!
//! - `rt_multi_thread`：多线程 runtime，默认 worker 数 = CPU 核数
//! - `macros`：启用 #[tokio::main] 属性宏
//! - `time`：时间驱动功能（sleep、timeout 等）
//! - `signal`：signal-hook 在 async 上下文中需要
//!
//! 如果需要手动配置 worker 线程数，可以在 Runtime Builder 里加：
//! ```rust,ignore
//! tokio::runtime::Builder::new_multi_thread()
//!     .worker_threads(8)
//!     .enable_all()
//!     .build()?
//! ```

// 全局设置 tracing subscriber（在 Runtime::build 里也会调，幂等）
// 这里先把 stderr 的输出级别设置好，避免 Runtime 初始化前的 early log 丢失
fn main() {
    // 解析命令行参数
    let cli = cli::Cli::parse_args();

    // 创建 Tokio Runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all() // 启用 time / io / net 等全部特性
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async move {
            // 在 Tokio Runtime 内执行 bootstrap
            if let Err(e) = bootstrap::run(cli).await {
                // 致命错误：打印到 stderr 后退出
                eprintln!("gateway exited with error: {e}");
                std::process::exit(1);
            }
        });
}

// 模块声明
mod bootstrap;
mod cli;
mod control;
