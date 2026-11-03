//! CLI 定义 —— clap 派生宏解析命令行参数。
//!
//! Phase 1 支持：
//!   - `gateway --config gateway.yaml`    启动网关
//!   - `gateway --check gateway.yaml`     只校验配置（不启动）
//!   - `gateway --version`                打印版本并退出

use clap::Parser;

/// Gateway 命令行入口。
///
/// clap 的 derive 宏让我们用 `#[derive(Parser)]` 自动生成 CLI 解析逻辑。
/// version_short 在 Cargo.toml 中定义为 "0.1.0"，会自动填入。
#[derive(Debug, Parser)]
#[command(
    name = "gateway",
    version,
    about = "API Gateway —— 企业级云原生 API 网关（Control Plane + Data Plane 分离）",
    long_about = None,
)]
pub struct Cli {
    /// YAML 配置文件路径（默认 gateway.yaml）
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        default_value = "gateway.yaml",
        env = "GATEWAY_CONFIG"
    )]
    pub config: String,

    /// 只校验配置文件（语法 + 业务规则），不启动网关
    #[arg(short = 'C', long = "check")]
    pub check: bool,

    /// 运行模式（standalone / integrated / distributed）。Phase 1 只支持 standalone
    #[arg(short = 'm', long = "mode", default_value = "standalone")]
    pub mode: String,
}

impl Cli {
    /// 解析命令行参数。
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
