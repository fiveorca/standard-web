//! gateway-control 命令行参数。

use clap::Parser;

/// 控制面命令行入口。
#[derive(Debug, Parser)]
#[command(
    name = "gateway-control",
    version,
    about = "API Gateway 控制面（配置管理 / 发布 / 回滚 / 审计）",
    long_about = None,
)]
pub struct Cli {
    /// 监听地址（默认仅本机）
    #[arg(
        long = "bind",
        value_name = "ADDR",
        default_value = "127.0.0.1:8091",
        env = "GATEWAY_CONTROL_BIND"
    )]
    pub bind: String,

    /// PostgreSQL 连接串
    #[arg(long = "database-url", value_name = "URL", env = "GATEWAY_DATABASE_URL")]
    pub database_url: Option<String>,

    /// 使用进程内内存仓储（数据重启即丢失，仅用于演示/测试）
    #[arg(long = "memory", default_value_t = false)]
    pub memory: bool,

    /// 管理员 token 清单，格式 `token:actor, token2:actor2`
    #[arg(long = "admin-tokens", value_name = "SPEC", env = "GATEWAY_ADMIN_TOKENS")]
    pub admin_tokens: Option<String>,

    /// 只读 token 清单，格式同 admin-tokens
    #[arg(long = "viewer-tokens", value_name = "SPEC", env = "GATEWAY_VIEWER_TOKENS")]
    pub viewer_tokens: Option<String>,

    /// 日志级别（trace / debug / info / warn / error）
    #[arg(long = "log-level", default_value = "info", env = "GATEWAY_LOG_LEVEL")]
    pub log_level: String,
}

impl Cli {
    /// 解析命令行参数。
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
