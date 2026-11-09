//! 网关可执行程序入口。

use std::path::PathBuf;

use gateway::bootstrap::{run, RunOptions};

const HELP: &str = "\
rust-api-gateway - 生产级 Rust API 网关

用法:
    gateway [选项]

选项:
    -c, --config <目录>      配置目录（默认: ./config 或 $GATEWAY_CONFIG_DIR）
    -p, --profile <名称>     环境 profile，加载 <目录>/<名称>.yaml（默认: $GATEWAY_PROFILE）
        --no-watch           关闭配置文件热加载轮询
    -h, --help               显示帮助
    -V, --version            显示版本
";

#[tokio::main]
async fn main() {
    let mut config_dir: Option<PathBuf> = None;
    let mut profile: Option<String> = std::env::var("GATEWAY_PROFILE").ok();
    let mut watch = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return;
            }
            "-V" | "--version" => {
                println!("rust-api-gateway {}", gateway::VERSION);
                return;
            }
            "-c" | "--config" => match args.next() {
                Some(value) => config_dir = Some(PathBuf::from(value)),
                None => exit_with("`--config` requires a directory"),
            },
            "-p" | "--profile" => match args.next() {
                Some(value) => profile = Some(value),
                None => exit_with("`--profile` requires a value"),
            },
            "--no-watch" => watch = false,
            other => exit_with(&format!("unknown argument `{other}`")),
        }
    }

    let config_dir = config_dir
        .or_else(|| std::env::var("GATEWAY_CONFIG_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config"));

    let mut options = RunOptions::new(config_dir, profile);
    if !watch {
        options.reload_interval = None;
    }

    if let Err(err) = run(options).await {
        eprintln!("gateway failed to start: {err:#}");
        std::process::exit(1);
    }
}

fn exit_with(message: &str) -> ! {
    eprintln!("error: {message}\n\n{HELP}");
    std::process::exit(2);
}
