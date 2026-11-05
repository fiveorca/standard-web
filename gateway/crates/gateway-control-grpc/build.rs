//! 构建脚本：用 vendored protoc 生成 gRPC 代码。
//!
//! 项目约束不要求在构建机预装 protoc：`protoc-bin-vendored` 提供
//! 各平台预编译二进制，构建脚本将其路径写入 `PROTOC` 环境变量。

fn main() {
    // 若当前平台没有 vendored protoc，则回退到系统 protoc
    if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", path);
    }

    // 生成 server + client 代码；失败时让构建直接失败（build script 的正确行为）
    if let Err(err) = tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/config_distribution.proto"], &["proto"])
    {
        panic!("failed to compile config_distribution.proto: {err}");
    }

    // proto 变更时触发重新生成
    println!("cargo:rerun-if-changed=proto/config_distribution.proto");
}
