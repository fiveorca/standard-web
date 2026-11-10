fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 注意：本项目不需要 protoc
    // Proto 文件在 proto/log/v1/ingestion.proto 作为规范参考
    // gRPC 相关的 Rust 类型在 src/transport/grpc/ingestion/mod.rs 中手动定义
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
