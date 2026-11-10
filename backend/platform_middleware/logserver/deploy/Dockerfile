# Logserver Dockerfile
#
# 构建 (多阶段):
#   docker build -f deploy/Dockerfile --target builder -t logserver-builder .
#   docker build -f deploy/Dockerfile --target api       -t logserver:api .
#   docker build -f deploy/Dockerfile --target worker    -t logserver:worker .

FROM rust:1.85-slim AS builder
WORKDIR /src

# rdkafka 依赖 libssl-dev pkg-config
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libssl-dev \
    pkg-config \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 先复制依赖清单，利用 Docker 缓存层
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo '// placeholder' > src/lib.rs && echo 'fn main(){}' > src/main.rs
RUN cargo build --release || true  # allow failure

# 再复制真正的源码
COPY . .
RUN touch src/lib.rs src/main.rs
RUN cargo build --release --bin logserver

# ========= 运行时 =========
FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/logserver /usr/local/bin/logserver
COPY config /etc/logserver/config
ENV RUST_LOG=info
EXPOSE 8080 8081 9090

# ========= API 镜像 =========
FROM base AS api
CMD ["logserver", "--mode", "api"]

# ========= Worker 镜像 =========
FROM base AS worker
CMD ["logserver", "--mode", "worker"]
