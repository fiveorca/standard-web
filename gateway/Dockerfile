# ======================================================================
# Gateway 多阶段构建 Dockerfile
# ----------------------------------------------------------------------
# 阶段 1（builder）：用官方 Rust 镜像编译 release 二进制
# 阶段 2（runtime）：只保留二进制 + 运行配置，镜像体积最小化
#
# 构建：
#   docker build -t api-gateway:latest -f Dockerfile .
# ======================================================================

FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# 构建期依赖：sqlx 的 postgres 驱动为纯 Rust，无需 libpq；
# 只需 pkg-config 以便部分构建脚本探测系统库。
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 先复制依赖清单，最大化利用 Docker 层缓存
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps

# --locked：严格使用 Cargo.lock 中的版本，保证构建可复现
RUN cargo build --release --locked -p gateway -p gateway-control

# ----------------------------------------------------------------------
# 运行镜像
# ----------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# curl 仅用于 HEALTHCHECK；ca-certificates 供未来 TLS 上游使用
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home gateway

WORKDIR /etc/gateway

COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /build/target/release/gateway-control /usr/local/bin/gateway-control
COPY deploy/gateway.yaml /etc/gateway/gateway.yaml

# 以非 root 用户运行
USER gateway

EXPOSE 8080 8081

# /health 走管理端口，不检查下游依赖
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8081/health || exit 1

ENTRYPOINT ["gateway"]
CMD ["--config", "/etc/gateway/gateway.yaml"]
