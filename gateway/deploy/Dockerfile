# syntax=docker/dockerfile:1

# ---------- 构建阶段 ----------
FROM rust:1.85-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# ---------- 运行阶段 ----------
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin gateway

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway
COPY config /etc/gateway/config

ENV GATEWAY_CONFIG_DIR=/etc/gateway/config \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_ADMIN_HOST=0.0.0.0 \
    RUST_LOG=info

USER gateway
EXPOSE 8080 9090

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9090/health/live || exit 1

ENTRYPOINT ["/usr/local/bin/gateway"]
