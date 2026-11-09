FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --bin user-center

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home app
WORKDIR /app
COPY --from=builder /app/target/release/user-center /usr/local/bin/user-center
COPY config ./config
ENV USER_CONFIG_DIR=/app/config
USER 10001
EXPOSE 8081
ENTRYPOINT ["user-center"]
