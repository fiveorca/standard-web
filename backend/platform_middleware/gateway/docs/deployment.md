# 部署指南

## 1. 构建产物

```bash
cd gateway
cargo build --release
# 产物：target/release/gateway
```

运行：

```bash
GATEWAY_CONFIG_DIR=/etc/gateway/config \
GATEWAY_PROFILE=production \
./target/release/gateway
```

## 2. 配置目录

```
/etc/gateway/config/
├── gateway.yaml
├── routes.yaml
└── production.yaml
```

- 配置目录需要可写（管理 API 持久化 `routes.yaml`）。
- 敏感值使用环境变量：`GATEWAY_JWT_SECRET`、`GATEWAY_ADMIN_KEY`、`REDIS_URL`、`CONSUL_TOKEN`。
- 修改文件后 5 秒内自动热加载；`--no-watch` 可关闭。也可调用 `POST /admin/v1/config/reload` 立即生效。

## 3. Docker

```bash
docker build -f deploy/Dockerfile -t rust-api-gateway:latest .
docker run --rm -p 8080:8080 -p 9090:9090 \
  -e GATEWAY_ADMIN_KEY=change-me \
  -e GATEWAY_JWT_SECRET=change-me \
  -v $PWD/config:/etc/gateway/config \
  rust-api-gateway:latest
```

镜像特性：

- 多阶段构建，运行镜像基于 `debian:bookworm-slim`，仅包含 CA 证书与二进制；
- 非 root 用户（UID 10001）运行；
- 内置 `HEALTHCHECK` 调用 `/health/live`。

## 4. Docker Compose

```bash
cd gateway
docker compose -f deploy/docker-compose.yml up --build
```

包含：

| 服务 | 端口 | 说明 |
| --- | --- | --- |
| gateway | 8080 / 127.0.0.1:9090 | 网关 |
| httpbin | 内部 | 示例上游 |
| redis | 内部 | 限流 + 配置同步 |
| consul | 127.0.0.1:8500 | 服务发现（示例） |
| prometheus | 127.0.0.1:9091 | 指标采集 |

Compose 使用 `development` profile（TLS 关闭）。生产环境请使用 `production` profile 并挂载证书。

## 5. TLS 与 mTLS

```yaml
gateway:
  server:
    tls:
      enabled: true
      cert_path: /etc/gateway/tls/tls.crt
      key_path: /etc/gateway/tls/tls.key
      client_ca_path: /etc/gateway/tls/ca.crt   # 可选，启用 mTLS
      min_version: "1.3"
```

- 证书需包含完整链；私钥支持 PKCS#8 / RSA / EC（`rustls-pemfile`）。
- ALPN 自动协商 `h2` 与 `http/1.1`。
- 上游 TLS 由 `gateway.upstream_tls` 与路由 `upstream.tls` 控制：`verify`、`ca_cert_path`、`client_cert_path`、`client_key_path`。

## 6. 多实例与配置同步

1. 所有实例连接到同一 Redis，配置相同的 `gateway.redis.channel`；
2. 任一实例通过管理 API 修改路由，变更会持久化并广播 `{version, routes}`；
3. 其他实例仅在版本号更大时应用，避免旧消息覆盖新配置；
4. 每个实例设置唯一 `GATEWAY_NODE_ID`，便于审计。

注意：Pub/Sub 不持久化消息。实例重启后以磁盘配置为准；若需要强一致，请将配置目录放在共享存储或使用配置中心下发。

## 7. 优雅关闭

- 收到 `SIGTERM` / `SIGINT` 后：标记 draining（`/health/ready` 返回 503）→ 停止接收新连接 → 等待在途请求完成（最长 `graceful_shutdown_timeout`）→ 关闭上游连接池 → 刷新并关闭 OTLP exporter。
- Kubernetes 建议：

```yaml
terminationGracePeriodSeconds: 40   # 大于 graceful_shutdown_timeout
readinessProbe:
  httpGet: { path: /health/ready, port: 8080 }
livenessProbe:
  httpGet: { path: /health/live, port: 8080 }
```

## 8. 监控接入

Prometheus：

```yaml
scrape_configs:
  - job_name: gateway
    metrics_path: /metrics
    static_configs:
      - targets: ["gateway:8080"]
```

关键指标：

| 指标 | 说明 |
| --- | --- |
| `gateway_requests_total` | 请求总数（route/method/status） |
| `gateway_request_duration_seconds` | 请求耗时直方图 |
| `gateway_upstream_requests_total` | 上游请求结果 |
| `gateway_rate_limited_total` | 限流次数 |
| `gateway_circuit_breaker_state` | 熔断状态（0/1/2） |
| `gateway_cache_hits_total` | 缓存命中 |
| `gateway_active_connections` | 活跃连接数 |
| `gateway_inflight_requests` | 在途请求 |
| `gateway_service_instances` | 服务实例数（健康/总数） |

OpenTelemetry：

```yaml
gateway:
  tracing:
    enabled: true
    endpoint: http://otel-collector:4318
    service_name: rust-api-gateway
    sample_ratio: 0.1
```

## 9. 容量与调优

- `server.enable_http2: true`：对外与上游同时启用 HTTP/2。
- 连接池由上游主机维度复用；`server.timeouts.idle` 作为池空闲超时。
- 大文件场景设置 `max_body_size: 0`（不限制），并确保 `timeout.total` 足够大或为 0。
- 本地缓存条目数由 `cache.max_capacity` 控制；高基数 URL 场景建议只对明确的路由开启缓存。
- 限流 `max_keys` 控制本地模式内存上限，超过后按插入顺序淘汰。

## 10. 回滚

1. 保留上一版本的 `routes.yaml` 与二进制；
2. 回滚二进制后，配置目录中的路由会在启动时重新加载；
3. 若仅需回滚路由，可通过管理 API 重新提交旧路由配置，或替换 `routes.yaml` 后调用 `/admin/v1/config/reload`。
