# rust-api-gateway

基于 **Rust + Axum 0.8 + Hyper 1.x + Tower** 实现的生产级 API 网关。支持动态路由、真正的流式反向代理、服务发现、负载均衡、认证授权、限流、熔断、重试、缓存、TLS、可观测性与热更新。

> 本项目是可直接编译、测试、部署的完整工程，不包含伪代码或 TODO 占位实现。

## 功能总览

| 领域 | 能力 |
| --- | --- |
| 路由 | Path / Host / Method / Header / Query / Cookie / RemoteAddr / After / Before / Between 谓词，AND 语义，`order` + 具体度 + ID 的确定性优先级 |
| 代理 | HTTP/1.1、HTTP/2、HTTPS 上游、WebSocket、gRPC、Trailer 透传、大 Body 流式转发、连接池、Hop-by-Hop 头清理、`X-Forwarded-*` |
| 过滤器 | StripPrefix、PrefixPath、SetPath、RewritePath、请求/响应头增删改、AddRequestParameter、PreserveHostHeader、RequestHeaderToRequestUri、SecureHeaders，以及自定义 Gateway/Global Filter |
| 服务发现 | 静态实例 + Consul 健康实例，定时刷新 |
| 负载均衡 | 轮询、随机、加权轮询、最少连接、Power of Two Choices |
| 限流 | 全局/路由；IP、用户、租户、API Key、自定义 Key；本地令牌桶 + Redis Lua 原子令牌桶；429 + `Retry-After`；fail-open / fail-closed |
| 认证 | JWT（HS256/384/512、RS256/384/512、ES256/384）、JWKS 缓存与轮换、iss/aud/exp/nbf、API Key（SHA-256）、身份头注入 |
| 授权 | scopes / roles / metadata 断言、外部授权中心（缓存 + 超时 + fail-open） |
| 防护 | IP 黑白名单 / CIDR、可信代理、Host 校验、SSRF 防护、Header/Body 大小限制、安全响应头 |
| 韧性 | 熔断（Closed/Open/Half-Open、失败率/慢调用率、降级响应）、幂等重试（指数退避）、多维度超时 |
| 缓存 | 本地响应缓存（TTL/容量/自定义 Key/Cache-Control/Vary/命中统计） |
| CORS | 全局 + 路由级策略、OPTIONS 预检 |
| TLS | HTTPS 监听、上游 TLS 校验、自定义 CA、可选 mTLS、TLS 1.2/1.3、ALPN |
| 可观测性 | Prometheus 指标、OpenTelemetry OTLP、W3C Trace Context、结构化 JSON 访问日志（脱敏） |
| 运维 | live/ready 健康检查、管理 API（路由 CRUD/启停、配置热更新、上游/熔断/指标查询）、Redis Pub/Sub 多实例同步 |

## 目录结构

```
gateway/
├── Cargo.toml
├── rust-toolchain.toml
├── config/                  # 网关配置
│   ├── gateway.yaml
│   ├── routes.yaml
│   ├── development.yaml
│   └── production.yaml
├── deploy/                  # 容器与监控配置
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── prometheus.yml
├── docs/                    # 中文文档
├── src/
│   ├── admin/               # 管理 API + 配置同步
│   ├── bootstrap/           # 启动装配
│   ├── cache/               # 响应缓存
│   ├── config/              # 配置模型 / 加载 / 校验
│   ├── core/
│   │   ├── filter/          # 过滤器
│   │   ├── gateway/         # Gateway 与请求管线
│   │   ├── load_balancer/
│   │   ├── predicate/       # 路由谓词
│   │   ├── proxy/           # 流式反向代理
│   │   ├── route/           # 路由编译与快照表
│   │   ├── service_discovery/
│   │   └── upstream/        # 上游注册与健康状态
│   ├── middleware/          # 认证/授权/限流/CORS/IP/Host/请求 ID
│   ├── observability/       # 日志/指标/追踪
│   ├── resilience/          # 熔断/重试/超时/健康检查
│   ├── transport/           # HTTP/HTTPS 监听与优雅关闭
│   └── utils/
└── tests/                   # 真实集成测试（路由/认证/限流/缓存/重试/WS/TLS/管理 API）
```

## 快速开始

```bash
cd gateway

# 1. 准备一个上游（示例使用 httpbin）
docker run --rm -p 8081:80 mccutchen/go-httpbin:latest

# 2. 启动网关（默认读取 ./config，监听 0.0.0.0:8080，管理端口 127.0.0.1:9090）
cargo run --release -- --config config

# 3. 验证
curl -s http://127.0.0.1:8080/api/httpbin/get | head
curl -s http://127.0.0.1:9090/health/ready
curl -s http://127.0.0.1:9090/admin/v1/config/status -H 'x-admin-key: dev-admin-key'
```

Docker Compose（网关 + httpbin + Redis + Consul + Prometheus）：

```bash
cd gateway
docker compose -f deploy/docker-compose.yml up --build
```

## 验收命令

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

## 文档

- [架构设计](architecture.md)
- [配置说明](configuration.md)
- [管理 API](api.md)
- [部署指南](deployment.md)
- [安全说明](security.md)

## 运行参数

| 参数 | 环境变量 | 说明 |
| --- | --- | --- |
| `--config <目录>` | `GATEWAY_CONFIG_DIR` | 配置目录，默认 `config` |
| `--profile <名称>` | `GATEWAY_PROFILE` | 加载 `<目录>/<名称>.yaml` 覆盖 |
| `--no-watch` | - | 关闭配置文件轮询热加载 |
| `--help` / `--version` | - | 帮助与版本 |
| - | `GATEWAY_NODE_ID` | 多实例同步节点标识 |

## 已知边界

- 上游 TLS 的 SNI 使用目标主机名，`server_name` 覆盖未实现（镜像/端口转发场景需要证书 SAN 与主机名一致）。
- `server.max_connections` 仅作为配置保留，实际并发由操作系统与 Tokio 调度决定。
- 响应缓存为进程内缓存（Moka），多实例之间不共享；Redis 仅用于限流与配置同步。
