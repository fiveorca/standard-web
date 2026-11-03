# Gateway — 完整项目设计与开发需求规格

> 文档版本：1.0.0  
> 项目名称：gateway  
> 项目类型：Enterprise API Gateway  
> 开发语言：Rust Stable  
> 架构模式：Control Plane + Data Plane  
> 核心原则：高性能、模块化、可扩展、高可用、安全、可观测  
> 本文件是 AI 编程 IDE 实施本项目的主需求文件。

---

# 第一章：项目目标

## 1.1 项目定位

开发一套企业级、云原生、插件化、高性能的 API Gateway。

网关作为整个微服务体系的统一流量入口，承担：

1. HTTP/HTTPS 流量接入。
2. API 路由管理。
3. 动态服务发现。
4. 负载均衡。
5. 身份认证和基础访问控制。
6. 请求限流和配额管理。
7. 服务熔断、重试和超时控制。
8. 灰度发布和流量治理。
9. 请求与响应转换。
10. 安全防护。
11. 日志、指标和分布式链路追踪。
12. 动态配置和插件管理。
13. 网关实例集群管理。
14. API 生命周期管理的基础接口。

## 1.2 核心设计目标

- 数据面必须具备高并发、异步、非阻塞处理能力。
- 数据面不得在每次请求中查询配置数据库。
- 路由、策略、服务发现结果应当支持本地缓存。
- 配置必须支持动态更新，无需重启网关。
- 配置更新失败不得破坏现有有效配置。
- 网关实例必须支持水平扩展。
- 控制面与数据面可以独立部署。
- 核心模块通过清晰的接口和 Trait 解耦。
- 不得将业务逻辑写入网关。
- 不得将所有功能堆积在单个 HTTP Handler 中。
- 不得为了模块化而过度创建微服务。
- 必须支持独立测试和故障隔离。
- 所有重要配置必须有默认值、校验规则和文档。
- 所有核心功能必须有自动化测试。

## 1.3 非目标

第一阶段不开发以下功能：

- 完整 OAuth2 / OpenID Connect 授权服务器。
- 用户注册和用户中心。
- 订单、支付等业务逻辑。
- 完整的企业级 WAF 检测引擎。
- 专业 DDoS 清洗系统。
- 完整 Service Mesh。
- 独立消息队列系统。
- 自研 Prometheus 或 OpenTelemetry 后端。
- 第一阶段直接兼容 Envoy 全套 xDS 协议。
- 第一阶段直接支持 HTTP/3、QUIC、任意 TCP/UDP 代理。
- 第一阶段允许任意第三方 Rust 动态库热加载。

网关负责集成这些基础设施，但不需要重复建设整个基础设施生态。

---

# 第二章：技术选型

## 2.1 核心技术栈

| 领域 | 技术 | 用途 |
|---|---|---|
| 编程语言 | Rust Stable | 核心开发语言 |
| Edition | 2021 或更新的稳定 Edition | Rust 项目标准 |
| 异步运行时 | Tokio | 异步任务和网络 IO |
| HTTP 应用框架 | Axum | Admin API、管理接口 |
| HTTP 协议 | Hyper | 数据面 HTTP 处理 |
| 中间件 | Tower | 统一 Service / Layer 抽象 |
| Web 中间件 | Tower HTTP | 常见 HTTP 中间件 |
| gRPC | Tonic | 控制面与数据面通信 |
| TLS | Rustls | TLS 和证书 |
| 序列化 | Serde | JSON、YAML 等 |
| 配置 | Figment 或 Serde 配置模块 | 配置加载 |
| 数据库 | SQLx + PostgreSQL | 控制面数据持久化 |
| 缓存 | Redis | 可选分布式限流 |
| 日志 | Tracing | 结构化日志 |
| 指标 | Prometheus | Metrics |
| 链路追踪 | OpenTelemetry | Tracing |
| 错误处理 | Thiserror / Anyhow | 错误管理 |
| CLI | Clap | 命令行工具 |
| API 文档 | OpenAPI | 管理 API 文档 |
| 测试 | Cargo Test | 自动化测试 |

实际依赖版本应采用实施时兼容的稳定版本，统一由 Cargo workspace 管理，不允许各 Crate 随意引入不同版本。

Rust Edition 应使用稳定版 Rust 支持的版本，不允许为了追求新版本而使用 nightly 特性。

## 2.2 技术使用约束

### Axum

用于：

- Admin REST API。
- 健康检查。
- Readiness 检查。
- 管理端请求处理。
- 控制面管理接口。

不应将 Axum Handler 设计成每一个反向代理请求的主要执行引擎。

### Hyper

用于：

- HTTP Server。
- HTTP Client。
- 上游连接。
- 请求转发。
- 响应转发。
- 流式 Body。
- HTTP/1.1。
- HTTP/2。

必须避免不必要的 Request Body 全量读取和复制。

### Tower

用于：

- 请求处理 Pipeline。
- 通用 Middleware。
- Timeout Layer。
- 限流 Layer。
- 认证 Layer。
- 请求追踪 Layer。
- 熔断和重试等策略封装。

### Tonic

用于：

- Data Plane 向 Control Plane 注册。
- 配置 Snapshot 获取。
- 配置动态推送。
- 配置版本 ACK / NACK。
- 实例状态上报。

### SQLx

用于控制面 PostgreSQL 访问。

不允许数据面处理普通流量时访问 PostgreSQL。

---

# 第三章：总体架构

## 3.1 架构组成

项目分为以下主要组件：

1. Gateway Control Plane
2. Gateway Data Plane
3. Gateway Shared Core
4. Gateway Configuration
5. Gateway Service Discovery
6. Gateway Plugin System
7. Gateway Observability
8. Gateway CLI

## 3.2 Control Plane

负责网关管理和配置下发。

包含：

- 管理 API。
- Listener 管理。
- Route 管理。
- Service 管理。
- Upstream 管理。
- Endpoint 管理。
- Consumer 管理。
- Authentication Policy 管理。
- Rate Limit Policy 管理。
- Circuit Breaker Policy 管理。
- Retry Policy 管理。
- TLS Certificate 管理。
- Plugin 管理。
- Configuration Compiler。
- Configuration Version Manager。
- Configuration Distributor。
- Gateway Instance Registry。
- Audit Log。

Control Plane 必须能够独立运行。

## 3.3 Data Plane

负责真实请求流量处理。

包含：

- Network Listener。
- TLS Acceptor。
- Connection Manager。
- HTTP Request Context。
- Request Normalizer。
- Route Engine。
- Authentication Engine。
- Authorization Policy Engine。
- Rate Limiter。
- Request Transformation。
- Service Discovery。
- Load Balancer。
- Health Checker。
- Circuit Breaker。
- Retry Engine。
- Timeout Manager。
- Reverse Proxy。
- Response Transformation。
- Access Logger。
- Metrics Collector。
- Trace Propagator。
- Configuration Watcher。

Data Plane 必须能够独立运行。

## 3.4 Gateway 运行模式

必须支持三种运行模式。

### Standalone Mode

仅运行 Data Plane，通过 YAML / TOML 配置文件加载配置。

适用于：

- 本地开发。
- 单机部署。
- 测试环境。
- 控制面不可用的独立部署。

### Integrated Mode

Control Plane 和 Data Plane 在同一个进程或者部署单元中运行。

适用于：

- 开发环境。
- 小规模部署。
- 初期部署。

### Distributed Mode

Control Plane 和 Data Plane 分开部署。

适用于：

- 生产集群。
- 多实例部署。
- 多地域部署。
- Kubernetes 部署。

即使 Integrated Mode 下运行在一个进程中，也必须保持 Control Plane 和 Data Plane 的模块边界，不得形成相互依赖的混乱结构。

---

# 第四章：功能模块需求

优先级说明：

- P0：第一个完整可用版本必须实现。
- P1：第二阶段实现。
- P2：高级扩展能力。

## 4.1 网络接入模块 Network

优先级：P0

### 功能

1. HTTP/1.1 Server。
2. HTTP/2 Server。
3. HTTP/HTTPS 监听。
4. TLS 终止。
5. TLS 证书配置。
6. TLS 证书热更新。
7. SNI。
8. HTTP Keep-Alive。
9. 连接超时。
10. 空闲连接超时。
11. 最大连接数限制。
12. 最大并发请求数限制。
13. 请求头大小限制。
14. 请求体大小限制。
15. URL 长度限制。
16. 优雅关闭。
17. Readiness。
18. Liveness。

P1：

- WebSocket。
- SSE。
- gRPC。
- mTLS。
- 多 Listener。
- 多证书。

P2：

- HTTP/3。
- QUIC。
- TCP Proxy。
- TLS Passthrough。
- UDP Proxy。

### 约束

- 所有网络 IO 必须异步化。
- 禁止在异步处理线程内执行阻塞 IO。
- 必须配置有界连接和并发资源。
- 不允许无限制创建后台任务。
- 请求体默认采用流式处理。
- 监听器关闭时应停止接收新请求，并等待允许的在途请求完成。

## 4.2 路由模块 Route Engine

优先级：P0

支持以下匹配条件：

- Host。
- HTTP Method。
- Path Exact。
- Path Prefix。
- Header。
- Query Parameter。
- 路由优先级。

P1：

- Regular Expression Path。
- Cookie。
- Client IP。
- 用户身份。
- 租户身份。
- 客户端 App Version。
- 多条件组合策略。

### 路由规则

一个 Route 至少包含：

```text
id
name
enabled
priority
host_matches
method_matches
path_match
header_matches
query_matches
service_id
plugins
timeout_policy
retry_policy
rate_limit_policy
auth_policy
request_transform
response_transform
```

### 路由匹配规则

必须定义确定性的优先级：

1. 先匹配 Host。
2. 再匹配 Path 类型及具体程度。
3. 再匹配 Method。
4. 再匹配 Header 和 Query。
5. 最后按照 Priority 排序。

同一优先级、同一匹配条件出现冲突时，配置发布必须失败，不允许依赖 HashMap 迭代顺序等非确定性行为。

### Path 支持

- Exact：完全匹配。
- Prefix：前缀匹配。

正则匹配作为 P1，必须限制复杂度并防止正则表达式资源耗尽。

### 路由管理

- 新建。
- 修改。
- 删除。
- 启用。
- 禁用。
- 查询。
- 批量发布。
- 配置校验。
- 路由优先级管理。
- 路由命中统计。
- 路由测试。

### 路由处理

支持：

- Path Rewrite。
- Host Rewrite。
- Header Add。
- Header Remove。
- Header Replace。
- Query Rewrite。
- Redirect。
- HTTP Status Rewrite。
- Weighted Routing。
- Version Routing。
- Default Route。
- Fallback。

## 4.3 Service / Upstream 模块

优先级：P0

### Service

Service 表示一个逻辑后端服务。

例如：

```text
user-service
order-service
payment-service
```

Service 不直接负责具体实例地址，而是关联 Upstream。

字段至少包含：

```text
id
name
description
enabled
upstream_id
protocol
connect_timeout
read_timeout
write_timeout
request_timeout
```

### Upstream

Upstream 表示一组后端实例。

字段：

```text
id
name
algorithm
discovery_provider
health_check
endpoints
tls
load_balancer_config
```

### Endpoint

字段：

```text
id
host
port
weight
enabled
zone
metadata
health_status
```

### 服务发现提供者

通过 Trait 抽象：

```rust
#[async_trait]
pub trait ServiceDiscoveryProvider: Send + Sync {
    async fn resolve(
        &self,
        service_name: &str,
    ) -> Result<Vec<Endpoint>, DiscoveryError>;

    async fn health(&self) -> DiscoveryHealth;
}
```

P0：

- Static Provider。
- DNS Provider。

P1：

- Kubernetes EndpointSlice Provider。

P2：

- Consul Provider。
- Nacos Provider。
- 其他外部注册中心。

不同服务发现提供者不得直接依赖 Route Engine。

### Endpoint 状态

```text
HEALTHY
UNHEALTHY
UNKNOWN
DRAINING
```

### 健康检查

主动健康检查：

- HTTP GET。
- TCP Connect。
- 可配置检查路径。
- 检查间隔。
- 检查超时。
- 连续失败阈值。
- 连续成功阈值。

被动健康检查：

- 连接失败统计。
- 5xx 统计。
- 上游超时统计。
- 异常实例检测。
- 实例自动恢复。

### 负载均衡

P0：

- Round Robin。
- Weighted Round Robin。
- Random。
- Weighted Random。

P1：

- Least Connections。
- IP Hash。
- Consistent Hash。
- Zone Aware。

负载均衡必须只在健康 Endpoint 中选择实例。

必须保证并发环境下算法的数据安全。

## 4.4 Authentication / Authorization

优先级：P0

支持：

- JWT。
- API Key。
- IP Allowlist。
- IP Denylist。
- Basic Auth。

P1：

- OAuth2 Token Validation。
- OIDC Integration。
- HMAC Signature。
- mTLS Identity。
- Consumer Group。
- 多租户认证策略。

### JWT 验证要求

必须实现：

1. Token 格式验证。
2. 签名验证。
3. 过期时间验证。
4. Not Before 验证。
5. Issuer 验证。
6. Audience 验证。
7. 允许算法白名单。
8. Key ID 处理。
9. JWKS 缓存。
10. Key Rotation。
11. Token 撤销或短期失效策略。

禁止直接信任客户端传入的用户身份 Header。

禁止通过 JWT Header 中任意指定的算法控制验证算法。

### API Key

- 生成 API Key。
- 查询 API Key 元数据。
- 吊销 API Key。
- 过期时间。
- 访问权限。
- Consumer 绑定。
- 使用次数统计。

数据库只保存 API Key 的安全摘要，不保存明文密钥。

明文密钥仅在创建时返回一次。

### Consumer

Consumer 表示一个 API 使用者，例如：

- Android App。
- Web App。
- 第三方系统。
- 企业租户。
- 内部微服务客户端。

### 访问控制边界

网关只处理通用访问资格和策略。

例如：

- Token 是否有效。
- Consumer 是否有效。
- API 是否开放。
- IP 是否被允许。
- Scope 是否满足。

具体业务资源权限由业务服务自己校验。

## 4.5 Rate Limiting

优先级：P0

### 限流范围

- Global。
- Service。
- Route。
- IP。
- Consumer。
- User。
- Tenant。
- API Key。

### 限流算法

P0：

- Token Bucket。
- Fixed Window。

P1：

- Sliding Window。
- Leaky Bucket。

### 功能

- QPS 限制。
- Burst 限制。
- 最大并发限制。
- 时间窗口配额。
- 每日调用量。
- 每月调用量。
- 动态限流配置。
- 限流统计。
- 限流原因。
- `Retry-After` Header。
- HTTP 429 响应。

### 存储实现

必须实现 Local Rate Limiter。

P1 提供 Redis Distributed Rate Limiter。

Redis 发生故障时，必须按照策略决定：

- FAIL_OPEN：允许请求通过，但需要记录限流后端故障。
- FAIL_CLOSED：拒绝请求，以保障配额或安全策略。

每个策略必须能够配置失败模式，不能默默降级为无限制访问。

### 多级限流

必须设计全局、Route、Consumer 等策略的组合执行方式。

任何一个有效策略触发限流，都应按照其拒绝行为处理。

## 4.6 Resilience

优先级：P0

### Timeout

必须区分：

- Connect Timeout。
- TLS Handshake Timeout。
- Response Header Timeout。
- Read Timeout。
- Write Timeout。
- Request Total Timeout。
- Idle Timeout。

不能用单一 Timeout 代替所有超时控制。

### Retry

支持：

- 最大重试次数。
- 可重试 HTTP 状态码。
- 可重试网络异常。
- 指数退避。
- 最大退避时间。
- 随机抖动。
- Retry Budget。
- 指定上游重试。

必须遵守：

- 默认禁止对非幂等请求自动重试。
- POST 不得默认无限重试。
- 请求体不能重放时不得尝试重新发送。
- 只有在响应尚未提交客户端且请求允许重放时才能执行重试。
- 重试耗时必须受总请求超时限制。
- 重试必须使用其他健康实例，避免无意义地打击同一个故障实例。

### Circuit Breaker

支持：

```text
CLOSED
OPEN
HALF_OPEN
```

配置：

- 失败率阈值。
- 统计窗口。
- 最小请求数量。
- 熔断持续时间。
- 半开探测请求数。
- 连续成功阈值。
- 恢复策略。

### Bulkhead

支持：

- Service 并发限制。
- Upstream 并发限制。
- Route 并发限制。
- 全局并发限制。

### Load Shedding

系统过载时能够主动拒绝新请求。

### Backpressure

请求积压达到资源阈值时，应控制继续接收流量，禁止无界排队。

## 4.7 Traffic Governance

优先级：P1

实现：

- Canary Release。
- Blue-Green Release。
- Weighted Routing。
- Header Based Routing。
- Cookie Based Routing。
- Version Routing。
- A/B Testing。
- Traffic Mirroring。
- Sticky Session。
- Zone Aware Routing。

权重路由必须支持：

```text
v1 = 90
v2 = 10
```

镜像请求不得将业务写入操作直接施加到正式生产数据。

镜像处理需要有独立并发限制、超时和失败隔离。

## 4.8 Request / Response Transformation

优先级：P1

Request：

- Header Add / Remove / Replace。
- Path Rewrite。
- Query Rewrite。
- Host Rewrite。
- Request Method Rewrite。
- Request Body 转换。

Response：

- Header Add / Remove / Replace。
- Response Body 转换。
- Status Code 转换。
- 自定义错误响应。

其他：

- CORS。
- Gzip。
- Brotli。
- HTTP Cache。
- ETag。
- Last-Modified。
- Cache-Control。

Request Body 和 Response Body 默认采用流式处理。

Body 转换只有在明确配置的情况下才允许缓冲，并必须定义最大缓冲大小和失败策略。

## 4.9 Security

优先级：P0

基础能力：

- TLS。
- Header 校验。
- Host 校验。
- Path 规范化。
- Request Body 大小限制。
- HTTP Method 限制。
- IP 黑白名单。
- Hop-by-Hop Header 处理。
- 敏感 Header 清除。
- 可信代理链处理。
- 内部身份 Header 防伪造。
- 管理接口访问隔离。
- 配置管理 API 认证。

P1：

- mTLS。
- WAF Integration。
- SQL Injection Detection。
- XSS Detection。
- Path Traversal Detection。
- Bot Protection。
- IP Reputation。
- Request Anomaly Detection。

必须正确处理：

- `Forwarded`。
- `X-Forwarded-For`。
- `X-Forwarded-Proto`。
- `X-Request-ID`。
- `traceparent`。

不能无条件信任任意客户端传来的 X-Forwarded-For。

只有配置为可信代理的上游 IP 才允许作为转发链中的可信信息来源。

必须移除客户端伪造的内部身份 Header，再由网关注入可信上下文。

## 4.10 Observability

优先级：P0

### Structured Logging

采用 JSON 结构化日志。

记录：

- timestamp。
- level。
- gateway_instance_id。
- request_id。
- trace_id。
- method。
- route_id。
- service_id。
- upstream_endpoint。
- response_status。
- request_duration。
- upstream_duration。
- error_code。
- error_message。

禁止记录：

- 密码。
- 完整 JWT。
- API Key。
- 私钥。
- 敏感用户数据。
- 未脱敏的敏感 Query 参数。

### Metrics

必须提供：

```text
gateway_requests_total
gateway_request_duration_seconds
gateway_request_bytes_total
gateway_response_bytes_total
gateway_active_connections
gateway_active_requests
gateway_upstream_requests_total
gateway_upstream_duration_seconds
gateway_upstream_errors_total
gateway_upstream_connections
gateway_rate_limited_total
gateway_auth_failures_total
gateway_circuit_breaker_state
gateway_retry_total
gateway_config_version
gateway_config_update_total
gateway_endpoint_health
gateway_plugin_errors_total
```

指标必须支持：

- 全局。
- Route。
- Service。
- Upstream。
- Status Code。

不得将用户 ID、完整 URL、动态路径参数等高基数数据作为默认 Prometheus Label。

### Distributed Tracing

使用 OpenTelemetry。

支持：

- Trace ID 传递。
- Span 创建。
- HTTP Server Span。
- HTTP Client Span。
- 上下游调用关系。
- 错误记录。
- Trace Context。
- 采样策略。
- OTLP 导出。

遵守 W3C Trace Context 标准。

## 4.11 Configuration Management

优先级：P0

### 配置来源

支持：

1. YAML。
2. TOML。
3. PostgreSQL 中的控制面配置。
4. 控制面分发的运行时 Snapshot。

优先级：

- 环境变量覆盖文件配置中的部署级设置。
- 数据面业务路由和策略配置由有效配置 Snapshot 决定。
- 不允许不同配置来源形成不明确的冲突优先级。

### 动态配置

必须支持：

- 配置加载。
- 格式校验。
- 业务校验。
- 版本生成。
- 配置发布。
- ACK。
- NACK。
- 热更新。
- 配置快照。
- 配置回滚。
- 最后有效配置保护。

### 原子更新

数据面使用不可变运行时配置快照。

推荐通过 `Arc` + 原子指针交换（例如 `ArcSwap`）实现。

更新流程：

```text
收到配置 Snapshot
        |
        v
Schema Validation
        |
        v
Reference Validation
        |
        v
Compile Runtime Config
        |
        v
Build New Route Table
        |
        v
Build New Upstream State
        |
        v
Prepare Plugins
        |
        v
Atomic Snapshot Swap
        |
        v
ACK Version
```

如果任何步骤失败：

- 不应用新配置。
- 保留原有配置。
- 返回 NACK。
- 记录具体错误。
- 向控制面反馈失败原因。

不得出现部分路由生效、部分路由未生效的不可预期状态。

### 配置兼容

每个配置必须具有：

- schema_version。
- config_version。
- created_at。
- updated_at。
- checksum。

数据面应拒绝无法识别的配置 Schema 版本。

## 4.12 Plugin System

优先级：P0 基础架构，P1 扩展能力。

采用 Trait + Tower Layer 的插件机制。

插件执行阶段：

```text
REQUEST_PRE_ROUTE
REQUEST_POST_ROUTE
AUTHENTICATION
AUTHORIZATION
REQUEST_PRE_UPSTREAM
UPSTREAM_SELECTION
UPSTREAM_RESPONSE
RESPONSE_PRE_CLIENT
ACCESS_LOG
```

插件接口必须包括：

- 插件名称。
- 插件版本。
- 配置 Schema。
- 初始化。
- 配置校验。
- 插件执行。
- 生命周期管理。
- 错误处理。
- 超时处理。

所有插件必须能够通过配置启用、禁用和指定作用范围。

插件作用范围：

- Global。
- Listener。
- Service。
- Route。
- Consumer。

优先级确定后必须形成确定性的执行顺序。

插件执行应支持短路，例如认证失败后不再继续执行上游代理。

内置插件：

P0：

- Request ID。
- CORS。
- JWT Auth。
- API Key Auth。
- IP Restriction。
- Rate Limit。
- Basic Request Validation。
- Request Rewrite。
- Metrics。
- Access Log。
- Trace Context。

P1：

- Compression。
- Cache。
- Circuit Breaker。
- Retry。
- Canary。
- Header Transformation。
- WAF Integration。

禁止任意插件绕过安全校验。

第一阶段使用编译时注册的内置插件，不实施未经隔离的 Rust `.so` 热加载。

未来可以通过 WASM 沙箱扩展第三方插件。

---

# 第五章：核心请求处理 Pipeline

数据面必须有统一、可测试、可观测的请求执行链。

推荐顺序：

```text
Client Request
      |
      v
1. Network Listener
      |
      v
2. TLS Termination
      |
      v
3. Request ID / Trace Context
      |
      v
4. Request Normalization
      |
      v
5. Basic Security Validation
      |
      v
6. Global IP Restriction
      |
      v
7. Route Matching
      |
      v
8. Consumer Identification
      |
      v
9. Authentication
      |
      v
10. Authorization Policy
      |
      v
11. CORS / Preflight Policy
      |
      v
12. Rate Limiting
      |
      v
13. Request Transformation
      |
      v
14. Service Discovery
      |
      v
15. Endpoint Health Filtering
      |
      v
16. Load Balancing
      |
      v
17. Circuit Breaker / Bulkhead
      |
      v
18. Retry / Timeout
      |
      v
19. Upstream Connection
      |
      v
20. Reverse Proxy
      |
      v
21. Response Transformation
      |
      v
22. Compression
      |
      v
23. Metrics / Access Logging
      |
      v
Client Response
```

这是一条逻辑处理链，不意味着上述步骤必须写成一个巨大的函数。

实现要求：

- 每个阶段职责单一。
- 每个阶段可以独立测试。
- 统一错误类型。
- 统一 Request Context。
- 支持插件短路。
- 支持阶段优先级。
- 处理异常时依然产生必要的观测数据。
- 记录请求在哪个阶段失败。

CORS Preflight、认证和限流等可能存在策略依赖，必须通过明确的执行阶段和配置决定最终顺序。

---

# 第六章：核心数据模型

## 6.1 Gateway

表示一个网关逻辑实例或网关集群。

字段：

```text
id
name
description
enabled
created_at
updated_at
```

## 6.2 GatewayInstance

表示实际运行的数据面实例。

字段：

```text
id
gateway_id
instance_name
node_id
version
status
last_heartbeat_at
config_version
ip_address
zone
metadata
```

状态：

```text
ONLINE
OFFLINE
DEGRADED
DRAINING
```

## 6.3 Listener

字段：

```text
id
gateway_id
name
address
port
protocol
tls_enabled
certificate_id
enabled
```

## 6.4 Route

字段：

```text
id
name
description
enabled
priority
hosts
methods
path_type
path_value
header_matches
query_matches
service_id
plugins
auth_policy_id
rate_limit_policy_id
retry_policy_id
timeout_policy_id
request_transform
response_transform
created_at
updated_at
```

## 6.5 Service

字段：

```text
id
name
description
enabled
protocol
upstream_id
default_timeout
metadata
```

## 6.6 Upstream

字段：

```text
id
name
enabled
load_balance_algorithm
discovery_provider
discovery_config
health_check_config
connection_config
tls_config
```

## 6.7 Endpoint

字段：

```text
id
upstream_id
host
port
weight
zone
enabled
status
metadata
```

动态发现的 Endpoint 状态允许仅存在于运行时，不要求所有 Endpoint 都持久化到 PostgreSQL。

## 6.8 Consumer

字段：

```text
id
name
description
enabled
tenant_id
group_id
created_at
updated_at
```

## 6.9 Credential

字段：

```text
id
consumer_id
credential_type
credential_hash
key_id
enabled
expires_at
created_at
```

不得保存明文 API Key。

## 6.10 AuthPolicy

字段：

```text
id
name
enabled
auth_type
auth_config
failure_mode
```

## 6.11 RateLimitPolicy

字段：

```text
id
name
enabled
algorithm
limit
window
burst
key_strategy
scope
backend
failure_mode
```

## 6.12 RetryPolicy

字段：

```text
id
name
enabled
max_retries
retryable_status_codes
retryable_errors
backoff_strategy
base_delay
max_delay
jitter
```

## 6.13 CircuitBreakerPolicy

字段：

```text
id
name
enabled
failure_rate_threshold
minimum_requests
rolling_window
open_duration
half_open_max_requests
```

## 6.14 Plugin

字段：

```text
id
name
version
enabled
scope_type
scope_id
priority
config
```

## 6.15 ConfigVersion

字段：

```text
id
gateway_id
version
schema_version
checksum
status
compiled_config
created_by
created_at
published_at
```

状态：

```text
DRAFT
VALIDATED
PUBLISHED
FAILED
ROLLED_BACK
```

## 6.16 AuditLog

字段：

```text
id
operator_id
operation
resource_type
resource_id
before_value
after_value
result
ip_address
created_at
```

---

# 第七章：运行配置格式

数据面必须支持本地 YAML 配置。

示例：

```yaml
gateway:
  id: gateway-default
  instance_name: gateway-node-01
  environment: development

server:
  http:
    enabled: true
    address: 0.0.0.0
    port: 8080
  admin:
    enabled: true
    address: 127.0.0.1
    port: 8081
  grpc:
    enabled: false

runtime:
  worker_threads: auto
  max_connections: 10000
  graceful_shutdown_timeout: 30s

observability:
  logging:
    level: info
    format: json
  metrics:
    enabled: true
    path: /metrics
  tracing:
    enabled: true
    exporter: otlp

control_plane:
  enabled: false

  endpoint: https://control.example.internal

  sync:
    heartbeat_interval: 10s
    reconnect_interval: 5s
    snapshot_timeout: 10s

upstreams:
  - id: user-upstream
    algorithm: weighted_round_robin

    endpoints:
      - host: 10.0.0.11
        port: 8080
        weight: 5

      - host: 10.0.0.12
        port: 8080
        weight: 3

services:
  - id: user-service
    protocol: http
    upstream_id: user-upstream

routes:
  - id: user-route
    enabled: true
    priority: 100

    hosts:
      - api.example.com

    methods:
      - GET
      - POST

    path:
      type: prefix
      value: /api/users

    service_id: user-service

    timeout:
      connect: 2s
      response: 10s
      total: 15s

    authentication:
      enabled: true
      type: jwt

    rate_limit:
      enabled: true
      algorithm: token_bucket
      requests_per_second: 100
      burst: 200

    retry:
      enabled: false
      max_retries: 0
```

要求：

- YAML Schema 必须有正式定义。
- 示例中的时间格式必须被解析并验证。
- 必须支持环境变量注入敏感配置。
- 禁止将真实密钥写入示例文件。
- 必须提供完整示例配置。
- 配置加载失败必须给出明确错误路径和错误信息。
- 未知字段处理策略必须明确，不能默默接受不支持的配置。

---

# 第八章：Control Plane API

所有管理 API 统一使用：

```text
/api/admin/v1
```

管理 API 绝不能直接暴露在公网业务 Listener 上。

## 8.1 系统 API

```http
GET /api/admin/v1/health
GET /api/admin/v1/ready
GET /api/admin/v1/version
GET /api/admin/v1/instances
GET /api/admin/v1/instances/{id}
```

## 8.2 Listener API

```http
GET    /api/admin/v1/listeners
GET    /api/admin/v1/listeners/{id}
POST   /api/admin/v1/listeners
PUT    /api/admin/v1/listeners/{id}
DELETE /api/admin/v1/listeners/{id}
```

## 8.3 Route API

```http
GET    /api/admin/v1/routes
GET    /api/admin/v1/routes/{id}
POST   /api/admin/v1/routes
PUT    /api/admin/v1/routes/{id}
DELETE /api/admin/v1/routes/{id}
POST   /api/admin/v1/routes/validate
POST   /api/admin/v1/routes/test
```

## 8.4 Service API

```http
GET    /api/admin/v1/services
GET    /api/admin/v1/services/{id}
POST   /api/admin/v1/services
PUT    /api/admin/v1/services/{id}
DELETE /api/admin/v1/services/{id}
```

## 8.5 Upstream API

```http
GET    /api/admin/v1/upstreams
GET    /api/admin/v1/upstreams/{id}
POST   /api/admin/v1/upstreams
PUT    /api/admin/v1/upstreams/{id}
DELETE /api/admin/v1/upstreams/{id}
GET    /api/admin/v1/upstreams/{id}/endpoints
```

## 8.6 Consumer API

```http
GET    /api/admin/v1/consumers
GET    /api/admin/v1/consumers/{id}
POST   /api/admin/v1/consumers
PUT    /api/admin/v1/consumers/{id}
DELETE /api/admin/v1/consumers/{id}

POST   /api/admin/v1/consumers/{id}/credentials
DELETE /api/admin/v1/consumers/{id}/credentials/{credential_id}
```

## 8.7 Policy API

```http
GET  /api/admin/v1/auth-policies
POST /api/admin/v1/auth-policies
PUT  /api/admin/v1/auth-policies/{id}

GET  /api/admin/v1/rate-limit-policies
POST /api/admin/v1/rate-limit-policies
PUT  /api/admin/v1/rate-limit-policies/{id}

GET  /api/admin/v1/retry-policies
POST /api/admin/v1/retry-policies
PUT  /api/admin/v1/retry-policies/{id}

GET  /api/admin/v1/circuit-breaker-policies
POST /api/admin/v1/circuit-breaker-policies
PUT  /api/admin/v1/circuit-breaker-policies/{id}
```

## 8.8 Plugin API

```http
GET  /api/admin/v1/plugins
GET  /api/admin/v1/plugins/{id}
POST /api/admin/v1/plugins
PUT  /api/admin/v1/plugins/{id}
POST /api/admin/v1/plugins/{id}/enable
POST /api/admin/v1/plugins/{id}/disable
```

## 8.9 Configuration API

```http
GET  /api/admin/v1/config
POST /api/admin/v1/config/validate
POST /api/admin/v1/config/compile
POST /api/admin/v1/config/publish
GET  /api/admin/v1/config/versions
GET  /api/admin/v1/config/versions/{id}
POST /api/admin/v1/config/versions/{id}/rollback
```

发布配置必须经过完整校验。

## 8.10 Audit API

```http
GET /api/admin/v1/audit-logs
GET /api/admin/v1/audit-logs/{id}
```

所有管理 API：

- 必须验证调用者身份。
- 必须实行 RBAC。
- 必须校验输入。
- 必须记录操作审计。
- 必须支持分页。
- 必须统一错误结构。
- 对配置修改操作建议支持幂等请求标识。
- 不允许将内部异常堆栈直接返回客户端。

---

# 第九章：Control Plane 与 Data Plane 配置同步协议

采用基于 Tonic 的 gRPC Streaming。

这是本项目自定义配置同步协议，第一阶段不宣称兼容 Envoy xDS。

## 9.1 连接流程

```text
Data Plane
    |
    | Establish mTLS gRPC Connection
    v
Control Plane
    |
    | Register Instance
    v
Authentication
    |
    | Get Full Configuration Snapshot
    v
Data Plane
    |
    | Validate / Compile / Apply
    v
ACK / NACK
    |
    v
Control Plane
```

## 9.2 消息类型

至少支持：

```text
RegisterInstance
InstanceHeartbeat
ConfigSnapshot
ConfigUpdate
ConfigAck
ConfigNack
ConfigRequest
InstanceStatus
```

## 9.3 配置分发要求

- 每个配置具有唯一版本号。
- 每次发布生成完整配置快照。
- 支持通过版本号判断是否需要更新。
- 支持全量 Snapshot。
- 未来可以支持 Delta Update。
- 支持配置校验 ACK / NACK。
- 支持连接断开重连。
- 支持实例心跳。
- 支持配置同步状态查看。
- 支持配置发布进度查看。

## 9.4 可靠性

- Data Plane 失去 Control Plane 连接后继续运行。
- Data Plane 必须保留最后一份有效配置。
- 重连后必须检查当前配置版本。
- 版本不一致时重新获取完整 Snapshot。
- NACK 不得覆盖当前运行配置。
- 配置版本不能倒退，回滚必须作为新发布版本处理。
- 配置消息必须有认证和完整性保护。

---

# 第十章：数据库设计要求

控制面采用 PostgreSQL。

至少建立以下表：

```text
gateways
gateway_instances
listeners
routes
services
upstreams
upstream_endpoints
consumers
consumer_credentials
auth_policies
rate_limit_policies
retry_policies
circuit_breaker_policies
plugins
plugin_configs
tls_certificates
config_versions
config_publish_records
audit_logs
```

设计原则：

1. 所有表必须有明确主键。
2. 需要关联的资源必须有外键或等效完整性校验。
3. 删除操作必须考虑被引用关系。
4. 必要字段设置 NOT NULL。
5. 合理使用 UNIQUE。
6. 高频查询字段建立索引。
7. 时间字段统一采用 UTC。
8. 敏感信息必须加密或只保存安全摘要。
9. 数据库迁移由 SQLx Migrations 管理。
10. 所有 Schema 变更必须通过 Migration。
11. 不允许业务运行时随意自动修改数据库表结构。

配置发布建议使用事务：

```text
Begin Transaction
    |
    v
Save Configuration
    |
    v
Generate Version
    |
    v
Save Audit Record
    |
    v
Commit
    |
    v
Notify Distributor
```

配置分发失败不得回滚已经成功保存的历史配置版本。

发布状态与实例应用状态应分开记录。

---

# 第十一章：错误处理规范

统一定义错误码：

```text
GATEWAY_INTERNAL_ERROR
GATEWAY_BAD_REQUEST
GATEWAY_ROUTE_NOT_FOUND
GATEWAY_METHOD_NOT_ALLOWED
GATEWAY_AUTHENTICATION_FAILED
GATEWAY_AUTHORIZATION_FAILED
GATEWAY_RATE_LIMITED
GATEWAY_REQUEST_TOO_LARGE
GATEWAY_UPSTREAM_UNAVAILABLE
GATEWAY_UPSTREAM_TIMEOUT
GATEWAY_UPSTREAM_CONNECTION_ERROR
GATEWAY_CIRCUIT_OPEN
GATEWAY_CONFIGURATION_INVALID
GATEWAY_CONFIGURATION_APPLY_FAILED
GATEWAY_RESOURCE_EXHAUSTED
```

建议 HTTP 状态码：

| 场景 | 状态码 |
|---|---|
| 输入错误 | 400 |
| 未认证 | 401 |
| 无权限 | 403 |
| 无匹配路由 | 404 |
| Method 不支持 | 405 |
| 请求体过大 | 413 |
| 限流 | 429 |
| 上游不可用 | 503 |
| 网关内部超时 | 504 |
| 上游响应异常 | 根据错误映射策略 |

所有错误响应采用统一 JSON 结构：

```json
{
  "code": "GATEWAY_UPSTREAM_TIMEOUT",
  "message": "Upstream request timeout",
  "request_id": "req-001",
  "trace_id": "trace-001"
}
```

不得在响应中输出敏感内部配置、密钥或完整堆栈。

---

# 第十二章：高可用和生产部署要求

优先级：P0

必须支持：

1. 多 Data Plane 实例。
2. 负载均衡部署。
3. 无状态流量处理。
4. 优雅关闭。
5. 在途请求处理。
6. Readiness。
7. Liveness。
8. 连接池管理。
9. 连接限制。
10. 并发限制。
11. 过载保护。
12. 配置本地持久化。
13. 配置恢复。
14. 控制面故障隔离。
15. 日志文件或标准输出。
16. 容器运行。
17. Docker 部署。
18. Linux 部署。

### 优雅关闭流程

```text
Receive SIGTERM
      |
      v
Set Instance Draining
      |
      v
Update Readiness = false
      |
      v
Stop Accepting New Connections
      |
      v
Wait for In-flight Requests
      |
      v
Flush Telemetry
      |
      v
Shutdown
```

必须设置最大 Graceful Shutdown Timeout。

超过时间必须取消剩余任务并退出，不能无限等待。

### 故障隔离

以下组件单独故障时，不应导致整个网关无差别瘫痪：

- PostgreSQL。
- Redis。
- OpenTelemetry Collector。
- 单个插件。
- 单个上游实例。
- Control Plane。
- 外部服务发现提供者。

具体降级行为应由功能风险决定。

---

# 第十三章：安全要求

必须满足：

1. 数据面管理端口默认不监听公网。
2. Control Plane 管理 API 必须身份认证。
3. 管理接口必须具有 RBAC。
4. Data Plane 与 Control Plane 通信必须采用 mTLS。
5. API Key 不能明文持久化。
6. JWT 算法必须使用白名单。
7. 内部 Header 必须防伪造。
8. TLS 私钥必须安全保存。
9. 日志必须脱敏。
10. 配置变更必须审计。
11. 所有外部输入必须校验。
12. 不允许使用 `unsafe`，除非存在明确、经过审查的必要性。
13. 不允许在错误信息中输出密钥。
14. 不允许将动态路由匹配变成不受约束的任意代码执行。
15. 服务发现产生的上游地址必须经过网络访问策略检查，降低 SSRF 风险。
16. 防止 HTTP Request Smuggling 和 Hop-by-Hop Header 处理错误。
17. 可信代理链必须显式配置。
18. 内部服务管理接口不得被普通业务路由意外暴露。

---

# 第十四章：项目目录结构

采用 Cargo Workspace。

推荐结构：

```text
rust-gateway/
│
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── .gitignore
├── README.md
│
├── apps/
│   ├── gateway/
│   │   └── src/
│   │       ├── main.rs
│   │       ├── bootstrap.rs
│   │       └── cli.rs
│   │
│   ├── gateway-control/
│   │   └── src/
│   │       ├── main.rs
│   │       └── bootstrap.rs
│   │
│   └── gatewayctl/
│       └── src/
│           └── main.rs
│
├── crates/
│   ├── gateway-common/
│   │   └── src/
│   │
│   ├── gateway-config/
│   │   └── src/
│   │
│   ├── gateway-core/
│   │   └── src/
│   │
│   ├── gateway-runtime/
│   │   └── src/
│   │
│   ├── gateway-network/
│   │   └── src/
│   │
│   ├── gateway-proxy/
│   │   └── src/
│   │
│   ├── gateway-routing/
│   │   └── src/
│   │
│   ├── gateway-upstream/
│   │   └── src/
│   │
│   ├── gateway-discovery/
│   │   └── src/
│   │
│   ├── gateway-security/
│   │   └── src/
│   │
│   ├── gateway-traffic/
│   │   └── src/
│   │
│   ├── gateway-resilience/
│   │   └── src/
│   │
│   ├── gateway-plugin/
│   │   └── src/
│   │
│   ├── gateway-transform/
│   │   └── src/
│   │
│   ├── gateway-control-api/
│   │   └── src/
│   │
│   ├── gateway-control-service/
│   │   └── src/
│   │
│   ├── gateway-storage/
│   │   └── src/
│   │
│   ├── gateway-protocol/
│   │   ├── proto/
│   │   └── src/
│   │
│   └── gateway-observability/
│       └── src/
│
├── config/
│   ├── development.yaml
│   ├── standalone.yaml
│   ├── production.example.yaml
│   └── schema/
│
├── migrations/
│
├── deploy/
│   ├── docker/
│   ├── compose/
│   └── kubernetes/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── GATEWAY_REQUIREMENTS.md
│   ├── CONFIGURATION.md
│   ├── API.md
│   ├── PLUGIN_DEVELOPMENT.md
│   ├── SECURITY.md
│   ├── DEPLOYMENT.md
│   └── DEVELOPMENT.md
│
├── tests/
│   ├── integration/
│   ├── e2e/
│   ├── fixtures/
│   └── mock-services/
│
└── benches/
```

### 目录设计原则

1. `apps` 只放可执行程序，不实现大量业务逻辑。
2. `crates` 存放可复用和相对独立的模块。
3. `gateway-core` 不允许依赖具体 Admin API 实现。
4. `gateway-runtime` 负责组合数据面运行时。
5. `gateway-control-api` 负责管理 API。
6. `gateway-storage` 负责数据库访问。
7. `gateway-discovery` 负责服务发现适配器。
8. `gateway-proxy` 负责代理核心能力。
9. `gateway-plugin` 负责插件接口与注册。
10. `gateway-common` 不允许演变成存放所有代码的杂物箱。
11. 不允许循环依赖。
12. 不能为了目录数量而把简单代码强制拆成多个 Crate。
13. 所有模块必须具有清晰的公开接口。

如果以后需要将 Data Plane 或 Control Plane 单独拿出去，应该能够通过 Cargo Workspace 内明确的 Crate 依赖关系独立构建，而不依赖整个业务项目中的其他语言或项目目录。

---

# 第十五章：核心模块依赖关系

必须遵守以下依赖方向：

```text
Apps
  |
  v
Runtime / Control Service
  |
  +------> Core
  |
  +------> Routing
  |
  +------> Proxy
  |
  +------> Security
  |
  +------> Traffic
  |
  +------> Resilience
  |
  +------> Discovery
  |
  +------> Plugin
  |
  +------> Observability
  |
  +------> Config
  |
  +------> Storage (Control Plane Only)
```

约束：

- Core 不依赖 App。
- Core 不依赖具体数据库。
- Route Engine 不依赖 PostgreSQL。
- Data Plane Runtime 不依赖 Control API。
- Proxy 不直接修改配置数据库。
- Plugin 不允许绕过 Core 的安全边界。
- Observability 不得成为请求成功的前提条件。
- 所有基础设施调用必须可以替换实现。
- 业务逻辑不得反向依赖网关实现。

所有跨模块交互尽量使用接口和依赖注入，不允许大量使用全局可变单例。

---

# 第十六章：测试要求

## 16.1 Unit Test

所有核心模块必须具有单元测试。

至少覆盖：

- 路由匹配。
- 路由优先级。
- 路由冲突。
- Header 匹配。
- Path Rewrite。
- Load Balancing。
- Token Bucket。
- JWT 验证。
- API Key 验证。
- Circuit Breaker。
- Retry。
- Timeout。
- Config Validation。
- Config Atomic Update。
- Plugin Execution。
- Error Mapping。

## 16.2 Integration Test

必须测试：

1. 客户端请求通过网关访问模拟上游。
2. 多个 Endpoint 负载均衡。
3. 上游实例故障剔除。
4. 服务恢复。
5. JWT 认证。
6. API Key 认证。
7. IP 限制。
8. QPS 限流。
9. 熔断。
10. 重试。
11. 请求超时。
12. 路由动态更新。
13. 配置发布。
14. 配置回滚。
15. Control Plane 断开。
16. Data Plane 重连。
17. 数据面无效配置 NACK。
18. 多实例配置同步。

## 16.3 E2E Test

使用 Docker Compose 启动：

- Gateway。
- Control Plane。
- PostgreSQL。
- Redis（可选）。
- Mock User Service。
- Mock Order Service。
- Prometheus（可选）。

通过真实 HTTP 请求验证完整链路。

## 16.4 Performance Test

必须建立基准压测。

测试场景：

1. 纯 HTTP 代理。
2. 简单路由。
3. JWT 认证。
4. 本地限流。
5. Redis 限流。
6. 完整中间件链。
7. 多 Endpoint 负载均衡。
8. 大请求体流式转发。
9. 长连接。
10. HTTP/2。

统计：

- QPS。
- 并发数。
- P50。
- P90。
- P95。
- P99。
- CPU。
- Memory。
- Network Throughput。
- Error Rate。

必须记录压测机器、连接方式、Payload 大小、配置和软件版本。

禁止虚构 QPS 或声称达到生产级性能而没有压测报告。

## 16.5 Code Quality

提交前必须通过：

```bash
cargo fmt --all -- --check

cargo clippy --workspace --all-targets --all-features -- -D warnings

cargo test --workspace

cargo build --workspace --release
```

如果有某个测试或 Clippy 检查需要环境变量或外部依赖，必须在文档中说明，并提供可复现的启动方式。

---

# 第十七章：实施阶段和交付标准

不得一次生成全部代码。

按阶段开发，每个阶段必须能够编译、运行和测试。

## Phase 1：项目骨架与核心运行时

P0。

实现：

- Cargo Workspace。
- 配置加载。
- 错误处理。
- Logging。
- HTTP Listener。
- Hyper Client。
- 基础反向代理。
- Route Engine。
- Static Upstream。
- Round Robin。
- JSON Access Log。
- Health Check。
- Graceful Shutdown。

验收：

- 能够成功启动网关。
- 能够将请求转发到模拟后端。
- 能够根据域名、路径、Method 路由。
- 能够进行多个实例间负载均衡。
- 能够处理上游连接失败。
- 能够正确关闭。

## Phase 2：基础网关治理

P0。

实现：

- JWT。
- API Key。
- IP Allowlist / Denylist。
- Token Bucket。
- Fixed Window。
- Request ID。
- CORS。
- Timeout。
- Retry。
- Circuit Breaker。
- Basic Plugin System。
- Request Transformation。
- Response Header Transformation。

验收：

- 每项策略有独立测试。
- 多个策略组合执行正确。
- 不允许认证失败的请求访问上游。
- 不允许不安全重试。
- 熔断后能够正确恢复。

## Phase 3：配置管理与控制面

P0。

实现：

- Axum Admin API。
- PostgreSQL。
- SQLx。
- Config Version。
- Config Validation。
- Config Compiler。
- Config Snapshot。
- Dynamic Update。
- Config Rollback。
- Audit Log。

验收：

- 可以通过 API 新建路由。
- 可以修改 Upstream。
- 可以创建限流策略。
- 可以发布配置。
- 不重启网关即可更新配置。
- 无效配置无法生效。
- 可以回滚配置。
- 数据面使用本地有效配置继续转发。

## Phase 4：集群和配置分发

P0。

实现：

- Tonic gRPC。
- Data Plane Registration。
- Heartbeat。
- Config Snapshot Distribution。
- ACK / NACK。
- Reconnection。
- Version Sync。
- Last Known Good Configuration。

验收：

- 多个 Data Plane 可以连接同一 Control Plane。
- 修改配置后所有实例收到更新。
- 配置应用失败时旧配置继续有效。
- 控制面故障不导致数据面停止服务。
- 重连后可以重新获取最新配置。

## Phase 5：可观测性与生产部署

P0。

实现：

- Prometheus Metrics。
- OpenTelemetry。
- JSON Logging。
- Request Trace。
- Docker。
- Docker Compose。
- Linux 部署。
- Deployment 文档。
- 完整 E2E 测试。

验收：

- 能查看请求量。
- 能查看 P99。
- 能查看上游耗时。
- 能查看限流次数。
- 能查看认证失败次数。
- 能关联 Request ID 和 Trace ID。
- 能够容器化部署。

## Phase 6：高级流量治理

P1。

实现：

- Canary。
- Blue-Green。
- Weighted Routing。
- Traffic Mirroring。
- Least Connections。
- Consistent Hash。
- Kubernetes Service Discovery。
- Redis Distributed Rate Limit。
- WebSocket。
- SSE。
- gRPC。

验收：

- 能够配置灰度比例。
- 能够进行版本路由。
- 能够隔离镜像请求。
- 能够发现 Kubernetes Endpoint。
- 能够代理 gRPC 请求。

## Phase 7：平台化能力

P2。

实现：

- Multi-Tenant。
- Developer Portal API。
- API Lifecycle。
- OpenAPI Import。
- API Quota。
- Certificate Management。
- WAF Integration。
- WASM Plugin。
- 多集群和多地域配置。

验收标准按具体子模块补充。

---

# 第十八章：AI 编程执行约束

AI IDE 必须严格遵守以下要求。

## 18.1 开发前

1. 先检查现有项目目录。
2. 确认是否已经存在 Cargo Workspace。
3. 阅读已有 README 和架构文档。
4. 不得无条件覆盖已经实现的代码。
5. 先建立项目架构和依赖关系。
6. 先确认所使用 Rust Crate 的当前稳定 API。
7. 不允许凭记忆编写已经变更的第三方 Crate API。
8. 不允许擅自改变本需求中确定的架构。

## 18.2 编码规范

1. 优先使用 Rust Stable。
2. 默认禁止 unsafe。
3. 必须处理 Result 和 Option。
4. 不允许使用大量 unwrap/expect 处理生产逻辑。
5. 异步函数必须正确处理取消。
6. 不得在 Tokio Worker 中执行长时间阻塞任务。
7. 避免无界 Channel。
8. 避免无限制创建 Task。
9. 避免全局可变状态。
10. 不允许循环依赖。
11. 不允许为未来功能提前写大量无用框架。
12. 核心接口必须有文档注释。
13. 复杂逻辑必须有必要的注释。
14. 重要配置必须有默认值及校验。
15. 不能以 TODO 或空函数冒充功能已实现。
16. 不能通过忽略测试、删除测试来解决问题。

## 18.3 架构约束

1. 数据面与控制面必须解耦。
2. Axum 不得承担完整数据面代理引擎。
3. 核心模块通过接口解耦。
4. 数据面不能对 PostgreSQL 形成运行时强依赖。
5. 不允许每个请求都从数据库加载路由。
6. 配置更新必须原子化。
7. 插件执行必须有明确阶段。
8. 服务发现必须可以更换 Provider。
9. 负载均衡必须可以更换策略。
10. 限流必须可以更换实现。
11. 配置管理不得破坏已有请求处理能力。
12. 数据面应支持独立部署。

## 18.4 每个开发阶段的执行流程

每次实施一个 Phase，都必须遵循：

```text
阅读需求
   |
   v
检查当前代码
   |
   v
设计本阶段模块
   |
   v
实现接口和数据模型
   |
   v
实现业务代码
   |
   v
编写单元测试
   |
   v
编写集成测试
   |
   v
运行 Cargo Check
   |
   v
运行 Clippy
   |
   v
运行测试
   |
   v
修复错误
   |
   v
更新文档
   |
   v
提交阶段报告
```

每个阶段完成后，必须给出：

- 新增目录。
- 新增文件。
- 修改文件。
- 已实现功能。
- 未实现功能。
- 使用的第三方依赖。
- 测试结果。
- 编译结果。
- 已知问题。
- 下一阶段建议。

不允许在阶段报告中将未完成的功能描述成已完成。

## 18.5 第一阶段最终交付物

第一阶段至少交付：

1. 完整 Cargo Workspace。
2. Gateway 可执行程序。
3. Hyper 反向代理。
4. 路由匹配。
5. Upstream。
6. 负载均衡。
7. YAML 配置。
8. JSON 日志。
9. 健康检查。
10. 优雅关闭。
11. 单元测试。
12. 集成测试。
13. Dockerfile。
14. README。
15. 架构说明文档。

---

# 第十九章：最终项目验收标准

整个项目只有满足以下基本条件，才可以认为已经形成一个可用的生产级 API Gateway 基础版本。

### 功能验收

- [ ] 支持 HTTP/1.1。
- [ ] 支持 HTTP/2。
- [ ] 支持 HTTPS。
- [ ] 支持动态路由。
- [ ] 支持多条件路由。
- [ ] 支持上游服务管理。
- [ ] 支持服务发现。
- [ ] 支持多种负载均衡。
- [ ] 支持 JWT。
- [ ] 支持 API Key。
- [ ] 支持 IP 访问控制。
- [ ] 支持限流。
- [ ] 支持超时。
- [ ] 支持安全重试。
- [ ] 支持熔断。
- [ ] 支持插件。
- [ ] 支持请求转换。
- [ ] 支持访问日志。
- [ ] 支持 Metrics。
- [ ] 支持 Tracing。
- [ ] 支持配置版本。
- [ ] 支持配置热更新。
- [ ] 支持配置回滚。
- [ ] 支持控制面与数据面分离。
- [ ] 支持多数据面实例。
- [ ] 支持配置 ACK / NACK。
- [ ] 支持控制面失联后的独立运行。
- [ ] 支持 Docker 部署。

### 质量验收

- [ ] 所有核心模块有单元测试。
- [ ] 具有完整集成测试。
- [ ] 具有关键链路 E2E 测试。
- [ ] Release 编译通过。
- [ ] Clippy 通过。
- [ ] 无已知未处理的严重安全问题。
- [ ] 没有未完成的核心功能占位实现。
- [ ] 所有管理接口有文档。
- [ ] 所有配置项有文档。
- [ ] 提供部署说明。
- [ ] 提供压测报告。
- [ ] 提供故障恢复测试报告。

达到以上验收标准后，可以将该项目作为整个微服务系统的统一流量入口使用。

---

# 第二十章：官方技术参考

开发时优先参考官方文档：

1. Axum：https://docs.rs/axum/latest/axum/
2. Tower：https://docs.rs/tower/latest/tower/
3. Hyper：https://docs.rs/hyper/latest/hyper/
4. Tokio：https://docs.rs/tokio/latest/tokio/
5. Tonic：https://docs.rs/tonic/latest/tonic/
6. Rustls：https://docs.rs/rustls/latest/rustls/
7. SQLx：https://docs.rs/sqlx/latest/sqlx/
8. OpenTelemetry：https://opentelemetry.io/docs/languages/rust/
9. Prometheus：https://prometheus.io/docs/introduction/overview/
10. Kubernetes Gateway API：https://gateway-api.sigs.k8s.io/
11. Apache APISIX Architecture：https://apisix.apache.org/docs/apisix/architecture-design/apisix/
12. Envoy Dynamic Configuration：https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration

以上文档是实现参考，不代表必须复制其他产品的全部架构。

最终代码必须遵循本需求确定的模块边界、技术选型和验收标准。