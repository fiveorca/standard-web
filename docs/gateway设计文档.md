# 项目名称：Rust API Gateway

## 一、你的角色与交付目标

你是一名资深 Rust 系统架构师、网络编程专家和 API Gateway 开发工程师。

请直接在当前项目工作区内，一次性设计、实现并交付一个完整、可编译、可运行、可部署的生产级 API Gateway 网关服务。

项目使用 Rust + Axum 技术栈，功能以 Spring Cloud Gateway 为参考基准，但不要求兼容 Spring Cloud Gateway 的 Java API 或配置语法。

**这是一次完整交付任务，不是分阶段开发任务。**

必须遵守：

1. 不要先输出设计方案等待确认。
2. 不要将需求拆分成多个阶段，也不要只实现 MVP。
3. 不要反复向我询问技术选型，未指定的细节由你根据成熟度、稳定性、性能和可维护性自行决定。
4. 不要只生成目录结构、接口定义、伪代码或示例代码，必须实现真实可运行的功能。
5. 不允许以 TODO、占位实现、模拟数据代替实际功能。
6. 直接创建和修改项目文件，不能只在聊天窗口输出代码。
7. 在实现过程中自行编译、检查、运行测试，修复发现的问题。
8. 最终交付必须包含完整源代码、配置文件、数据库以外的必要依赖、部署文件、测试和中文文档。
9. 不能为了追求功能数量而编写不安全、不完整的网络代理逻辑。
10. 如果某项能力无法可靠实现，必须明确指出，不得伪称已经实现。

最终目标是一个可以独立部署、独立运行、独立扩展的 Rust API Gateway。

## 二、技术栈与架构约束

### 2.1 基础技术栈

- 编程语言：Rust Stable。
- HTTP 框架：Axum 0.8.x。
- 异步运行时：Tokio。
- 中间件：Tower、Tower-HTTP。
- HTTP 底层：Hyper 及 Hyper-Util。
- HTTP 客户端及上游连接：选择能够支持连接池、流式请求/响应、TLS 和 HTTP/2 的成熟实现。
- TLS：Rustls。
- 序列化：Serde。
- 配置文件：YAML。
- 日志：Tracing。
- JWT：使用维护活跃的 Rust JWT 库。
- Redis：使用成熟的异步 Redis 客户端。
- 服务发现：Consul HTTP API。
- 监控：Prometheus。
- 分布式追踪：OpenTelemetry。
- 缓存：Moka 或其他成熟异步缓存组件。
- 正则表达式：Regex。
- 配置热更新：使用线程安全、支持原子更新的配置快照机制。

优先选择稳定、维护活跃、文档完善的 Rust 生态组件。

所有依赖必须检查兼容性，统一使用兼容的版本，生成 Cargo.lock。

不要为了减少依赖而自行重复实现已经成熟的基础组件。

### 2.2 架构要求

整体采用单独部署的独立网关服务。

项目内部采用模块化架构，模块之间通过清晰的接口解耦。

要求：

- 业务代码与 HTTP 框架尽可能解耦。
- 配置加载、路由匹配、请求过滤、认证、限流、负载均衡、服务发现、代理转发、监控之间职责独立。
- 不允许将所有功能全部堆积在 main.rs。
- 不依赖 Java、Spring Cloud 或其他业务服务的内部实现。
- 可以代理 Java、Rust、Python、Node.js、Go 等任意 HTTP 后端服务。
- 支持独立部署、Docker 部署和集群部署。
- 预留扩展接口，便于后续替换 Redis、Consul 或增加其他服务发现实现。

建议采用如下目录结构，允许根据实际需要调整，但必须保持模块边界清晰：

```text
rust-api-gateway/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── config/
│   ├── gateway.yaml
│   ├── routes.yaml
│   └── development.yaml
├── src/
│   ├── main.rs
│   ├── bootstrap/
│   ├── config/
│   ├── core/
│   │   ├── gateway/
│   │   ├── route/
│   │   ├── predicate/
│   │   ├── filter/
│   │   ├── proxy/
│   │   ├── upstream/
│   │   ├── load_balancer/
│   │   ├── service_discovery/
│   │   └── runtime/
│   ├── middleware/
│   │   ├── authentication/
│   │   ├── authorization/
│   │   ├── rate_limit/
│   │   ├── cors/
│   │   ├── ip_filter/
│   │   ├── request_id/
│   │   └── security/
│   ├── resilience/
│   │   ├── circuit_breaker/
│   │   ├── retry/
│   │   ├── timeout/
│   │   └── health_check/
│   ├── cache/
│   ├── admin/
│   ├── observability/
│   ├── transport/
│   ├── error/
│   └── utils/
├── tests/
│   ├── integration/
│   ├── proxy/
│   ├── authentication/
│   ├── rate_limit/
│   └── routing/
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── prometheus.yml
├── scripts/
├── docs/
│   ├── README.md
│   ├── architecture.md
│   ├── configuration.md
│   ├── api.md
│   ├── deployment.md
│   └── security.md
└── .github/
    └── workflows/
```

## 三、核心功能需求

### 3.1 路由管理

实现完整的动态路由管理系统。

路由匹配支持：

- Path：路径匹配。
- Host：域名匹配。
- Method：HTTP 方法匹配。
- Header：请求头匹配。
- Query：URL 查询参数匹配。
- Cookie：Cookie 匹配。
- RemoteAddr：客户端 IP 地址匹配。
- After：指定时间之后匹配。
- Before：指定时间之前匹配。
- Between：指定时间区间匹配。

多个 Predicate 默认采用 AND 逻辑。

支持路由优先级、路由启用和禁用、路由 ID、路由元数据。

多个路由同时匹配时，必须遵循明确且可测试的优先级规则。

支持配置文件和管理 API 两种路由管理方式。

### 3.2 请求转发与反向代理

实现真正的 HTTP 反向代理，而不仅仅是路由到 Axum Handler。

必须支持：

- HTTP/1.1。
- HTTP/2。
- HTTPS 上游。
- 请求 Body 流式转发。
- 响应 Body 流式转发。
- 大文件上传和下载。
- Transfer-Encoding 处理。
- WebSocket Upgrade 和双向数据转发。
- gRPC 透明代理。
- HTTP Trailer 保留。
- 请求和响应 Header 转发。
- Keep-Alive。
- 上游连接池。
- 连接复用。
- 上游连接超时。
- 请求超时。
- 响应超时。
- 空闲连接超时。
- 客户端断开时正确取消上游请求。

不得将完整请求和响应 Body 无限制读取到内存再转发。

必须正确处理 Hop-by-Hop Headers，遵守 HTTP 协议要求。

正确处理 Connection、Keep-Alive、Upgrade、TE、Trailer、Transfer-Encoding 等请求头。

正确设置 X-Forwarded-For、X-Forwarded-Host、X-Forwarded-Proto 和标准 Forwarded 信息。

默认不能信任客户端传入的伪造 X-Forwarded-* 信息，必须提供可信代理 IP 配置。

反向代理优先评估成熟的 Axum/Hyper 代理组件，包括 axum-reverse-proxy。必须检查组件的许可证、维护情况和实际能力。

如果现有组件不能满足动态路由、连接复用、流式代理或协议兼容要求，可以使用 Hyper 1.x 生态实现必要的代理层。

禁止简单使用会导致 Body 缓冲或协议能力丢失的实现来冒充完整反向代理。

### 3.3 路径和请求转换

支持以下过滤器：

- StripPrefix。
- RewritePath。
- SetPath。
- PrefixPath。
- AddRequestHeader。
- SetRequestHeader。
- RemoveRequestHeader。
- AddResponseHeader。
- SetResponseHeader。
- RemoveResponseHeader。
- AddRequestParameter。
- PreserveHostHeader。
- RequestHeaderToRequestUri。
- SecureHeaders。

支持自定义 Gateway Filter 和 Global Filter。

过滤器必须具有确定的执行顺序，支持路由级和全局级配置。

### 3.4 服务发现

实现服务发现抽象接口。

必须支持：

1. 静态服务地址配置。
2. Consul 服务注册信息查询。
3. Consul 健康实例过滤。
4. 服务实例定时刷新。
5. 服务注册信息变化更新。
6. 服务发现失败处理。
7. 服务实例上下线处理。

支持使用以下形式配置路由：

```yaml
uri: http://127.0.0.1:8081
```

或者：

```yaml
uri: lb://user-service
```

支持配置不同的服务发现策略。

不得将服务发现逻辑和具体代理实现绑定在一起。

### 3.5 负载均衡

至少支持：

- Round Robin。
- Random。
- Weighted Round Robin 或 Weighted Random。
- Least Connections。
- Power of Two Choices。

支持：

- 实例权重。
- 实例健康状态。
- 自动剔除不可用实例。
- 恢复后重新加入。
- 被动健康检查。
- 主动健康检查。
- 不同路由配置不同的负载均衡策略。

负载均衡必须支持并发访问，不能出现数据竞争或实例状态不一致。

### 3.6 限流

实现完整的流量限制模块。

支持：

- 全局限流。
- 路由限流。
- IP 限流。
- 用户限流。
- 租户限流。
- API Key 限流。
- 自定义 Key 限流。

支持 Token Bucket 算法。

支持两种模式：

1. 本地限流。
2. Redis 分布式限流。

Redis 限流必须采用 Lua 脚本或其他原子操作，确保集群环境下限流结果正确。

限流规则支持：

- 每秒请求数量。
- 每分钟请求数量。
- 每小时请求数量。
- 突发流量容量。
- 不同用户使用不同额度。
- 不同路由使用不同额度。

超出限流阈值时返回 HTTP 429。

响应中提供合理的限流信息。

Redis 不可用时，必须支持明确配置 fail-open 或 fail-closed，不能静默切换导致限流失效。

### 3.7 身份认证

支持：

- JWT Bearer Token。
- JWT 本地签名验证。
- HS256、RS256、ES256 等受支持算法。
- OIDC JWKS 公钥获取。
- JWKS 缓存。
- 公钥自动刷新和轮换。
- Token 过期验证。
- Issuer 验证。
- Audience 验证。
- NBF 验证。
- Token 类型验证。
- Token Relay。

必须避免算法混淆、弱签名算法和密钥配置错误。

支持 API Key 认证，API Key 不允许明文写入代码或普通日志。

路由可以配置：

- public：公开访问。
- authenticated：必须认证。
- scopes：要求指定 Token Scope。
- roles：要求指定角色声明。

认证和授权失败分别返回合理的 HTTP 状态码。

不得将完整 OAuth2 授权服务器、用户注册系统或用户中心写入网关。

网关只负责认证信息验证以及适合在入口层执行的访问控制。

### 3.8 授权扩展

提供统一 AuthorizationProvider 接口。

支持：

- 基于 JWT Scope 的访问控制。
- 基于 JWT Role 的访问控制。
- 基于路由元数据的访问策略。
- 对接外部授权中心。
- 外部授权结果缓存。
- 授权服务请求超时和失败处理。

预留接入独立 RBAC 授权中心的能力。

明确区分接口级访问控制和业务资源级权限。

不得依靠网关判断用户是否有权访问某一个具体订单、文章或其他业务数据。

网关验证 JWT 后，允许向后端传递经过验证的用户身份信息。

必须先删除客户端自行提交的内部身份 Header，再设置由网关生成的可信身份 Header。

### 3.9 IP 访问控制

支持：

- IP 白名单。
- IP 黑名单。
- IPv4。
- IPv6。
- CIDR 网段。
- 全局规则。
- 路由级规则。
- 可信代理 IP 配置。
- 客户端真实 IP 提取。

防止客户端通过伪造 X-Forwarded-For 绕过 IP 限制。

### 3.10 熔断和降级

实现 Circuit Breaker。

支持状态：

- Closed。
- Open。
- Half-Open。

支持配置：

- 失败率阈值。
- 慢请求阈值。
- 统计窗口。
- 最小请求数量。
- 熔断持续时间。
- 半开状态探测请求数量。
- 熔断后的降级响应。

熔断器支持按路由或上游服务隔离。

支持统一 Fallback Handler。

熔断和服务发现的健康状态应当协调，但不能简单把一次业务错误当作永久服务不可用。

### 3.11 重试机制

支持：

- 连接失败重试。
- 上游连接超时重试。
- 指定 HTTP 状态码重试。
- 最大重试次数。
- 重试间隔。
- 指数退避。
- 可配置重试状态码。

默认只对安全、可重放的请求执行重试。

POST 等非幂等请求不得在缺少明确幂等保证的情况下自动重放。

必须识别请求是否已经发送给上游，避免重复执行业务操作。

对于流式 Body 和 WebSocket，不得强行重试已经开始传输的请求。

### 3.12 超时控制

支持不同维度的超时配置：

- 客户端连接超时。
- 上游连接超时。
- TLS 握手超时。
- 请求发送超时。
- 上游响应超时。
- 整体请求超时。
- 空闲连接超时。

支持全局默认值以及路由级覆盖。

### 3.13 缓存

支持 GET 请求的本地响应缓存。

要求：

- TTL。
- 最大缓存容量。
- 缓存 Key 自定义。
- 路由级缓存控制。
- Cache-Control 支持。
- 缓存命中统计。
- 缓存清理。
- 缓存失效策略。

默认不能缓存带有 Authorization 的私有响应，也不能无视 Set-Cookie、Cache-Control: private 等安全语义。

大响应、流式响应和不适合缓存的内容必须自动绕过缓存。

### 3.14 CORS 跨域

支持：

- Allowed Origins。
- Allowed Methods。
- Allowed Headers。
- Exposed Headers。
- Allow Credentials。
- Max Age。
- 全局 CORS。
- 路由级 CORS。

正确处理 OPTIONS 预检请求。

不允许在启用 Credentials 时无条件使用通配符 Origin。

### 3.15 TLS 和安全

支持：

- HTTP 监听。
- HTTPS 监听。
- Rustls。
- TLS 证书和私钥配置。
- 上游 HTTPS 证书校验。
- 可选上游 mTLS。
- 可配置 TLS 协议版本。
- 安全响应头。
- 请求 Header 大小限制。
- 请求 Body 大小限制。
- Host 校验。
- 管理接口访问保护。
- 敏感信息脱敏。
- 上游地址安全校验。

上游 TLS 默认必须验证证书，不能为了调试方便关闭生产环境验证。

必须避免开放代理、SSRF、Header 注入和不可信上游地址等安全问题。

WAF 和 DDoS 防护不属于本次直接实现范围，不能宣称本项目已经具备这些专业防护能力。

### 3.16 监控和日志

集成 Prometheus。

提供：

- 总请求数。
- 请求成功数量。
- 请求失败数量。
- 各 HTTP 状态码数量。
- 请求延迟。
- 路由请求数量。
- 上游请求数量。
- 上游错误数量。
- 限流数量。
- 熔断状态。
- 缓存命中率。
- 当前连接数量。
- 服务发现状态。

提供独立的 Prometheus Metrics Endpoint。

集成 OpenTelemetry，支持 OTLP 导出。

支持 W3C Trace Context 传播。

日志采用结构化 JSON 格式。

至少记录：

- Request ID。
- Trace ID。
- HTTP Method。
- 请求路径。
- 路由 ID。
- 上游服务。
- 响应状态码。
- 请求耗时。
- 客户端 IP。
- 错误原因。

严禁记录完整 Authorization、Cookie、Token、密码或其他敏感信息。

默认禁止记录完整请求和响应 Body。

### 3.17 健康检查

提供：

- Liveness。
- Readiness。
- 服务内部依赖状态。
- Redis 连接状态。
- Consul 连接状态。
- 上游实例健康信息。

健康检查不能阻塞核心代理请求。

Readiness 应正确反映网关是否已经完成初始化，以及必要依赖是否可用。

## 四、网关管理 API

提供独立的管理 API。

管理 API 不经过普通业务路由逻辑。

所有管理接口默认必须认证，并支持限制管理来源 IP。

至少提供以下接口：

```text
GET    /admin/v1/routes
GET    /admin/v1/routes/{id}
POST   /admin/v1/routes
PUT    /admin/v1/routes/{id}
DELETE /admin/v1/routes/{id}

POST   /admin/v1/routes/{id}/enable
POST   /admin/v1/routes/{id}/disable

POST   /admin/v1/config/reload
GET    /admin/v1/config/status

GET    /admin/v1/services
GET    /admin/v1/upstreams
GET    /admin/v1/circuit-breakers
GET    /admin/v1/metrics/summary

GET    /health/live
GET    /health/ready
GET    /metrics
```

所有管理 API 使用统一 JSON 响应结构。

新增、修改路由时必须校验配置是否合法。

路由变更必须采用原子更新，不能让正在处理的请求读到不完整配置。

配置文件支持热加载。

管理 API 更新的路由应当按照明确策略持久化，不能只在内存中生效而没有说明。

多实例部署时支持配置版本和 Redis Pub/Sub 变更通知，避免各网关节点配置不一致。

## 五、路由配置设计

设计合理、可扩展的 YAML 路由配置格式。

例如：

```yaml
gateway:
  server:
    host: 0.0.0.0
    port: 8080

routes:
  - id: user-service
    enabled: true
    order: 10

    predicates:
      - Path=/api/users/**
      - Method=GET,POST,PUT,DELETE

    uri: lb://user-service

    filters:
      - StripPrefix=1
      - AddRequestHeader=X-Gateway, rust-gateway

    authentication:
      mode: authenticated

    timeout:
      connect: 3s
      response: 10s

    retry:
      enabled: true
      max_attempts: 2

    rate_limit:
      enabled: true
      key_type: user
      replenish_rate: 20
      burst_capacity: 40

    circuit_breaker:
      enabled: true
      failure_rate_threshold: 50
      open_duration: 10s

  - id: public-service
    enabled: true
    order: 20

    predicates:
      - Path=/public/**

    uri: http://127.0.0.1:9000

    authentication:
      mode: public
```

以上仅为配置格式示意，请设计完整的配置结构、校验器、默认值以及详细配置文档。

不要将业务逻辑写死在 YAML 配置加载代码中。

## 六、部署和运维

提供：

1. 完整 Dockerfile。
2. Docker Compose。
3. Redis 服务配置。
4. Consul 服务配置。
5. Prometheus 配置。
6. 环境变量配置示例。
7. 开发环境配置。
8. 生产环境配置。
9. 日志轮转建议。
10. 优雅启动。
11. 优雅关闭。
12. 容器非 root 用户运行。
13. 配置文件挂载。
14. TLS 证书挂载。
15. 资源限制建议。

必须提供可直接运行的部署示例。

## 七、测试要求

必须编写真正的单元测试和集成测试。

至少覆盖：

### 路由测试

- Path 匹配。
- Host 匹配。
- Method 匹配。
- Header 匹配。
- 多 Predicate AND 匹配。
- 路由优先级。
- 动态路由更新。

### 代理测试

- 基础 HTTP 转发。
- 路径重写。
- 请求 Header 转发。
- 响应 Header 转发。
- Hop-by-Hop Header 清理。
- 大请求体流式传输。
- 大响应体流式传输。
- 客户端断开处理。
- HTTPS 上游。
- WebSocket。
- gRPC Trailer。

### 安全测试

- JWT 合法 Token。
- JWT 过期。
- JWT 签名错误。
- Issuer 不匹配。
- Audience 不匹配。
- JWKS 公钥刷新。
- IP 黑名单。
- IP 白名单。
- 管理接口未授权访问。
- 客户端伪造身份 Header。

### 限流测试

- IP 限流。
- 用户限流。
- 路由限流。
- Redis 分布式限流。
- Redis 不可用时的策略。

### 高可用测试

- 熔断打开。
- 熔断恢复。
- 服务节点不可用。
- 负载均衡。
- 重试行为。
- 超时行为。

测试必须验证真实行为，而不仅仅是测试函数能否执行。

使用 Mock Upstream 或测试服务构造端到端测试环境。

## 八、质量和性能要求

必须满足：

- Rust 所有权和生命周期设计合理。
- 不使用不必要的 unsafe。
- 不允许使用阻塞操作阻塞 Tokio 异步运行时。
- 不允许无限制缓存请求 Body。
- 避免不必要的锁竞争。
- 优先使用共享配置快照。
- 避免高基数 Prometheus Label。
- 所有错误都有明确处理。
- 所有外部依赖都有超时。
- Redis 和 Consul 操作不得阻塞代理主流程。
- 支持并发请求。
- 不泄漏连接和任务。
- 正确实现优雅关闭。
- 关键资源必须有容量限制。
- 默认配置必须安全。

如果采用第三方代理组件，必须验证其实际功能，而不是仅仅因为存在一个 crate 就认为具备完整网关能力。

## 九、最终验收标准

在最终交付前，必须实际执行以下命令，并修复所有由项目代码导致的问题：

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

如果项目存在必要的外部依赖，使用 Docker Compose 启动依赖并执行对应的集成测试。

最终交付必须具备：

1. 完整的项目源代码。
2. 完整的 Cargo.toml 和 Cargo.lock。
3. 完整的默认配置文件。
4. 至少两个不同业务服务的路由示例。
5. 完整的管理 API。
6. 完整的代理转发。
7. 完整的认证和限流实现。
8. 服务发现和负载均衡。
9. 熔断和重试。
10. 监控和健康检查。
11. Docker 部署文件。
12. 自动化测试。
13. 中文 README。
14. 中文架构说明。
15. 中文配置说明。
16. API 接口说明。
17. 安全说明。
18. 部署和运维文档。

README 必须包含从零开始的启动命令、配置说明、访问示例以及实际可用的 API 调用示例。

## 十、最终执行指令

现在开始直接检查当前工作区，并完成上述全部需求。

不要输出阶段计划，不要等我确认，不要中途要求我选择技术方案。

允许你在内部自行安排实现顺序，但必须在本次任务中完成全部实现，并进行完整编译、测试和修复。

遇到技术实现问题，优先查阅对应 Rust Crate 的官方文档和实际 API，选择兼容、可靠的方案。

如果某个功能存在技术限制，应该选择能够真正实现该功能的方案，而不是删除需求。

最终只在全部工作结束后向我汇报：

- 实际完成了哪些功能。
- 最终项目目录结构。
- 使用的核心技术及依赖。
- 实际执行过的测试和结果。
- 启动和部署命令。
- 仍然存在的限制或未完成项。

**最终交付的是一个真实可运行的完整网关项目，而不是一份方案文档或者代码骨架。**