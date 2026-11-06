# 架构设计

## 1. 总体结构

```
                    ┌────────────────────────────────────────────┐
   Client ────────► │ transport (HTTP/1.1 · HTTP/2 · TLS · mTLS) │
                    └───────────────────┬────────────────────────┘
                                        │ axum Router
                    ┌───────────────────▼────────────────────────┐
                    │ pipeline: 请求处理管线                      │
                    │ request-id → OTel span → IP → 路由匹配      │
                    │ → CORS → 认证 → 授权 → 过滤器 → 限流        │
                    │ → 熔断 → 缓存 → 超时 → 代理 → 响应过滤器    │
                    └───────┬──────────────┬──────────────┬──────┘
                            │              │              │
              ┌─────────────▼───┐  ┌───────▼──────┐  ┌────▼─────────────┐
              │ RouteTable      │  │ AuthService  │  │ ProxyService     │
              │ ArcSwap 快照    │  │ JWT / APIKey │  │ hyper + rustls   │
              └─────────────┬───┘  └──────────────┘  └────┬─────────────┘
                            │                             │
              ┌─────────────▼──────────────┐   ┌──────────▼────────────┐
              │ UpstreamRegistry           │   │ 连接池 / HTTP2 / WS    │
              │ 静态 + Consul + 负载均衡   │   └───────────────────────┘
              └────────────────────────────┘
```

管理平面与数据平面使用**独立端口**：管理 API 默认监听 `127.0.0.1:9090`，业务流量监听 `0.0.0.0:8080`。

## 2. 请求处理流程

1. **传输层**：TLS 终止（可选 mTLS）、HTTP/2 协商（ALPN）、活跃连接计数。
2. **请求 ID**：优先复用客户端传入且格式合法的 ID，否则生成 UUID。
3. **追踪**：从 `traceparent` 提取父上下文，创建服务器 Span；响应注入 `x-trace-id`。
4. **客户端 IP**：仅当直连对端在 `trusted_proxies` 内才采信 `X-Forwarded-For`，防止伪造。
5. **IP 过滤**：全局黑白名单 → 路由级黑白名单，deny 优先。
6. **路由匹配**：读取 `ArcSwap` 不可变快照，按 `order` → 路径具体度 → ID 排序后取第一个命中的路由。
7. **CORS 预检**：无匹配路由时按“忽略 Method”的规则寻找策略，避免 OPTIONS 被 404。
8. **认证**：Public / Optional / Authenticated / ApiKey 四种模式；JWT 校验算法白名单，拒绝算法混淆。
9. **授权**：身份头先删除再写入，防止客户端伪造；按 scopes / roles / 外部授权中心判定。
10. **请求过滤器**：全局过滤器 → 快照级全局过滤器 → 路由过滤器，依次修改路径、查询、请求头。
11. **限流**：全局限流 + 路由限流；本地令牌桶或 Redis Lua 原子令牌桶。
12. **熔断**：按路由隔离；Open 时直接返回降级响应；Half-Open 限量探测。
13. **缓存**：GET/HEAD 且无 Upgrade、无 Authorization（除非显式允许）时才可缓存。
14. **超时**：连接 / 响应头 / 整体超时，响应体流式读取共享同一截止时间。
15. **代理**：`lb://` 服务名解析到实例、SSRF 校验、幂等重试、流式转发。
16. **响应处理**：缓存写入、响应过滤器、CORS、安全头、访问日志与指标。

## 3. 动态路由与热更新

- 配置编译为 `RouteSnapshot`（路由、全局过滤器、完整配置、版本号、hash）。
- `RouteTable` 用 `ArcSwap` 持有快照：请求只读，更新原子替换。
- 更新过程先编译、后存储；编译失败保持旧快照，避免半更新状态。
- 三种更新来源：
  1. 文件轮询（默认 5s，`--no-watch` 关闭）；
  2. 管理 API（校验 → 替换 → 重建派生组件 → 持久化 → Pub/Sub 广播）；
  3. Redis Pub/Sub 订阅（版本号更大才应用，避免回退）。

## 4. 反向代理

- 使用 `hyper-util` legacy `Client`，按 `ClientKey`（协议、TLS 校验、CA、mTLS、超时）隔离连接池。
- 请求体使用 `ProxyBody` 三态（空 / 内存 / 流），不整体缓冲；只有需要重试的非流式请求才在限定大小内缓冲。
- 响应体使用 `TimedResponseBody` 包裹，流式转发并在总超时到达时中断。
- WebSocket：上游返回 `101` 后，用 `hyper::upgrade::OnUpgrade` 建立双向隧道（`copy_bidirectional`）。
- Hop-by-Hop 头与 `Connection` 中声明的逐跳头会被移除；`X-Forwarded-For/Proto/Host` 由网关维护。

## 5. 服务发现与负载均衡

- `StaticDiscovery`：来自 `gateway.services` 的静态实例。
- `ConsulDiscovery`：查询 `/v1/health/service/{name}`，仅保留健康实例，按 `refresh_interval` 刷新。
- 负载均衡策略：
  - `round_robin`：AtomicUsize 轮询；
  - `random`：随机；
  - `weighted_round_robin`：平滑加权轮询；
  - `least_connections`：比较在途请求数；
  - `p2c`：随机取两个实例，选择在途更少者。
- 被动健康：连接失败累计失败次数，连续失败后摘除，成功后退避恢复。
- 主动健康：按服务配置定时探测 `/health` 或 TCP 连通性。

## 6. 限流

- 本地模式：`DashMap<key, Mutex<Bucket>>`，令牌桶按 `rate_per_second` 补充，`burst_capacity` 为桶容量；超过 `max_keys` 时淘汰最旧条目。
- Redis 模式：Lua 脚本原子完成「读令牌 → 补充 → 扣减 → 写回 → 设置 TTL」，返回允许标记、剩余令牌与重试时间。
- Redis 不可用：`fail_open=false`（默认）拒绝请求并返回 503；`fail_open=true` 放行。
- 命中限流返回 429，附带 `Retry-After`、`x-ratelimit-limit`、`x-ratelimit-remaining`。

## 7. 熔断

- 每个路由一个熔断器，滑动窗口统计请求数、失败数、慢调用数。
- 达到 `minimum_requests` 后，失败率或慢调用率超过阈值 → Open，持续 `open_duration`。
- 到期后进入 Half-Open，允许 `half_open_max_calls` 个探测；连续成功达到阈值 → Closed，任一失败 → 重新 Open。
- Open 状态可配置降级响应（状态码、Body、Content-Type）。

## 8. 可观测性

- **指标**（Prometheus）：请求总数/延迟、上游结果、限流次数、熔断状态、缓存命中、活跃连接、在途请求、服务发现状态、实例数、WebSocket 连接数。
- **追踪**：OTLP HTTP 导出，采样率可配置，自动注入 `traceparent`。
- **日志**：JSON 或文本格式；访问日志包含请求 ID、路由、状态、耗时、上游、客户端 IP、trace ID；敏感头脱敏。

## 9. 部署拓扑

- 单实例：网关直接读取本地 YAML。
- 多实例：共享 Redis；任一实例通过管理 API 修改路由后，通过 Pub/Sub 广播版本与路由配置，其余实例原子应用。
- Consul 环境：服务注册到 Consul，网关按服务名解析健康实例。
