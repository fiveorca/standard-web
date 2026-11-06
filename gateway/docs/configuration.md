# 配置说明

配置由三部分组成，按顺序合并（后者覆盖前者）：

1. `config/gateway.yaml`：全局配置与静态服务组；
2. `config/routes.yaml`：路由列表；
3. `config/{profile}.yaml`：环境覆盖（`--profile` 或 `GATEWAY_PROFILE`）。

所有字符串值支持 `${ENV}` 与 `${ENV:-默认值}` 占位。若整个值是一个占位符，替换结果会自动识别为数字或布尔值（例如 `port: ${PORT:-8080}`）。

## 1. `gateway.server`

```yaml
gateway:
  server:
    host: 0.0.0.0
    port: 8080
    enable_http2: true
    max_connections: 10000
    graceful_shutdown_timeout: 30s
    trusted_proxies: [127.0.0.1/32, 10.0.0.0/8]
    timeouts:
      client_connect: 10s
      idle: 75s
      request: 60s
    limits:
      max_header_size: 32768
      max_body_size: 67108864
    tls:
      enabled: false
      cert_path: /etc/gateway/tls/tls.crt
      key_path: /etc/gateway/tls/tls.key
      client_ca_path: /etc/gateway/tls/ca.crt   # 配置后启用 mTLS
      min_version: "1.2"                        # 1.2 / 1.3
```

- `trusted_proxies`：只有直连对端在此范围内才采信 `X-Forwarded-*`。
- `max_body_size: 0` 表示不限制。
- `timeouts.request` 是路由未配置超时时的默认整体超时。

## 2. `gateway.admin`

```yaml
gateway:
  admin:
    enabled: true
    host: 127.0.0.1
    port: 9090
    allowed_ips: [127.0.0.1/32]
    auth:
      mode: api_key          # api_key | jwt | none
      header: x-admin-key
      api_keys: ["${GATEWAY_ADMIN_KEY:-dev-admin-key}"]
      jwt: ~                 # mode=jwt 时必填，结构同 authentication.jwt
    persistence:
      enabled: true
      path: ~                # 默认 <配置目录>/routes.yaml
```

## 3. `gateway.authentication`

```yaml
gateway:
  authentication:
    jwt:
      algorithms: [HS256]            # 允许的算法白名单
      secret: ${GATEWAY_JWT_SECRET}
      jwks_uri: https://auth.example.com/.well-known/jwks.json
      issuer: https://auth.example.com/
      audience: [my-api]
      leeway: 30                     # 秒
      require_exp: true
      required_claims: [sub]
      header: authorization
      prefix: Bearer
      scope_claim: scope
      roles_claim: roles
      tenant_claim: tenant
      jwks_cache_ttl: 300s
      jwks_min_refresh_interval: 10s
    api_keys:
      - id: partner-a
        key: ${PARTNER_A_KEY}
        subject: partner-a
        scopes: [read]
        roles: [partner]
        tenant: partner-a
    api_key_header: x-api-key
    identity_headers:
      user_id: x-user-id
      scopes: x-user-scopes
      roles: x-user-roles
      tenant: x-tenant-id
      auth_type: x-auth-type
```

- HS 算法使用 `secret`；RS/ES 算法使用 `jwks_uri`（也支持直接内联 JWKS）。
- 未知 `kid` 会触发一次受 `jwks_min_refresh_interval` 限制的刷新，实现密钥轮换。

## 4. `gateway.rate_limit`

```yaml
gateway:
  rate_limit:
    enabled: true
    mode: redis          # local | redis
    key_type: ip         # global | ip | user | tenant | api_key | custom
    key_template: ~      # key_type=custom 时生效
    fail_open: false
    max_keys: 100000
    redis_key_prefix: gateway:rl
    quota:
      requests_per_second: 500
      requests_per_minute: 0
      requests_per_hour: 0
      replenish_rate: 0  # >0 时覆盖每秒速率
      burst_capacity: 1000
```

## 5. `gateway.cache` 与路由缓存

```yaml
gateway:
  cache:
    enabled: true
    default_ttl: 30s
    max_capacity: 50000
    cacheable_status: [200, 301, 404]
    max_body_size: 2097152
    cache_authenticated: false

routes:
  - id: cachable
    uri: lb://backend
    predicates: [Path=/api/public/**]
    cache:
      enabled: true
      ttl: 10s
      max_capacity: 2000
      key_template: "user:{header:x-user-id}:{path}"  # 支持 header/cookie/query/path/method/host
      vary_headers: [accept]
      respect_cache_control: true
      cache_authenticated: false
```

## 6. `gateway.cors`

```yaml
gateway:
  cors:
    allowed_origins: ["https://app.example.com", "https://*.example.com"]
    allowed_methods: [GET, POST, OPTIONS]
    allowed_headers: ["*"]
    exposed_headers: [x-request-id]
    allow_credentials: true
    max_age: 3600s
```

`allowed_origins` 支持 `*` 与 `https://*.example.com` 通配；`allow_credentials=true` 时不允许 `*`。

## 7. `gateway.ip_filter`

```yaml
gateway:
  ip_filter:
    allow: [10.0.0.0/8]
    deny: [1.2.3.4]
```

deny 优先；`allow` 非空时，不在其中的来源一律拒绝。支持单 IP 与 CIDR。

## 8. `gateway.security`

```yaml
gateway:
  security:
    request_id_header: x-request-id
    trust_client_request_id: true
    add_security_headers: true
    extra_headers:
      x-content-type-options: nosniff
    host_validation:
      enabled: true
      allowed_hosts: [api.example.com]
    block_private_upstreams: false
```

`block_private_upstreams=true` 会阻止上游解析到回环、私网、链路本地等地址（SSRF 防护）。

## 9. 服务组与负载均衡

```yaml
gateway:
  load_balancer:
    strategy: round_robin   # round_robin | random | weighted_round_robin | least_connections | p2c
    default_weight: 1
  service_discovery:
    refresh_interval: 10s
    consul:
      address: http://127.0.0.1:8500
      token: ${CONSUL_TOKEN:-}
      datacenter: ~
      passing_only: true
      tag: ~
  services:
    user-service:
      discovery: static       # static | consul
      load_balancer: least_connections
      instances:
        - id: user-1
          uri: http://10.0.0.11:8080
          weight: 3
        - id: user-2
          uri: http://10.0.0.12:8080
      health_check:
        enabled: true
        path: /health
        interval: 10s
        timeout: 2s
```

使用 `uri: lb://user-service` 引用服务组；也可直接写 `http://host:port`。

## 10. 路由

```yaml
routes:
  - id: user-api
    description: 用户服务
    uri: lb://user-service
    order: 10
    enabled: true
    predicates:
      - Path=/api/users/**
      - Method=GET,POST
      - Header=X-Tenant,acme*
      - Query=debug,true
      - After=2025-01-01T00:00:00Z
      - Between=2025-01-01T00:00:00Z,2025-12-31T23:59:59Z
    filters:
      - StripPrefix=2
      - AddRequestHeader=X-From-Gateway,1
      - AddResponseHeader=X-Route,user-api
    authentication:
      mode: authenticated      # public | optional | authenticated | api_key
      allow_api_key: true
    authorization:
      scopes: [read]
      roles: [user]
      external:
        url: http://authz.internal/check
        timeout: 200ms
        cache_ttl: 30s
        fail_open: false
        forward_headers: [x-request-id]
    timeout:
      connect: 2s
      response: 10s
      total: 15s
    retry:
      enabled: true
      max_attempts: 3
      retry_on_connect_error: true
      retry_on_timeout: false
      retry_statuses: [502, 503, 504]
      backoff_initial: 50ms
      backoff_max: 1s
      backoff_multiplier: 2.0
      max_body_bytes: 1048576
    rate_limit:
      enabled: true
      key_type: user
      quota:
        requests_per_second: 20
        burst_capacity: 40
    circuit_breaker:
      enabled: true
      failure_rate_threshold: 50
      slow_call_duration: 2s
      slow_call_rate_threshold: 80
      sliding_window_size: 100
      window_duration: 10s
      minimum_requests: 10
      open_duration: 15s
      half_open_max_calls: 3
      half_open_success_threshold: 2
      fallback:
        status: 503
        body: '{"error":"unavailable"}'
    cache:
      enabled: false
    cors: ~
    ip_filter:
      allow: []
      deny: []
    upstream:
      protocol: auto        # auto | http1 | http2
      websocket: false
      tls:
        verify: true
    metadata:
      owner: platform
```

### 谓词语法

| 谓词 | 写法 | 说明 |
| --- | --- | --- |
| Path | `Path=/api/**` | Ant 风格，`**` 匹配多级，`*` 匹配单级 |
| Host | `Host=api.example.com` | 支持 `*.example.com` |
| Method | `Method=GET,POST` | 逗号分隔 |
| Header | `Header=X-A,value*` | 头名 + 值模式 |
| Query | `Query=debug,true` | 参数名 + 值模式，值可省略 |
| Cookie | `Cookie=session,abc*` | Cookie 名 + 值模式 |
| RemoteAddr | `RemoteAddr=10.0.0.0/8` | CIDR |
| After / Before / Between | RFC3339 时间 | 时间窗口 |

### 过滤器语法

- 单值：`StripPrefix=2`
- 双值：`AddRequestHeader=Name,Value`（值可含逗号，按第一个逗号分割）
- 替换：`RewritePath=/old/(?P<id>\d+),/new/$id`
- 无参：`SecureHeaders`

## 11. 日志与追踪

```yaml
gateway:
  logging:
    level: info
    format: json          # json | text
    access_log: true
    redact_headers: [authorization, cookie, x-api-key]
  tracing:
    enabled: true
    endpoint: http://otel-collector:4318
    service_name: rust-api-gateway
    sample_ratio: 0.1
    headers:
      x-api-key: ${OTEL_KEY:-}
  metrics:
    enabled: true
    path: /metrics
```

## 12. Redis 与配置同步

```yaml
gateway:
  redis:
    url: redis://127.0.0.1:6379
    channel: gateway:config
    connect_timeout: 2s
    command_timeout: 1s
```

`url` 非空时启用 Redis 限流与配置同步；管理 API 的变更会发布到 `channel`，其他实例按版本号应用。

## 13. 全局过滤器

```yaml
gateway:
  global_filters:
    - SecureHeaders
    - AddRequestHeader=X-Gateway,rust
```

全局过滤器先于路由过滤器执行；响应阶段按相反顺序执行。
