# 管理 API

- 监听地址：`gateway.admin.host:port`（默认 `127.0.0.1:9090`）。
- 统一响应：

```json
{ "success": true, "data": { } }
```

```json
{ "success": false, "error": { "code": "BAD_REQUEST", "message": "..." } }
```

- 认证：`admin.auth.mode`
  - `api_key`（默认）：请求头 `admin.auth.header`（默认 `x-admin-key`）携带任一 `api_keys`；
  - `jwt`：`Authorization: Bearer <token>`，校验 `admin.auth.jwt` 配置；
  - `none`：不校验（仅供受控网络使用）。
- 来源限制：`admin.allowed_ips` 非空时仅允许这些 IP / CIDR。
- 所有变更操作都是原子的：先校验、再编译、成功后替换快照，失败保持原配置不变。

---

## 路由管理

### 列出路由

`GET /admin/v1/routes`

```json
{
  "success": true,
  "data": {
    "version": 3,
    "total": 2,
    "routes": [
      { "id": "user-api", "enabled": true, "order": 10, "uri": "lb://user-service", "...": "..." }
    ]
  }
}
```

查询参数：`?enabled=true|false`（可选）。

### 获取单个路由

`GET /admin/v1/routes/{id}`

### 创建路由

`POST /admin/v1/routes`

请求体为完整的路由配置：

```json
{
  "id": "orders",
  "uri": "lb://order-service",
  "order": 20,
  "predicates": ["Path=/api/orders/**", "Method=GET,POST"],
  "filters": ["StripPrefix=2"],
  "authentication": { "mode": "authenticated" },
  "retry": { "enabled": true, "max_attempts": 3, "retry_statuses": [502, 503, 504] }
}
```

- `200`：创建成功，`data.version` 为新版本号；
- `409`：ID 已存在；
- `400`：配置校验失败或路由编译失败。

### 更新 / 删除

- `PUT /admin/v1/routes/{id}`：请求体同创建（ID 以路径为准）。
- `DELETE /admin/v1/routes/{id}`：删除路由。

### 启用 / 禁用

- `POST /admin/v1/routes/{id}/enable`
- `POST /admin/v1/routes/{id}/disable`

```json
{ "success": true, "data": { "id": "orders", "enabled": false, "version": 4 } }
```

---

## 配置管理

### 热重载

`POST /admin/v1/config/reload`

从磁盘重新读取配置并原子应用。用于外部配置管理系统更新文件后的立即生效（文件轮询之外的补充）。

```json
{ "success": true, "data": { "version": 5, "routes": 7 } }
```

### 配置状态

`GET /admin/v1/config/status`

```json
{
  "success": true,
  "data": {
    "version": 5,
    "hash": "9f2c...",
    "routes": 7,
    "enabled_routes": 6,
    "profile": "production",
    "config_dir": "/etc/gateway/config",
    "node_id": "gateway-1-8080",
    "uptime_secs": 3600,
    "loaded_at": 1762416000
  }
}
```

---

## 运行时查询

### 服务与实例

`GET /admin/v1/services`

```json
{
  "success": true,
  "data": {
    "static_services": ["httpbin", "user-service"],
    "upstreams": [
      {
        "name": "user-service",
        "discovery": "static",
        "strategy": "least_connections",
        "last_refresh": null,
        "healthy": true,
        "error": null,
        "discovery_calls": 0,
        "instances": [
          { "id": "user-1", "uri": "http://10.0.0.11:8080", "weight": 3, "healthy": true, "in_flight": 2, "total_requests": 120, "total_failures": 1 }
        ]
      }
    ],
    "routes": ["lb://httpbin", "lb://user-service"]
  }
}
```

### 上游

`GET /admin/v1/upstreams`：返回 `{ "upstreams": [...] }`，结构与上面的 `upstreams` 相同。

### 熔断器

`GET /admin/v1/circuit-breakers`

```json
{
  "success": true,
  "data": {
    "circuit_breakers": [
      {
        "key": "route:user-api",
        "state": "closed",
        "total_samples": 100,
        "failure_rate": 2.0,
        "slow_call_rate": 1.0,
        "failure_threshold": 50.0,
        "open_duration_secs": 15.0
      }
    ]
  }
}
```

### 指标摘要

`GET /admin/v1/metrics/summary`

```json
{
  "success": true,
  "data": {
    "gateway_requests_total": 10240,
    "gateway_rate_limited_total": 12,
    "gateway_cache_hits_total": 500,
    "gateway_inflight_requests": 3,
    "gateway_active_connections": 42
  }
}
```

（键名为原始 Prometheus 指标名，值为该指标所有样本的聚合值。）

---

## 健康检查与指标

| 路径 | 说明 |
| --- | --- |
| `GET /health/live` | 进程存活，始终 200，返回 `{"status":"ok","uptime_seconds":N}` |
| `GET /health/ready` | 初始化完成且未在 draining，并检查依赖（Redis/Consul） |
| `GET /metrics` | Prometheus 文本格式 |

`/health/ready` 返回：

```json
{
  "ready": true,
  "draining": false,
  "dependencies": [
    { "name": "redis", "healthy": true, "message": null, "latency_ms": 1 }
  ]
}
```

依赖不健康时返回 `503`。业务端口同样提供 `/health/live`、`/health/ready`，便于负载均衡器使用。
注意：管理端口的 `/health/*` 使用统一的 `{"success":true,"data":{...}}` 包装，业务端口直接返回上述结构。

---

## 错误码

| HTTP | code | 场景 |
| --- | --- | --- |
| 400 | `BAD_REQUEST` | 请求体非法、路由配置无效 |
| 401 | `UNAUTHORIZED` | 管理认证失败 |
| 403 | `FORBIDDEN` | 来源 IP 不允许 |
| 404 | `ROUTE_NOT_FOUND` | 管理资源不存在 |
| 409 | `CONFLICT` | 路由 ID 冲突 |
| 503 | `SERVICE_UNAVAILABLE` | 配置未就绪 / Redis 故障且 fail-closed |
