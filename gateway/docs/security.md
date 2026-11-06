# 安全说明

本项目遵循「默认安全」原则：不安全的选项必须显式开启，且关键路径都有明确的失败策略。

## 1. 传输安全

- **下游 TLS**：`gateway.server.tls` 开启后使用 rustls，支持 TLS 1.2/1.3、ALPN、完整证书链；配置 `client_ca_path` 即启用 mTLS，未提供合法客户端证书的连接在握手阶段被拒绝。
- **上游 TLS**：默认 `upstream_tls.verify: true`，使用系统根证书或自定义 CA 校验上游；`verify: false` 仅建议用于本地调试。
- **mTLS 上游**：`client_cert_path` / `client_key_path` 提供客户端证书。
- 私钥文件仅需进程用户可读；容器中以非 root（UID 10001）运行。

## 2. 认证

### JWT

- 算法白名单：只接受 `authentication.jwt.algorithms` 中声明的算法，杜绝 `alg=none` 与算法混淆攻击。
- 校验 `exp`、`nbf`（可配置 leeway）、`iss`、`aud`、`typ` 与必需 claims。
- HS 算法使用 `secret`；RS/ES 使用 JWKS。JWKS 缓存 `jwks_cache_ttl`，遇到未知 `kid` 时触发刷新，但受 `jwks_min_refresh_interval` 限制，避免被恶意 `kid` 打爆认证中心。
- Token 只从配置的请求头与前缀读取，不接受 URL 参数。

### API Key

- 只保存 Key 的 SHA-256 摘要用于比对，配置中的明文 Key 建议通过环境变量注入。
- 比较使用常量时间算法，避免时序侧信道。
- 管理 API Key 与业务 API Key 分离（不同配置节与请求头）。

### 身份头注入

- 请求进入时先**删除**所有客户端传入的身份头（`x-user-id`、`x-user-scopes`、`x-user-roles`、`x-tenant-id`、`x-auth-type`），再由认证结果写入，防止伪造。
- 身份头名称可配置；未认证请求不会携带任何身份头。

## 3. 授权

- 路由级 `scopes` / `roles` 采用「全部满足」语义。
- 外部授权中心：
  - 只转发白名单请求头；
  - 结果按身份 + 路由 + 方法 + 路径缓存 `cache_ttl`；
  - 超时受 `timeout` 控制；
  - `fail_open=false`（默认）时，授权中心不可用即拒绝（503/403）。
- 外部授权失败不会回退到本地放行。

## 4. 限流

- 本地令牌桶按 Key 隔离，容量上限 `max_keys`，防止内存被高基数 Key 撑爆。
- Redis 模式使用 Lua 脚本保证「读-改-写」原子性，避免多实例竞争导致超发。
- Redis 故障策略：
  - `fail_open: false`（默认）：拒绝请求（503），保护后端；
  - `fail_open: true`：放行，适合可用性优先的场景。
- 限流响应包含 `Retry-After`，避免客户端立即重试。

## 5. 网络与 SSRF

- **客户端 IP 解析**：仅当直连对端属于 `trusted_proxies` 时才采信 `X-Forwarded-For`；否则使用 TCP 对端地址，防止伪造来源绕过 IP 黑名单与限流。
- **IP 过滤**：`deny` 优先，支持 CIDR；全局与路由级可叠加。
- **Host 校验**：`security.host_validation` 开启后，`Host` 不在白名单的请求直接拒绝（421）。
- **SSRF 防护**：`security.block_private_upstreams=true` 时，上游主机名解析结果若为回环、私网、链路本地、组播、保留地址则拒绝；解析结果缓存 60 秒。注意：这会阻止访问内网后端，请按部署环境选择。
- **Hop-by-Hop 清理**：`Connection`、`Keep-Alive`、`TE`、`Trailer`、`Transfer-Encoding`、`Upgrade`、`Proxy-*` 等头在转发前移除，`Connection` 中声明的自定义逐跳头同样移除。
- **转发头**：`X-Forwarded-For` 在可信链上追加，`X-Forwarded-Proto` / `X-Forwarded-Host` 由网关重写，客户端传入值不会被无条件信任。

## 6. 请求限制

- `limits.max_header_size`：请求头总大小上限，超出返回 431。
- `limits.max_body_size`：请求体上限，超出返回 413；缓存与重试缓冲也遵守各自的 `max_body_size`。
- 超时：连接、响应头、整体三层限制，避免慢速攻击长期占用连接。
- 管理接口默认只监听回环地址，并支持 IP 白名单与认证。

## 7. CORS

- 允许来源支持精确匹配、`*` 与子域通配；`allow_credentials=true` 时禁止 `*`。
- 预检请求只对命中路由的 Origin 生效；不在白名单的 Origin 不会收到允许头。
- `Vary: Origin` 自动维护，避免缓存串源。

## 8. 缓存安全

默认不缓存以下响应：

- 非 GET/HEAD；
- 带 `Upgrade` 的请求；
- 带 `Authorization` 或已认证身份的请求（除非 `cache_authenticated: true`）；
- `Cache-Control: no-store` / `private`（`respect_cache_control: true` 时）；
- 含 `Set-Cookie` 的响应；
- 状态码不在 `cacheable_status` 中；
- 无法确定长度或超过 `max_body_size` 的响应。

缓存 Key 默认包含方法、Host、路径与查询串；可通过 `key_template` 追加用户/租户维度，避免越权读取。

## 9. 管理平面

- 与业务端口分离，默认 `127.0.0.1:9090`。
- `auth.mode=api_key`（默认）或 `jwt`；`none` 仅应在受控网络中显式使用。
- `allowed_ips` 非空时按 CIDR 校验来源。
- 所有写操作先校验再原子替换；失败不会产生半更新状态。
- 变更持久化到磁盘，并通过 Redis Pub/Sub 同步，消息包含版本号，旧版本不会覆盖新版本。

## 10. 日志与追踪

- 敏感请求头（`authorization`、`cookie`、`set-cookie`、`x-api-key`、`x-admin-key`、`proxy-authorization`）默认脱敏。
- 日志不记录请求体与响应体。
- 追踪采样率可配置，生产环境建议 1%~10%。

## 11. 安全清单

- [ ] 修改默认 `GATEWAY_ADMIN_KEY` 与 `GATEWAY_JWT_SECRET`
- [ ] 生产环境启用 TLS 1.2+，必要时启用 mTLS
- [ ] 管理端口只监听内网/回环并配置 `allowed_ips`
- [ ] 为敏感路由开启认证与授权
- [ ] 配置合理的 Header/Body 限制与超时
- [ ] 根据部署环境决定是否开启 `block_private_upstreams`
- [ ] 为限流配置 Redis 并选择 fail-open / fail-closed 策略
- [ ] 接入 Prometheus 与告警（5xx、限流、熔断 Open、依赖不健康）
