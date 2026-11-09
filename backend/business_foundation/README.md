# Rust + Axum 认证授权中心与用户中心

本仓库包含两个可独立部署的服务：

| 服务 | 目录 | 端口 | 职责 |
| --- | --- | --- | --- |
| 认证授权中心（auth-center） | `base/auth` | 8080 | 身份凭证、登录、OAuth2/OIDC、SAML2、MFA、Token、RBAC/ABAC/ReBAC、租户、审计 |
| 用户中心（user-center） | `base/user` | 8081 | 用户业务资料、扩展属性、联系方式投影、分组、组织部门、注册审核、账户关联 |

两个服务使用**独立数据库**，不共享代码与数据访问层，只通过内部 HTTP API 与可靠领域事件协作：

- 认证中心拥有身份、密码、凭证、会话、Token、角色权限的权威数据。
- 用户中心拥有个人资料、属性、分组、组织关系、业务状态的权威数据。
- 用户 ID 即认证中心的 `subject`，两端使用同一个 UUID 关联。
- 用户中心不保存、不验证密码，不签发 JWT；访问令牌通过认证中心 JWKS 离线校验。
- 联系方式（邮箱/手机号）的验证码发送与校验始终由认证中心完成，用户中心只维护本地投影。

```
浏览器 / 业务前端
      │  Authorization: Bearer <access_token>
      ▼
┌──────────────────┐   JWKS / 内部令牌 / 领域事件   ┌──────────────────┐
│   用户中心 :8081  │ ───────────────────────────▶ │  认证中心 :8080   │
│  profile/group   │ ◀─────────────────────────── │  identity/oauth  │
│  org/registration│        Outbox → Inbox        │  rbac/mfa/audit   │
└──────────────────┘                               └──────────────────┘
        │ PostgreSQL(user_center)                         │ PostgreSQL(auth_center)
        └────────────── Redis ────────────────────────────┘
```

## 快速开始（Docker Compose）

```bash
cd base
docker compose up -d --build
```

首次启动后：

- 认证中心 `http://localhost:8080`，Swagger UI `http://localhost:8080/docs`
- 用户中心 `http://localhost:8081`，Swagger UI `http://localhost:8081/docs`
- 管理员账号由 `AUTH_SEED_ADMIN_USERNAME` / `AUTH_SEED_ADMIN_PASSWORD` 指定；未指定密码时会随机生成并打印在认证中心日志中：

```bash
docker compose logs auth | grep -A2 "初始管理员"
```

- 用户中心服务客户端 `user-center` 的 secret 由 `AUTH_SEED_USER_CENTER_SECRET` 指定（compose 中已与用户中心配置对齐）；未指定时会随机生成并打印，需要同步写入用户中心的 `USER__AUTH__SERVICE_CLIENT_SECRET`。

## 本地运行

前置：PostgreSQL 16、Redis 7。

```bash
# 认证中心
cd base/auth
cp .env.example .env
cargo run --bin auth-center

# 用户中心（另一个终端）
cd base/user
cp .env.example .env
cargo run --bin user-center
```

数据库迁移默认在启动时自动执行（`auto_migrate = true`），也可以先手动执行：

```bash
psql "$AUTH_DATABASE_URL" -f base/auth/migrations/0001_init.sql
psql "$USER_DATABASE_URL" -f base/user/migrations/0001_init.sql
```

## 首次管理员初始化

认证中心启动时执行幂等播种：

1. 默认租户 `00000000-0000-0000-0000-000000000001`；
2. 内置权限（`admin:access`、`identity:manage`、`role:manage`、`oauth:manage`、`audit:read`、`saml:manage`、`tenant:manage`、`internal:events`、`authz:check`）；
3. `platform-admin` 平台管理员角色并绑定全部内置权限；
4. 管理员身份并授予该角色；
5. `auth-console`、`user-center` 两个 OAuth 客户端；
6. 默认 SAML IdP 元数据配置。

```bash
# 只执行播种后退出
cd base/auth
AUTH_SEED_ADMIN_PASSWORD='Admin12345!' cargo run --bin auth-center -- seed-admin
```

## 客户端接入示例

### 1. 密码登录获取 Token

```bash
curl -s http://localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"Admin12345!"}'
```

响应中的 `access_token` 用于访问用户中心：

```bash
curl -s http://localhost:8081/api/v1/users/me \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

### 2. OAuth2 Authorization Code + PKCE

```bash
# 1) 生成 PKCE
verifier=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

# 2) 浏览器打开授权地址
# http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-console&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=demo&code_challenge=$challenge&code_challenge_method=S256

# 3) 用回调中的 code 换取 Token
curl -s http://localhost:8080/oauth2/token \
  -d grant_type=authorization_code \
  -d client_id=auth-console \
  -d code='<code>' \
  -d redirect_uri='http://localhost:3000/callback' \
  -d code_verifier="$verifier"
```

### 3. Client Credentials

```bash
curl -s http://localhost:8080/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id=user-center \
  -d client_secret='<user-center-secret>' \
  -d scope=internal
```

### 4. OIDC Discovery / JWKS

```bash
curl -s http://localhost:8080/.well-known/openid-configuration
curl -s http://localhost:8080/oauth2/jwks
```

## 授权检查调用示例

### 面向资源服务（用户中心等）

```bash
curl -s http://localhost:8080/api/v1/authz/check \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"permission":"identity:manage"}'
```

### 服务间内部授权判定（使用内部令牌）

```bash
curl -s http://localhost:8080/api/v1/internal/authz/check \
  -H 'x-internal-token: dev-internal-token-change-me-0001' \
  -H 'content-type: application/json' \
  -d '{
    "tenant_id":"00000000-0000-0000-0000-000000000001",
    "identity_id":"<user-uuid>",
    "permission":"identity:manage"
  }'
```

### 资源级授权

```bash
curl -s http://localhost:8080/api/v1/authz/check \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "permission":"document:read",
    "resource":{"type":"document","id":"doc-123","attributes":{"owner":"<user-uuid>"}},
    "context":{"ip":"10.0.0.1"}
  }'
```

## 服务交互

详细的数据所有权、事件清单、内部 API 与一致性机制见 [docs/integration.md](docs/integration.md)；数据库表说明见 [docs/database.md](docs/database.md)。

## 测试

```bash
# 单元测试
cd base/auth && cargo test --lib
cd base/user && cargo test --lib

# 集成测试（需要真实 PostgreSQL 与 Redis）
cd base/auth && AUTH_TEST_DATABASE_URL='postgres://...' AUTH_TEST_REDIS_URL='redis://...' cargo test --test integration
cd base/user && USER_TEST_DATABASE_URL='postgres://...' USER_TEST_REDIS_URL='redis://...' USER_TEST_AUTH_BASE_URL='http://localhost:8080' USER_TEST_INTERNAL_TOKEN='...' cargo test --test integration
```

集成测试会真实执行 Migration、写入并读取数据库，不做内存模拟。

## 安全说明

- JWT 私钥不硬编码，由认证中心生成并以 AES-256-GCM 加密后存入数据库；主密钥来自配置/环境变量。
- 密码使用 Argon2id；OTP 使用 HMAC-SHA256 存储。
- 登录、验证码、注册均有频率限制；Cookie 认证强制 CSRF 双提交。
- 重定向白名单、SSRF 目标校验、安全响应头（CSP、nosniff、DENY、no-referrer）。
- 审计日志采用哈希链，Outbox/Inbox 保证事件最终一致与消费幂等。
- 生产环境必须使用 HTTPS，并覆盖 `master_key`、`internal_token`、数据库与 Redis 凭证。
