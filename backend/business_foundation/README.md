# Java 认证授权中心与用户中心

本仓库包含两个可独立部署的服务：

| 服务 | 目录 | 端口 | 职责 |
| --- | --- | --- | --- |
| 认证授权中心（auth-center） | `auth` | 8080 | 身份凭证、登录、OAuth2/OIDC、SAML2、MFA、Token、RBAC/ABAC/ReBAC、租户、审计 |
| 用户中心（user-center） | `user` | 8081 | 用户业务资料、扩展属性、联系方式投影、分组、组织部门、注册审核、账户关联 |

两个服务均基于 Java 25 + Spring Boot 4.1.2 + Spring Framework 7.0.10 + Spring Cloud 2025.1.4，使用 Maven 构建。

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
cd backend/business_foundation
docker compose up -d --build
```

首次启动后：

- 认证中心 `http://localhost:8080`，Swagger UI `http://localhost:8080/docs`
- 用户中心 `http://localhost:8081`，Swagger UI `http://localhost:8081/docs`
- 管理员账号：`AUTH_BOOTSTRAP_ADMIN_USERNAME` / `AUTH_BOOTSTRAP_ADMIN_PASSWORD`（默认 `admin` / `Admin@12345`）
- 内置 OAuth 客户端 `auth-console`、`web-app`、`user-center` 的密钥由 `AUTH_BOOTSTRAP_CLIENT_SECRET` 指定

## 本地运行

前置：JDK 25、Maven 3.9+、PostgreSQL 16+、Redis 7。

```bash
# 数据库（首次）
createdb auth_center
createdb user_center

# 认证中心
cd auth
cp .env.example .env
mvn -DskipTests package
java -jar target/auth-center-1.0.0.jar

# 用户中心（另一个终端）
cd user
cp .env.example .env
mvn -DskipTests package
java -jar target/user-center-1.0.0.jar
```

Flyway 在启动时自动执行各服务 `src/main/resources/db/migration` 下的迁移脚本。

## 首次管理员初始化

认证中心启动时执行幂等播种：

1. 默认租户 `00000000-0000-0000-0000-000000000001`；
2. 内置权限目录与 `super_admin` 全局角色；
3. 管理员身份并授予 `super_admin` 角色；
4. `auth-console`、`web-app`、`user-center` OAuth 客户端；
5. 内置菜单、按钮、API 资源与权限映射；
6. 签名密钥（RS256，私钥 AES-256-GCM 加密入库）。

## 客户端接入示例

### 1. 密码登录获取 Token

```bash
curl -s http://localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"Admin@12345"}'
```

响应中的 `data.tokens.access_token` 用于访问用户中心：

```bash
curl -s http://localhost:8081/api/v1/users/me \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

### 2. OAuth2 Authorization Code + PKCE

```bash
verifier=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

# 浏览器打开授权地址
# http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-console&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=demo&code_challenge=$challenge&code_challenge_method=S256

curl -s http://localhost:8080/oauth2/token \
  -d grant_type=authorization_code \
  -d client_id=auth-console \
  -d client_secret=dev-client-secret-change-me \
  -d code='<code>' \
  -d redirect_uri='http://localhost:3000/callback' \
  -d code_verifier="$verifier"
```

### 3. Client Credentials

```bash
curl -s http://localhost:8080/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id=user-center \
  -d client_secret=dev-client-secret-change-me \
  -d scope=internal
```

### 4. OIDC Discovery / JWKS

```bash
curl -s http://localhost:8080/oauth2/.well-known/openid-configuration
curl -s http://localhost:8080/oauth2/jwks
```

## 授权检查调用示例

```bash
curl -s http://localhost:8080/api/v1/authz/check \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"permission":"identity:read"}'
```

```bash
curl -s http://localhost:8080/api/v1/internal/authz/check \
  -H 'x-internal-token: dev-internal-token-change-me' \
  -H 'content-type: application/json' \
  -d '{
    "tenant_id":"00000000-0000-0000-0000-000000000001",
    "identity_id":"<user-uuid>",
    "permission":"identity:read"
  }'
```

## 测试

```bash
cd auth && mvn test
cd user && mvn test
```

## 安全说明

- JWT 私钥不硬编码，由认证中心生成并以 AES-256-GCM 加密后存入数据库；加密密钥来自配置/环境变量。
- 密码使用 Argon2id；OTP 使用 HMAC-SHA256 存储。
- 登录、验证码、注册均有频率限制；Cookie 认证配合 SameSite/HttpOnly。
- 重定向白名单、SSRF 目标校验、统一错误响应，避免泄露内部细节。
- 审计日志采用哈希链，Outbox/Inbox 保证事件最终一致与消费幂等。
- 生产环境必须使用 HTTPS，并覆盖 `AUTH_ENCRYPTION_KEY`、`AUTH_INTERNAL_TOKEN`、数据库与 Redis 凭证。
