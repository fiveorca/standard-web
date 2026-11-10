# 认证授权中心（auth-center）

通用身份认证与授权中心（IAM）。基于 Java 25 + Spring Boot 4.1.2 + Spring Framework 7.0.10 + Spring Cloud 2025.1.4 实现，独立数据库、独立部署。

## 能力范围

| 领域 | 能力 |
| --- | --- |
| 身份与凭证 | 注册、用户名/邮箱/手机号密码登录、验证码登录、密码策略与历史、找回与重置、联系方式验证 |
| 会话 | 多设备会话、单点登录、单点登出、会话撤销、登录历史、设备命名 |
| MFA | TOTP 绑定/校验、恢复码、WebAuthn/Passkeys、管理员重置、高风险二次验证 |
| OAuth 2.0 | Authorization Code + PKCE、Client Credentials、Refresh Token 轮换与重用检测、撤销、内省、Consent |
| OpenID Connect | Discovery、Authorization/Token/UserInfo/JWKS/End Session、ID Token、nonce/state/issuer/audience 校验 |
| SAML 2.0 | IdP Metadata、AuthnRequest、签名 Assertion、HTTP Redirect/POST Binding、SLO、ACS 验签、防重放 |
| 身份联邦 | Google、GitHub、Microsoft、Apple 与通用 OIDC Provider 登录、绑定/解绑、自动注册策略 |
| 授权 | RBAC、权限树、用户直接授权、API/菜单/按钮资源、数据权限、ABAC 策略、ReBAC 资源关系、租户隔离 |
| 安全 | Argon2id、AES-256-GCM 密钥加密、RS256 + JWKS 轮换、审计哈希链、限流、Outbox/Inbox 事件 |

## 目录结构

```
auth/
├── pom.xml
├── Dockerfile
├── .env.example
└── src/
    ├── main/java/com/platform/auth/
    │   ├── AuthApplication.java
    │   ├── bootstrap/          # 启动播种
    │   ├── common/             # 响应、异常、DB、审计、Outbox、限流
    │   ├── config/             # 配置、CORS、Trace
    │   ├── security/           # JWT、密钥、Argon2、TOTP、PKCE、WebAuthn
    │   ├── service/            # 身份、会话、MFA、OAuth、联邦、SAML、RBAC
    │   └── web/                # Auth/Authz/Admin/Internal/OAuth/SAML/Meta
    ├── main/resources/
    │   ├── application.yml
    │   └── db/migration/V1__init.sql
    └── test/java/...           # 单元测试
```

## 本地运行

前置：JDK 25、Maven 3.9+、PostgreSQL 16+、Redis 7（Redis 不可用时限流自动降级为内存实现）。

```bash
createdb auth_center
export JAVA_HOME=/path/to/jdk-25
mvn -DskipTests package
java -jar target/auth-center-1.0.0.jar
```

或使用环境变量覆盖配置（见 `.env.example`）：

```bash
AUTH_DATABASE_URL=jdbc:postgresql://localhost:5432/auth_center \
AUTH_DATABASE_USER=postgres AUTH_DATABASE_PASSWORD=postgres \
java -jar target/auth-center-1.0.0.jar
```

Flyway 在启动时自动执行 `db/migration`。首次启动会幂等播种默认租户、管理员、内置 OAuth 客户端与资源目录。

## 测试

```bash
mvn test          # 单元测试
mvn package       # 打包
```

## 主要端点

| 分组 | 前缀 | 说明 |
| --- | --- | --- |
| 认证 | `/api/v1/auth` | 注册、登录、刷新、会话、密码、MFA、联邦登录 |
| 授权决策 | `/api/v1/authz` | `/check`、`/batch-check`、`/me/*` |
| 管理后台 | `/api/v1/admin` | 身份、角色、权限、策略、租户、菜单/按钮/API、审计、客户端、SAML |
| 内部服务 | `/api/v1/internal` | 身份同步、授权检查、事件接收（`x-internal-token`） |
| OAuth2/OIDC | `/oauth2` | authorize、token、userinfo、jwks、introspect、revoke、logout、discovery |
| SAML | `/saml` | metadata、sso、slo、acs |
| 元信息 | `/health`、`/ready`、`/openapi.json`、`/docs` | 健康检查、OpenAPI 3.1、Swagger UI |

## 默认引导数据

- 租户：`default`（`00000000-0000-0000-0000-000000000001`）
- 管理员：`AUTH_BOOTSTRAP_ADMIN_USERNAME` / `AUTH_BOOTSTRAP_ADMIN_PASSWORD`（默认 `admin` / `Admin@12345`）
- 角色：`super_admin`（全局，绑定全部内置权限）
- OAuth 客户端：`auth-console`（授权码 + PKCE）、`web-app`（公共 PKCE）、`user-center`（client_credentials）
- 客户端密钥：`AUTH_BOOTSTRAP_CLIENT_SECRET`

## 安全说明

- 密码 Argon2id；OTP 以 HMAC-SHA256 存储。
- JWT 使用 RS256，私钥以 AES-256-GCM 加密存入 `signing_keys`；JWKS 仅暴露公钥，支持轮换。
- Refresh Token 只存哈希并轮换，检测到重用会撤销整个会话族。
- SAML 校验 XML 签名、Conditions、Audience、Recipient、InResponseTo，并使用重放缓存。
- 审计日志使用哈希链；所有管理操作记录操作者、对象、租户、IP 与结果。
- 生产环境必须替换 `AUTH_ENCRYPTION_KEY`、`AUTH_INTERNAL_TOKEN`、数据库口令并启用 HTTPS。
