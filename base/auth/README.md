# auth-center 认证授权中心

基于 Rust + Axum 的统一身份认证与授权服务，提供 OAuth2/OIDC、SAML2、MFA、会话管理和 RBAC/ABAC/ReBAC 授权能力。

## 能力清单

- 身份与凭证：注册、登录、邮箱/手机验证码、密码策略与历史、账户状态、租户隔离。
- MFA：TOTP、WebAuthn/Passkey、恢复码、MFA 待验证 Token。
- 会话：设备会话列表、单会话/全会话撤销、Refresh Token 轮换与重放检测。
- OAuth2 / OIDC：授权码 + PKCE、client_credentials、refresh_token、introspection、revocation、discovery、JWKS、userinfo、consent、end_session。
- SAML2：IdP 元数据、SSO、SLO、断言签名、SP 管理、防重放。
- 身份联邦：Google、GitHub、Microsoft、Apple、通用 OIDC / OAuth2。
- 授权：RBAC、ABAC 条件策略、ReBAC 资源关系、数据范围；默认拒绝；菜单/按钮/API/数据权限。
- 审计：哈希链审计日志；Outbox 事件投递与 Inbox 幂等。
- 内部服务 API：身份创建/查询/状态同步、联系方式换绑/解绑、授权判定、事件接收。

## 运行

```bash
cp .env.example .env
cargo run --bin auth-center
```

- API：`http://localhost:8080`
- Swagger UI：`http://localhost:8080/docs`
- OpenAPI JSON：`http://localhost:8080/openapi.json`
- 健康检查：`/health`、`/ready`

首次启动会执行迁移并播种默认租户、内置权限、`platform-admin` 角色、管理员账号、`auth-console` 与 `user-center` 客户端。管理员密码与客户端 secret 未显式配置时会随机生成并打印在日志中。

```bash
# 仅播种
cargo run --bin auth-center -- seed-admin
```

## 配置

优先级：`config/default.toml` → `config/<profile>.toml` → 环境变量。

环境变量格式为 `AUTH__SECTION__KEY`，例如：

```bash
AUTH__DATABASE__URL=postgres://auth_center:auth_center@localhost:5432/auth_center
AUTH__REDIS__URL=redis://localhost:6379/0
AUTH__SECURITY__MASTER_KEY=<openssl rand -base64 32>
AUTH__SECURITY__INTERNAL_TOKEN=<至少 24 字符>
AUTH__EVENTS__PUBLISH_URLS=["http://localhost:8081/api/v1/internal/events"]
```

关键安全配置：

- `security.master_key`：32 字节 Base64，用于 AES-256-GCM 加密数据库中的签名私钥。
- `security.internal_token`：与用户中心共享的内部调用令牌。
- `security.allowed_redirect_origins`：登录后跳转白名单，防开放重定向。
- `events.allow_http_targets`：仅本地开发可开启，生产必须使用 HTTPS。
- `notifications.provider`：`log` 或 `webhook`，接入真实邮件/短信网关。

## 主要接口

| 分类 | 路径 |
| --- | --- |
| 认证 | `/api/v1/auth/register`、`/login`、`/logout`、`/refresh`、`/mfa/verify`、`/password/change`、`/sessions` |
| OIDC | `/.well-known/openid-configuration`、`/oauth2/authorize`、`/oauth2/token`、`/oauth2/jwks`、`/oauth2/userinfo`、`/oauth2/introspect`、`/oauth2/revoke` |
| OAuth 管理 | `/api/v1/admin/oauth/clients`、`/oauth2/consents` |
| 授权 | `/api/v1/authz/check`、`/api/v1/admin/roles`、`/permissions`、`/policies`、`/resources` |
| MFA | `/api/v1/auth/mfa/totp`、`/mfa/webauthn`、`/mfa/recovery-codes` |
| SAML | `/saml/metadata`、`/saml/sso`、`/saml/slo`、`/api/v1/admin/saml/*` |
| 联邦 | `/api/v1/auth/federation/{provider}/start`、`/callback` |
| 内部 | `/api/v1/internal/identities/*`、`/api/v1/internal/authz/check`、`/api/v1/internal/events` |
| 管理 | `/api/v1/admin/identities`、`/tenants`、`/audit-logs` |

## 安全设计

- 密码使用 Argon2id；登录失败锁定；登录与验证码限流。
- JWT 私钥不落明文，数据库只存加密密文；JWKS 只输出公钥。
- Refresh Token 与授权码只存哈希，轮换时检测重放并撤销整条 Token 链。
- Cookie 认证强制 CSRF 双提交；TLS 环境下启用 `Secure`。
- 校验重定向白名单、SSRF 目标；统一安全响应头。
- 审计日志哈希链可校验篡改；事件消费幂等。

## 测试

```bash
cargo test --lib          # 单元测试（密码、JWT 算法、PKCE、重定向、Cookie、TOTP、输入校验等）
cargo test --test integration -- --ignored   # 需要真实 PostgreSQL/Redis
```

单元测试不伪造 Token：JWT 相关测试使用真实生成的 RSA 密钥。

## 部署

```bash
docker build -t auth-center .
docker run -p 8080:8080 --env-file .env auth-center
```

或使用 `base/docker-compose.yml` 一并启动 PostgreSQL、Redis 与用户中心。
