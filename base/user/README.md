# user-center 用户中心

用户业务资料与组织关系中心，鉴权完全依赖认证中心（auth-center），不保存密码、不签发 Token。

## 能力清单

- 用户资料：基础信息、昵称/头像、详细资料、资料完整度、标签。
- 扩展属性：字符串/数字/布尔/日期/枚举/数组类型，必填与范围/正则/选项校验。
- 联系方式：邮箱/手机号投影；换绑与解绑必须经认证中心发码与校验；展示脱敏。
- 分组：树形分组、成员管理、用户所属分组查询。
- 组织与部门：树形组织/部门、负责人、成员、主组织/主部门、调动与历史。
- 注册：自助注册、开关与频率限制、审核（通过/驳回）、注册记录。
- 第三方账号关联：绑定、解绑、按 provider + subject 查找。
- 账户状态：启用/锁定/禁用/注销/恢复，同步认证中心并撤销会话。
- 批量与导入导出：批量创建/更新、CSV 导入导出。
- 内部服务 API：用户投影确保、状态/资料/联系方式同步、事件接收。
- 审计：用户中心操作审计、状态历史。

## 运行

```bash
cp .env.example .env
cargo run --bin user-center
```

- API：`http://localhost:8081`
- Swagger UI：`http://localhost:8081/docs`
- OpenAPI JSON：`http://localhost:8081/openapi.json`
- 健康检查：`/health`、`/ready`（包含数据库、Redis、认证中心状态）

启动前需确保：

1. 认证中心已启动并可访问 `auth.base_url`；
2. `auth.internal_token` 与认证中心 `security.internal_token` 一致；
3. 已创建 `user-center` OAuth 客户端（认证中心启动时自动播种），如需 client_credentials 请配置 `auth.service_client_secret`。

## 配置

环境变量格式 `USER__SECTION__KEY`：

```bash
USER__DATABASE__URL=postgres://user_center:user_center@localhost:5432/user_center
USER__REDIS__URL=redis://localhost:6379/1
USER__AUTH__BASE_URL=http://localhost:8080
USER__AUTH__INTERNAL_TOKEN=<与认证中心一致>
USER__AUTH__SERVICE_CLIENT_SECRET=<user-center secret>
USER__REGISTRATION__REQUIRE_REVIEW=false
```

## 鉴权方式

- 终端用户请求携带认证中心签发的 `Authorization: Bearer <access_token>`。
- 用户中心从认证中心 JWKS 获取公钥并缓存（Redis + 内存，默认 300 秒），离线校验 RS256/384/512、ES256/384 的 JWT。
- 校验 `iss`、`aud`、`exp`、`nbf`、`typ=access`；从 `sub` 提取用户 ID，从 `tenant_id` 提取租户。
- 管理端权限通过认证中心内部授权接口判定并短 TTL 缓存：
  - 用户管理：`identity:manage`
  - 审计日志：`audit:read`
- 用户中心不保存密码、不验证密码、不签发 JWT。

## 主要接口

| 分类 | 路径 |
| --- | --- |
| 自助 | `/api/v1/users/me`、`/profile`、`/avatar`、`/nickname`、`/contacts`、`/attributes`、`/groups`、`/organizations`、`/history`、`/links` |
| 注册 | `POST /api/v1/registrations` |
| 用户管理 | `/api/v1/admin/users`、`/{id}`、`/batch`、`/import`、`/export`、`/{id}/status`、`/{id}/tags`、`/{id}/contacts`、`/{id}/attributes`、`/{id}/memberships`、`/{id}/transfer` |
| 属性 | `/api/v1/admin/attributes` |
| 分组 | `/api/v1/admin/groups`、`/tree`、`/{id}/members` |
| 组织 | `/api/v1/admin/organizations`、`/tree`、`/{id}/leader`、`/{id}/members` |
| 部门 | `/api/v1/admin/departments`、`/tree`、`/{id}/leader`、`/{id}/members` |
| 注册审核 | `/api/v1/admin/registrations`、`/{id}/review` |
| 审计 | `/api/v1/admin/audit-logs` |
| 内部 | `/api/v1/internal/users/*`、`/api/v1/internal/events` |

## 与认证中心的协作

- 注册、创建用户：用户中心调用认证中心内部 API 创建身份，密码只透传，不落库。
- 禁用/注销：用户中心变更本地状态后调用认证中心撤销会话并同步身份状态。
- 联系方式：用户中心请求认证中心发送验证码并校验，成功后更新本地投影。
- 组织关系：用户中心发布 `user.organization.changed` 事件，认证中心消费后更新资源关系与授权缓存。
- 认证中心事件（`auth.identity.*`）由用户中心 Inbox 幂等消费，同步状态、登录时间与权限缓存。

完整事件与内部 API 说明见 [../docs/integration.md](../docs/integration.md)。

## 测试

```bash
cargo test --lib                    # 单元测试（规范化、校验、脱敏、分页、配置合并）
cargo test --test integration -- --ignored   # 需要真实 PostgreSQL 与认证中心
```

集成测试真实执行迁移并读写数据库，覆盖用户生命周期、状态变更、跨租户隔离、分组关系和 Inbox 幂等。

## 部署

```bash
docker build -t user-center .
docker run -p 8081:8081 --env-file .env user-center
```
