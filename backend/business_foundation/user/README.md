# user-center 用户中心

用户业务资料与组织关系中心，鉴权完全依赖认证中心（auth-center），不保存密码、不签发 Token。

技术栈：Java 25、Spring Boot 4.1.2、Spring Framework 7.0.10、Spring Cloud 2025.1.4、Spring JDBC、Flyway、PostgreSQL、可选 Redis。

## 能力清单

- 用户资料：基础信息、昵称/头像、详细资料、资料完整度、标签。
- 扩展属性：字符串/数字/布尔/日期/枚举/数组类型，必填与范围/正则/选项校验；全量替换。
- 联系方式：邮箱/手机号投影；换绑与解绑必须经认证中心发码与校验；展示脱敏。
- 分组：树形分组（path/level 级联）、成员管理、用户所属分组查询。
- 组织与部门：树形组织/部门、负责人、成员、主组织/主部门、调动与历史。
- 注册：自助注册、开关与频率限制、审核（通过/驳回）、注册记录。
- 第三方账号关联：绑定、解绑、按 provider + subject 查找。
- 账户状态：启用/锁定/禁用/冻结/注销/恢复，状态机校验、状态历史，同步认证中心并撤销会话。
- 批量与导入导出：批量创建/更新（逐项结果）、CSV/JSON 导入导出。
- 内部服务 API：用户投影确保、状态/资料/联系方式同步、事件接收（Inbox 幂等）。
- 审计与事件：全量操作审计、Outbox 事件投递（指数退避、死信）。
- 运维：请求追踪 `X-Request-Id`、`/health`、`/live`、`/ready`、`/readyz`、`/openapi.json`、`/docs`。

## 构建与运行

```bash
# 编译打包（跳过测试）
mvn -DskipTests package

# 运行单元测试
mvn test

# 启动（默认 8081）
java -jar target/user-center.jar
```

要求 JDK 25 与 Maven 3.9+。启动前需准备：

1. PostgreSQL 数据库 `user_center`，Flyway 启动时自动执行 `src/main/resources/db/migration`；
2. 认证中心可访问（`USER_AUTH_BASE_URL`），内部令牌与认证中心 `security.internal_token` 一致；
3. Redis 可选：连接失败时自动降级为进程内缓存与限流，不影响启动。

- API：`http://localhost:8081`
- Swagger UI：`http://localhost:8081/docs`
- OpenAPI JSON：`http://localhost:8081/openapi.json`
- 健康检查：`/health`、`/ready`、`/readyz`（数据库、Redis、认证中心状态）

## 配置

环境变量示例见 `.env.example`：

```bash
USER_DATABASE_URL=jdbc:postgresql://localhost:5432/user_center
USER_DATABASE_USER=user_center
USER_DATABASE_PASSWORD=user_center
REDIS_HOST=localhost
REDIS_PORT=6379
USER_AUTH_BASE_URL=http://localhost:8080
USER_INTERNAL_TOKEN=<与认证中心一致>
USER_REGISTRATION_REQUIRE_REVIEW=true
```

## 鉴权方式

- 终端用户请求携带认证中心签发的 `Authorization: Bearer <access_token>`。
- 用户中心从认证中心 JWKS 获取公钥并缓存，自行完成 RS256 验签，校验 `iss`、`aud`、`exp`、`nbf`、`typ=access`；从 `sub` 提取用户 ID，从 `tenant_id` 提取租户。
- 管理端权限通过认证中心内部授权接口判定并短 TTL 缓存：
  - 用户管理：`identity:manage`
  - 审计日志：`audit:read`
- 认证中心不可达时返回 503；用户中心不保存密码、不验证密码、不签发 JWT。
- 内部接口使用 `X-Internal-Token` 校验。

## 主要接口

| 分类 | 路径 |
| --- | --- |
| 自助 | `/api/v1/users/me`、`/profile`、`/avatar`、`/nickname`、`/contacts`、`/attributes`、`/groups`、`/organizations`、`/history`、`/links`、`/registration` |
| 匿名注册 | `POST /api/v1/registrations` |
| 用户管理 | `/api/v1/admin/users`、`/{id}`、`/batch`、`/import`、`/export`、`/{id}/restore`、`/status`、`/tags`、`/contacts`、`/attributes`、`/groups`、`/memberships`、`/history`、`/status-history`、`/registration`、`/links`、`/transfer` |
| 属性 | `/api/v1/admin/attributes` |
| 分组 | `/api/v1/admin/groups`、`/tree`、`/{id}/members` |
| 组织 | `/api/v1/admin/organizations`、`/tree`、`/{id}/leader`、`/{id}/members` |
| 部门 | `/api/v1/admin/departments`、`/tree`、`/{id}/leader`、`/{id}/members` |
| 注册审核 | `/api/v1/admin/registrations`、`/{id}/review` |
| 审计 | `GET /api/v1/admin/audit-logs` |
| 内部 | `/api/v1/internal/users/ensure`、`/users/{id}`、`/users/{id}/status`、`/users/{id}/contacts`、`/events` |

## 关键行为

- 统一响应 `{"code":"ok","data":...}`，错误响应包含 `code`、`message`、`details` 与 `request_id`，JSON 使用 snake_case。
- 乐观锁：更新可携带 `If-Match` 或 `version`，冲突返回 409。
- 软删除与恢复；状态变更遵循状态机并写入 `user_status_history`。
- 列表支持过滤与白名单排序，分页默认 1/20，最大 200。
- 批量与导入逐项返回成功/失败；导出支持 CSV 与 JSON。
- 组织/分组树使用 `path`/`level` 级联维护，移动时检测循环，`code` 租户内唯一。
- 审计写入 `user_audit_logs`；领域事件写入 `outbox_events`，后台每 2 秒以 `FOR UPDATE SKIP LOCKED` 领取投递，失败指数退避，10 次转入死信。
- 认证中心事件通过 `inbox_events(event_id, consumer)` 幂等消费。

## 目录结构

```text
src/main/java/com/platform/user
├── bootstrap   # AuthClient（JWKS 验签 / authz / 同步）、Redis 降级、Outbox
├── common      # JSON、DB、分页、文本归一化、状态机、CSV、错误
├── config      # 配置属性、请求追踪、参数解析、Web 配置
├── service     # 用户、联系人、属性、分组、组织、注册、审计、内部服务
└── web         # 自助、管理端、内部、健康检查与 OpenAPI
```

## 测试

```bash
mvn test
```

单元测试只覆盖纯逻辑（分页解析、状态机、手机号/邮箱归一化、CSV 解析、权限校验、属性校验），不依赖数据库、Redis 或认证中心。

## 部署

```bash
docker build -t user-center .
docker run -p 8081:8081 --env-file .env user-center
```

镜像为多阶段构建（Maven + Temurin 25），以非 root 用户运行，暴露 8081。
