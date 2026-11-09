# 服务之间的交互说明

## 1. 数据所有权与边界

| 数据 | 权威方 | 说明 |
| --- | --- | --- |
| 身份主体、Subject、密码、凭证 | auth | 用户中心不得保存或校验密码 |
| 邮箱/手机号的验证结论 | auth | 验证码发送与校验只能在 auth 完成 |
| 邮箱/手机号业务展示 | user | 仅保存投影，换绑必须经 auth 校验 |
| 个人资料、扩展属性、标签 | user | auth 只保存登录所需的展示字段 |
| 分组、组织、部门、成员关系 | user | 变化以事件投影给 auth 的资源关系 |
| 角色、权限、授权策略 | auth | 用户分组不等于角色授权 |
| 业务账户状态 | user | 必须通过内部 API 同步到 auth 的身份状态 |
| 注册业务记录 | user | 注册失败时补偿删除 auth 身份 |

两个服务不得共享数据库、数据库访问层或实体代码，只通过 HTTP API 与领域事件通信。

## 2. ID 规范

- 用户 ID 为 UUID，由 auth 创建身份时生成（或由调用方带入）。
- user 的 `users.id` 必须等于 auth 身份的 `subject`。
- 跨服务关联只使用 UUID，不使用用户名、邮箱或手机号作为主键。

## 3. 内部 API（auth 提供）

所有内部请求必须携带 `x-internal-token`，服务端做常量时间比较。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/v1/internal/identities` | 创建认证身份 |
| GET | `/api/v1/internal/identities/{id}` | 查询身份基本信息 |
| PATCH | `/api/v1/internal/identities/{id}` | 同步展示资料（昵称、头像、邮箱、手机号） |
| POST | `/api/v1/internal/identities/{id}/status` | 启用/禁用/锁定/注销/恢复身份状态 |
| POST | `/api/v1/internal/identities/{id}/sessions/revoke` | 撤销该身份全部会话（禁用、注销、改密后） |
| POST | `/api/v1/internal/identities/{id}/contacts/request` | 发起邮箱/手机号换绑验证码 |
| POST | `/api/v1/internal/identities/{id}/contacts/confirm` | 校验验证码并切换联系方式 |
| DELETE | `/api/v1/internal/identities/{id}/contacts/{kind}` | 解绑邮箱或手机号 |
| POST | `/api/v1/internal/authz/check` | 内部授权判定（RBAC/ABAC/ReBAC） |
| POST | `/api/v1/internal/events` | 接收领域事件（Inbox 幂等） |

## 4. 内部 API（user 提供）

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/v1/internal/users/ensure` | 确保本地用户投影存在（不存在则从 auth 拉取身份创建） |
| GET | `/api/v1/internal/users/{id}` | 查询用户投影 |
| PATCH | `/api/v1/internal/users/{id}` | 更新资料投影 |
| POST | `/api/v1/internal/users/{id}/status` | 同步业务状态（不回调 auth，避免循环） |
| POST | `/api/v1/internal/users/{id}/contacts` | 同步已验证联系方式 |
| POST | `/api/v1/internal/events` | 接收 auth 领域事件 |

## 5. 领域事件

### auth 发布

- `auth.identity.registered`
- `auth.identity.activated`
- `auth.identity.disabled`
- `auth.identity.deleted`
- `auth.identity.restored`
- `auth.identity.credentials_changed`
- `auth.user_roles.changed`
- `auth.permissions.changed`
- `auth.tenant_membership.changed`
- `auth.session.created`
- `auth.mfa.enrolled` / `auth.mfa.removed`

### user 发布

- `user.created` / `user.profile.created`
- `user.profile.updated`
- `user.deleted` / `user.profile.deleted`
- `user.account_status.changed`
- `user.organization.changed`
- `user.group.changed`
- `user.contact.changed`

### 事件信封

```json
{
  "event_id": "0190f1c2-...",
  "event_type": "user.account_status.changed",
  "aggregate_type": "user",
  "aggregate_id": "0190f1c0-...",
  "occurred_at": "2026-11-09T08:00:00Z",
  "version": 1,
  "trace_id": "trace-123",
  "payload": {}
}
```

### 可靠性

- 业务事务内写 `outbox_events`，提交后由 dispatcher 异步投递。
- 投递失败按指数退避重试，超过最大次数进入死信（`status = 'dead'`）。
- 消费端先写 `inbox_events`（`UNIQUE(consumer, event_id)`）再处理，重复事件直接忽略。
- 消费失败不写 inbox，允许下一次重试。
- 事件处理完成后记录审计，并可失效本地权限缓存。

## 6. 注册一致性流程

1. 用户中心校验注册参数、开关、IP 限流与重复账号。
2. 调用 auth `POST /api/v1/internal/identities` 创建身份（可指定状态）。
3. 使用返回的同一个 UUID 创建 `users`、`user_profiles`、`user_contacts`、注册记录。
4. 任一步失败：删除已创建的 auth 身份作为补偿，并记录失败审计。
5. 需要审核时，身份为 `disabled`；审核通过后同步为 `active`，驳回则删除身份。
6. 全过程幂等：用户名/邮箱/手机号唯一约束 + 事件 Inbox 去重。

## 7. 状态同步

- 用户中心禁用/锁定/注销：`change_status` 事务写本地状态与事件，随后调用 auth 状态接口撤销会话并禁用身份。
- auth 管理员禁用身份：发布 `auth.identity.disabled`，用户中心更新本地状态与状态历史。
- 恢复：auth `auth.identity.restored` → 用户中心恢复为 `active`。
- 联系方式变化：用户中心调用 auth 发码与确认，auth 成功后用户中心更新 `user_contacts` 投影并发布 `user.contact.changed`。

## 8. 鉴权方式

- 用户中心从 auth JWKS 获取公钥并缓存（Redis + 内存，默认 300 秒），离线验证 RS/ES 系列 JWT。
- 校验 `iss`、`aud`、`exp`、`nbf`、`typ=access`，容差 30 秒；从 `sub`/`tenant_id` 提取身份与租户。
- 管理端权限通过 auth 内部授权接口判定，结果短 TTL 缓存（30 秒）。
- 用户中心不会自行签发 Token，也不会用共享密钥验证 Token。

## 9. 跨租户隔离

- 管理端请求只能操作令牌所属租户；请求体中的 `tenant_id` 必须与令牌一致，否则 403。
- 所有 SQL 查询均带 `tenant_id` 条件。
- 内部接口由内部令牌保护，调用方必须显式传入租户与身份 ID。
