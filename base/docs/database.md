# 数据库表结构说明

两个服务使用完全独立的数据库：

- `auth_center`：由 `base/auth/migrations/0001_init.sql` 创建。
- `user_center`：由 `base/user/migrations/0001_init.sql` 创建。

所有业务表均包含 `tenant_id`（除全局角色/权限外），并启用软删除字段 `deleted_at`（按表需要）。时间字段统一使用 `timestamptz`，主键统一使用 UUID（多数为 UUIDv7）。

## 一、认证授权中心（auth_center）

### 身份与凭证

| 表 | 说明 |
| --- | --- |
| `tenants` | 租户；`00000000-0000-0000-0000-000000000001` 为默认租户 |
| `identities` | 身份主体；`id` 即跨服务用户 ID / JWT `sub`；含邮箱、手机号、状态、来源 |
| `identity_identifiers` | 登录标识（username/email/phone）；`UNIQUE(kind, normalized_value)` |
| `identity_credentials` | 凭证（password 等）；密码仅存 Argon2id 哈希 |
| `password_history` | 历史密码哈希，用于禁止复用 |
| `verification_codes` | 邮箱/短信验证码；只存 HMAC 哈希、用途、尝试次数与过期时间 |

### 会话与 Token

| 表 | 说明 |
| --- | --- |
| `auth_sessions` | 登录会话；记录客户端、IP、UA、AMR/ACR、最后活跃时间 |
| `refresh_tokens` | Refresh Token（哈希存储）；支持轮换、重放检测与撤销 |
| `authorization_codes` | OAuth2 授权码；绑定 PKCE challenge、nonce、redirect_uri |
| `signing_keys` | JWT 签名密钥；私钥使用 AES-256-GCM 加密，支持轮换与保留期 |

### OAuth2 / OIDC

| 表 | 说明 |
| --- | --- |
| `oauth_clients` | OAuth 客户端；`client_secret_hash`、redirect URI、grant types、scopes、PKCE 开关 |
| `oauth_scopes` | 自定义 scope 元数据 |
| `oauth_consents` | 用户对客户端 + scope 的授权同意记录 |

### MFA

| 表 | 说明 |
| --- | --- |
| `mfa_factors` | TOTP / WebAuthn / Passkey 因子；凭证与公钥 |
| `mfa_recovery_codes` | 恢复码（哈希存储，一次性） |

### 身份联邦与 SAML

| 表 | 说明 |
| --- | --- |
| `identity_providers` | 外部 OIDC/OAuth2/Google/GitHub/Microsoft/Apple 提供商配置 |
| `external_identities` | 外部账号映射；`UNIQUE(provider_id, external_subject)` |
| `saml_idp_configs` | SAML IdP 配置（实体 ID、证书、私钥、签名算法） |
| `saml_sp_configs` | 受信 SP 配置（ACS、SLO、属性映射、签名要求） |
| `saml_replay_cache` | SAML Assertion/Request ID 防重放缓存 |

### 授权模型

| 表 | 说明 |
| --- | --- |
| `roles` | 角色；全局角色 `tenant_id IS NULL` |
| `permissions` | 权限；全局权限 `tenant_id IS NULL`；含 `kind`（action/menu/button/api/data） |
| `role_permissions` | 角色－权限关联 |
| `user_roles` | 用户－角色关联（含租户与有效期） |
| `user_permissions` | 用户直接授权（正/负授权） |
| `resource_types` | 资源类型定义与属性 schema |
| `resource_relations` | ReBAC 资源关系（subject－relation－object） |
| `identity_org_memberships` | 身份与组织/部门的投影，用于数据范围与组织关系授权 |
| `authorization_policies` | ABAC 策略（条件 JSON）与数据范围策略 |
| `api_resources` | API 权限资源（method + path 模式） |
| `menu_resources` | 菜单权限资源（树形） |
| `button_resources` | 按钮权限资源 |
| `data_permissions` | 数据权限规则（范围：all/tenant/org/department/self/custom） |

### 审计与事件

| 表 | 说明 |
| --- | --- |
| `security_audit_logs` | 安全审计日志；`prev_hash`/`hash` 构成哈希链 |
| `outbox_events` | 事务性 Outbox；状态、尝试次数、下次重试时间、死信 |
| `inbox_events` | Inbox 幂等消费记录；`UNIQUE(consumer, event_id)` |

## 二、用户中心（user_center）

### 用户与资料

| 表 | 说明 |
| --- | --- |
| `users` | 用户业务主体；`id` 与认证中心身份 ID 一致；含状态、来源、最后登录/活跃时间 |
| `user_profiles` | 详细资料：性别、生日、简介、地区、时区、语言、公司、职位、扩展信息、资料完整度 |
| `user_tags` | 用户标签 |
| `user_status_history` | 状态变更历史（操作人、原因） |
| `user_audit_logs` | 用户中心审计日志（不含敏感凭证） |

### 扩展属性

| 表 | 说明 |
| --- | --- |
| `user_attributes` | 属性定义：编码、类型（string/number/boolean/date/enum/array）、必填、默认值、校验规则、选项、排序、分组 |
| `user_attribute_values` | 用户属性值（JSONB），`UNIQUE(user_id, attribute_id)` |

### 联系方式

| 表 | 说明 |
| --- | --- |
| `user_contacts` | 邮箱/手机号投影；`UNIQUE(kind, normalized_value)`；验证状态；实际验证由认证中心完成 |

### 分组与组织

| 表 | 说明 |
| --- | --- |
| `user_groups` | 用户分组（树形：`parent_id`、`path`、`level`）；标签与扩展属性 |
| `user_group_members` | 分组－用户关联 |
| `organizations` | 组织（企业/公司/团队等类型，树形，负责人，扩展属性） |
| `departments` | 部门（树形，负责人，扩展属性） |
| `organization_members` | 组织成员（职位、是否主组织） |
| `department_members` | 部门成员（职位、是否主部门，支持兼职） |
| `user_organization_history` | 用户组织/部门变动历史 |

### 注册与关联

| 表 | 说明 |
| --- | --- |
| `user_registration_records` | 注册申请：状态（pending/approved/rejected/completed）、来源、渠道、活动、邀请码、审核信息 |
| `user_account_links` | 第三方账号关联；`UNIQUE(user_id, provider)` 与 `UNIQUE(provider, provider_subject)` |

### 事件

| 表 | 说明 |
| --- | --- |
| `outbox_events` | 用户中心 Outbox |
| `inbox_events` | 用户中心 Inbox 幂等消费记录 |

## 三、索引与约束要点

- 身份登录标识、联系方式均对规范化值建立唯一索引，防止重复账号。
- 会话、Refresh Token、授权码、验证码均按 `expires_at` 建索引便于清理。
- 用户列表筛选字段（状态、来源、创建时间）与组织/分组成员关系均有索引。
- 审计表按租户 + 创建时间倒序索引。
- Outbox 按 `status + next_attempt_at` 索引，消费者使用 `FOR UPDATE SKIP LOCKED` 并发领取。
