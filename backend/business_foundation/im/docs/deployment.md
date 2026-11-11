# 部署与运维

## 1. 组件与端口

| 组件 | 默认端口 | 说明 |
| --- | --- | --- |
| im-service HTTP | 8080 | 管理、设备、内部回调、Actuator、Swagger |
| im-service gRPC | 9090 | 业务服务调用 |
| PostgreSQL | 5432 | 业务数据库 |
| EMQX MQTT | 1883 | 设备 MQTT 连接（TLS 建议 8883） |
| EMQX Dashboard | 18083 | 管理控制台 |

## 2. 环境配置

### 2.1 开发环境

- 使用 `docker-compose.yml` 默认值
- `IM_SECURITY_ENABLED=true` 仍然生效，使用开发密钥
- `IM_SEED_ENABLED=true` 自动创建默认 Broker 与接入配置
- 邮件 Worker 默认开启；无 SMTP 时任务会进入重试/失败，属预期

```bash
cp .env.example .env
./scripts/start.sh
```

### 2.2 测试环境

建议与生产结构一致，仅规模较小：

- 独立数据库与 EMQX 实例
- 使用测试用 SMTP（如 MailHog/Mailpit 或测试邮箱）
- 开启安全认证，使用测试密钥
- 可关闭自动初始化：`IM_SEED_ENABLED=false`，通过管理 API 创建配置

### 2.3 生产环境

- 所有密钥通过环境变量或密钥管理系统注入，禁止提交 `.env`
- 开启 HTTPS（反向代理/网关终止 TLS）与 gRPC TLS（必要时 mTLS）
- 开启 EMQX TLS、Dashboard 强密码、限制管理端网络
- PostgreSQL 使用托管实例或主从，开启备份与监控
- 至少 2 个 im-service 实例时：
  - HTTP 无状态，可直接水平扩展
  - gRPC 通过负载均衡暴露
  - 邮件 Worker 可多实例：任务表使用 `FOR UPDATE SKIP LOCKED` 抢占，不会重复消费
  - 附件目录必须使用共享存储（NFS/对象存储挂载），否则多实例读取不到附件
- 建议设置资源限制与 JVM 参数：`-XX:MaxRAMPercentage=75`

## 3. 环境变量

所有变量均可通过环境变量覆盖 `application.yml`。常用变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IM_HTTP_PORT` | `8080` | HTTP 端口 |
| `IM_GRPC_PORT` | `9090` | gRPC 端口 |
| `IM_DATABASE_URL` | `jdbc:postgresql://localhost:5432/im_service` | JDBC URL |
| `IM_DATABASE_USER` | `im_service` | 数据库用户 |
| `IM_DATABASE_PASSWORD` | `im_service` | 数据库密码 |
| `IM_DB_POOL_SIZE` | `20` | Hikari 最大连接数 |
| `IM_FLYWAY_ENABLED` | `true` | 启动时执行迁移 |
| `IM_ENCRYPTION_KEY` | 开发默认值 | Base64 32 字节 AES 主密钥 |
| `IM_ADMIN_API_KEY` | 开发默认值 | 管理 API 快捷密钥 |
| `IM_INTERNAL_TOKEN` | 开发默认值 | 内部回调/gRPC 内部令牌 |
| `IM_DEVICE_TOKEN_PEPPER` | 开发默认值 | 设备令牌摘要 pepper |
| `IM_SECURITY_ENABLED` | `true` | 是否启用认证 |
| `IM_JWT_HMAC_SECRET` | 空 | JWT HMAC 密钥 |
| `IM_JWT_JWKS_URL` | 空 | JWT JWKS 地址 |
| `IM_JWT_ISSUER` / `IM_JWT_AUDIENCE` | 空 | JWT 校验 |
| `IM_GRPC_AUTH_ENABLED` | `true` | gRPC 认证 |
| `IM_GRPC_TLS_ENABLED` | `false` | gRPC TLS |
| `IM_GRPC_REQUIRE_CLIENT_AUTH` | `false` | gRPC mTLS |
| `IM_GRPC_CERT_CHAIN` / `IM_GRPC_PRIVATE_KEY` / `IM_GRPC_TRUST_CERT` | 空 | PEM 文件路径 |
| `IM_RATE_LIMIT_ENABLED` | `true` | HTTP/gRPC 限流 |
| `IM_RATE_LIMIT_HTTP_PER_MINUTE` | `600` | HTTP 每分钟限额 |
| `IM_RATE_LIMIT_GRPC_PER_MINUTE` | `6000` | gRPC 每分钟限额 |
| `IM_MQTT_DEFAULT_QOS` | `1` | 默认 QoS |
| `IM_MQTT_MAX_PAYLOAD_BYTES` | `262144` | 发布消息最大字节数 |
| `IM_MQTT_SERVICE_TOPIC_PREFIX` | `tenants/` | 服务发布 Topic 前缀 |
| `IM_EMAIL_WORKER_ENABLED` | `true` | 邮件 Worker 开关 |
| `IM_EMAIL_POLL_INTERVAL_MS` | `2000` | 轮询间隔 |
| `IM_EMAIL_MAX_ATTEMPTS` | `5` | 最大尝试次数 |
| `IM_EMAIL_RETRY_BASE_SECONDS` | `60` | 退避基数 |
| `IM_EMAIL_RETRY_MAX_SECONDS` | `3600` | 退避上限 |
| `IM_EMAIL_ATTACHMENT_DIR` | `./data/email-attachments` | 附件目录 |
| `IM_EMAIL_MAX_ATTACHMENT_BYTES` | `10485760` | 单附件上限 |
| `IM_EMAIL_MAX_TOTAL_ATTACHMENT_BYTES` | `26214400` | 附件总大小上限 |
| `IM_EMAIL_ALLOWED_ATTACHMENT_EXTENSIONS` | 见 yml | 允许扩展名 |
| `IM_EMAIL_MAX_RECIPIENTS` | `100` | 收件人总数上限 |
| `IM_SEED_ENABLED` | `true` | 初始化默认 Broker/接入配置 |
| `IM_SEED_BROKER_HOST` | `localhost` | 初始化 Broker 主机 |
| `IM_SEED_BROKER_TCP_PORT` | `1883` | 初始化 Broker 端口 |

完整列表见 `.env.example` 与 `src/main/resources/application.yml`。

## 4. 数据持久化

Docker Compose 卷：

| 卷 | 挂载点 | 内容 |
| --- | --- | --- |
| `pgdata` | `/var/lib/postgresql/data` | PostgreSQL 数据 |
| `emqxdata` | `/opt/emqx/data` | EMQX 数据与会话 |
| `attachments` | `/app/attachments` | 邮件附件 |

生产环境建议：

- PostgreSQL 使用托管服务或独立磁盘，按 RPO/RTO 配置备份
- 附件使用对象存储或共享文件系统
- EMQX 使用持久化存储并配置集群

## 5. 健康检查

| 检查 | 地址 | 用途 |
| --- | --- | --- |
| Liveness | `/actuator/health/liveness` | 进程存活，失败重启 |
| Readiness | `/actuator/health/readiness` | 依赖就绪，失败摘流 |
| 总体健康 | `/actuator/health` | 包含数据库、MQTT 等组件 |

Dockerfile 与 Compose 已配置 Readiness 健康检查。

## 6. 启动与停止

```bash
# 启动全部
./scripts/start.sh

# 仅重建 im-service
./scripts/start.sh im-service

# 停止（保留数据）
./scripts/stop.sh

# 停止并清空数据卷（危险）
./scripts/stop.sh --volumes

# 查看日志
docker compose logs -f im-service
```

手动命令：

```bash
docker compose --env-file .env up -d --build
docker compose --env-file .env ps
docker compose --env-file .env down
```

## 7. 镜像构建与运行

```bash
# 构建镜像
docker build -t im-service:1.0.0 .

# 运行（依赖外部 PostgreSQL / EMQX）
docker run -d --name im-service \
  -p 8080:8080 -p 9090:9090 \
  -e IM_DATABASE_URL=jdbc:postgresql://postgres:5432/im \
  -e IM_DATABASE_USER=im \
  -e IM_DATABASE_PASSWORD='<password>' \
  -e IM_ENCRYPTION_KEY='<base64-32-bytes>' \
  -e IM_ADMIN_API_KEY='<admin-key>' \
  -e IM_INTERNAL_TOKEN='<internal-token>' \
  -e IM_DEVICE_TOKEN_PEPPER='<pepper>' \
  -v /data/im/attachments:/app/attachments \
  im-service:1.0.0
```

## 8. 数据库初始化与升级

- 首次启动：Flyway 自动执行 `V1__init.sql` 建表。
- 升级：
  1. 在 `src/main/resources/db/migration` 新增 `V2__xxx.sql`。
  2. 在测试环境验证迁移。
  3. 备份生产数据库。
  4. 发布新版本，应用启动时自动执行 `flyway migrate`。
- 禁止修改已执行的历史脚本；需要修正时新增迁移。
- 查看迁移状态：

```sql
SELECT installed_rank, version, description, success, installed_on
FROM flyway_schema_history ORDER BY installed_rank;
```

- 回滚：优先使用向前兼容变更；必要时从备份恢复。
- 大数据量变更建议拆分为“加列 → 回填 → 切换 → 清理”，避免长时间锁表。

## 9. 密钥与凭证轮换

| 密钥 | 轮换影响 |
| --- | --- |
| `IM_ADMIN_API_KEY` / `IM_INTERNAL_TOKEN` | 同步更新调用方与 EMQX 配置后重启 |
| `IM_DEVICE_TOKEN_PEPPER` | 所有设备令牌摘要失效，需要重新创建/轮换设备凭证 |
| `IM_ENCRYPTION_KEY` | 历史密文无法解密；需要先解密再重新加密的数据迁移 |
| SMTP 密码 | 通过 `PUT /api/v1/admin/email/senders/{id}/password` 在线更新 |
| 设备 MQTT 密码 | 通过轮换接口更新，设备重新拉取配置 |

## 10. 常见问题

| 问题 | 处理 |
| --- | --- |
| 启动失败 `Flyway` | 检查数据库连接、用户建表权限、已执行脚本是否被修改 |
| EMQX 认证全部失败 | 检查 `IM_INTERNAL_TOKEN` 与 `docker/emqx/emqx.conf` 是否一致；查看 EMQX 日志 |
| gRPC 连接失败 | 确认端口 9090、TLS 配置、健康检查状态 |
| 邮件一直 PENDING | Worker 是否启用；数据库任务队列；查看日志与 `next_retry_at` |
| 邮件一直 RETRYING | 检查 SMTP 配置、限额、网络；查看 `last_error_message` |
| 附件发送失败 | 共享存储是否可读写；文件是否被清理；大小/类型限制 |
| 429 限流 | 调整 `IM_RATE_LIMIT_*` 或检查调用方是否异常高频 |
