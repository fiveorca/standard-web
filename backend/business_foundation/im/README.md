# im-service

平台通信基础设施服务：为平台内部业务服务与终端设备提供 **MQTT 设备消息发布** 和 **邮件发送** 能力。

- Java 25 / Spring Boot 4.1.x / Spring Cloud 2025.1.x / Spring Framework 7 / Maven
- Spring Data JPA + PostgreSQL + Flyway
- Protocol Buffers + gRPC（HTTP/2，可选 TLS/mTLS）
- MQTT 5.0（EMQX / Eclipse Paho）
- Spring Security、Actuator + Micrometer、OpenAPI 3
- 模块化单体，按领域分层组织，可平滑拆分 MQTT 与邮件模块

> 本服务不实现微信式用户聊天/好友/群聊业务，只提供通信基础设施。

## 功能概览

### MQTT

- Broker 管理：新增、修改、查询、删除、启停、设默认、测试连接、运行状态
- 接入配置管理：Broker 绑定、Topic 模板、QoS、Keep Alive、Session Expiry、TLS、认证模式、配置版本
- 设备凭证：创建、轮换、禁用、撤销、配置版本查询
- 设备配置查询：`GET /api/v1/device/mqtt/config`（仅返回当前设备自己的配置）
- EMQX 5 HTTP 认证/ACL 回调：`/api/v1/internal/mqtt/auth`、`/api/v1/internal/mqtt/acl`
- gRPC 发布：单设备、批量设备、授权 Topic；幂等、发送记录、失败原因
- MQTT 5.0 能力：QoS 0/1/2、Retained、Message Expiry、Clean Start、Session Expiry、自动重连与长连接复用

### 邮件

- 发送方管理：多 SMTP 账号、启用/禁用、默认发送方、密码独立更新、连接测试、测试邮件
- 异步任务：PENDING / PROCESSING / SUCCESS / RETRYING / FAILED
- 指数退避重试、最大重试次数、失败终态、手动重试
- 服务重启后的僵死任务恢复、任务抢占（`FOR UPDATE SKIP LOCKED`）、幂等受理
- 纯文本 / HTML / 抄送 / 密送 / 附件（类型与大小限制）
- 发送记录：状态、耗时、SMTP 返回信息、失败原因

### 通用能力

- 统一响应结构、统一错误码、统一分页、统一异常处理
- 管理接口认证 + RBAC 角色校验；设备接口独立认证
- HTTP / gRPC 固定窗口限流
- 租户隔离、幂等、防重放（requestId / messageId 唯一约束）
- 敏感字段 AES-256-GCM 加密存储，查询接口不返回密码
- 操作审计、Trace ID、统一日志、Liveness / Readiness、Prometheus 指标

## 快速开始（Docker Compose）

前置条件：Docker Engine / Docker Desktop，支持 Compose V2。

```bash
cp .env.example .env      # 修改 IM_ENCRYPTION_KEY、IM_ADMIN_API_KEY 等敏感值
./scripts/start.sh
```

启动后：

| 组件 | 地址 |
| --- | --- |
| HTTP API | http://localhost:8080 |
| Swagger UI | http://localhost:8080/docs |
| 健康检查 | http://localhost:8080/actuator/health |
| gRPC | localhost:9090 |
| EMQX Dashboard | http://localhost:18083 |

停止：

```bash
./scripts/stop.sh            # 保留数据卷
./scripts/stop.sh --volumes  # 清空数据库与 EMQX 数据
```

## 本地运行（不使用容器运行 im-service）

1. 启动 PostgreSQL 与 EMQX（可直接复用 compose 中的两个服务）：

```bash
docker compose up -d postgres emqx
```

2. 构建并运行：

```bash
export IM_DATABASE_URL=jdbc:postgresql://localhost:5432/im
export IM_DATABASE_USER=im
export IM_DATABASE_PASSWORD=im_password
export IM_INTERNAL_TOKEN=dev-internal-token-change-me
export IM_ADMIN_API_KEY=dev-admin-key-change-me
mvn -DskipTests package
java -jar target/im-service.jar
```

首次启动会自动执行 Flyway 迁移，并初始化默认 Broker 与默认接入配置（可用 `IM_SEED_ENABLED=false` 关闭）。

## 认证速查

| 调用方 | 方式 |
| --- | --- |
| 管理 HTTP API | `X-API-Key: <IM_ADMIN_API_KEY>` 或 `Authorization: Bearer <JWT>`（需 `IM_ADMIN` 角色） |
| 设备 HTTP API | `X-Device-Id` + `X-Device-Token`，或 `Authorization: Bearer <JWT>`（含 `device_id` claim） |
| 内部回调 / 内部 HTTP | `X-Internal-Token: <IM_INTERNAL_TOKEN>` |
| gRPC | metadata `x-internal-token` 或 `authorization: Bearer <JWT>` |
| 设备 MQTT | 服务创建的 MQTT 用户名/密码，Broker 通过 HTTP 回调本服务校验 |

> 生产环境请替换所有默认密钥，开启 HTTPS / gRPC TLS，并限制管理端网络访问。

## 目录结构

```text
im/
├── pom.xml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── docker/emqx/emqx.conf
├── scripts/
│   ├── start.sh
│   └── stop.sh
├── docs/
│   ├── architecture.md
│   ├── database.md
│   ├── http-api.md
│   ├── grpc-api.md
│   ├── mqtt.md
│   └── deployment.md
└── src/
    ├── main/
    │   ├── java/com/platform/im/
    │   │   ├── application/      业务编排
    │   │   ├── config/           配置、Web、安全、初始化
    │   │   ├── domain/           领域模型、规则、Repository 接口
    │   │   ├── grpc/             gRPC 服务与拦截器
    │   │   ├── infrastructure/   MQTT、邮件、限流适配器
    │   │   ├── security/         认证、JWT、设备认证
    │   │   ├── shared/           统一响应、错误、加密、分页
    │   │   └── web/              HTTP Controller 与 DTO
    │   ├── proto/                Protobuf 契约
    │   └── resources/
    │       ├── application.yml
    │       └── db/migration/V1__init.sql
    └── test/java/com/platform/im/
```

## 文档

- [架构设计](docs/architecture.md)
- [数据库设计](docs/database.md)
- [HTTP API 与 Java 调用示例](docs/http-api.md)
- [gRPC API 与 Java 调用示例](docs/grpc-api.md)
- [MQTT 接入与 Topic 权限](docs/mqtt.md)
- [部署与运维](docs/deployment.md)

## 测试

```bash
# 单元测试（Domain / Application / gRPC InProcess）
mvn test

# Docker 集成测试（Testcontainers + PostgreSQL，需要 Docker）
mvn -Pintegration test
```

集成测试覆盖：Flyway 建表、管理 API、设备配置、EMQX 认证/ACL 回调、错误凭证 401。

## 监控

- Liveness：`GET /actuator/health/liveness`
- Readiness：`GET /actuator/health/readiness`
- 指标：`GET /actuator/metrics`、`GET /actuator/prometheus`
- 关键指标：
  - `im.mqtt.publish.total{result=...}`、`im.mqtt.publish.duration`、`im.mqtt.reconnect.total`
  - `im.email.send.total{result=...}`、`im.email.retry.total`、`im.email.send.duration`、`im.email.pending.tasks`
  - `im.grpc.requests.total`、`im.grpc.request.duration`
  - HTTP 指标由 Spring Boot / Micrometer 自动采集

## 安全说明

- 所有 MQTT 密码、SMTP 密码使用 AES-256-GCM 加密后落库，查询接口只返回 `hasPassword`
- 设备 MQTT 密码使用随机生成值，数据库仅保存带 pepper 的摘要
- 管理接口默认拒绝匿名访问，内部回调使用常量时间比较令牌
- 请求体大小、附件类型/大小、Topic 长度、QoS、设备 ID 均进行校验
- `messageId` / `requestId` + 租户唯一约束保证幂等，避免重复发送
- 生产环境必须通过环境变量或密钥管理系统注入主密钥，禁止硬编码
