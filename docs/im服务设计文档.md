# 项目开发提示词：IM 通信服务（im-service）

## 一、项目角色

你是一名资深 Java 架构师和高级后端开发工程师，负责设计和实现一个生产级、可扩展、易维护的 IM 通信服务。

请直接在当前工作区创建项目并实现代码，而不只是输出架构设计文档或示例代码。

项目名称：`im-service`

项目定位：互联网平台基础通信服务，统一为平台内部其他业务服务、终端设备提供 MQTT 消息推送和邮件发送能力。

注意：这里的 IM 服务主要指平台通信基础设施，不要求实现类似微信的用户聊天、好友关系、群聊等业务功能。

## 二、技术栈要求

严格遵循以下技术栈：

- Java 25+
- Spring Boot 4.1.x
- Spring Cloud 2025.1.x
- Spring Framework 7.x
- Maven
- Spring Data JPA / Hibernate（数据持久化）
- PostgreSQL（关系型数据库）
- Flyway（数据库版本管理）
- Protocol Buffers + gRPC（服务间通信）
- MQTT 5.0（设备消息通信）
- Jakarta EE 11 相关规范
- Spring Security（安全认证与授权）
- Spring Boot Actuator（健康检查和监控）
- OpenAPI 3（HTTP API 文档）
- Docker / Docker Compose（容器化部署）

版本管理要求：

1. 使用 Maven BOM 统一管理 Spring Boot 和 Spring Cloud 依赖。
2. Spring Boot、Spring Cloud、Spring Framework 版本必须保持官方兼容。
3. 使用 Spring Cloud 2025.1.x 时，针对 Spring Boot 4.1.x，选择官方明确支持该版本线的 Spring Cloud 补丁版本。
4. Spring Framework 由 Spring Boot 管理，原则上禁止手动覆盖版本。
5. 所有第三方组件必须确认兼容 Java 25、Spring Boot 4 和 Spring Framework 7。
6. 注意 Spring Boot 4 的 Jackson 3、Jakarta 包名等变化，不得直接照搬 Spring Boot 3 的旧代码。
7. gRPC 优先采用官方 grpc-java 生态和 Protobuf；如果使用 Spring Boot Starter，必须先验证其对 Spring Boot 4 的兼容性。

在编码前核实官方依赖版本、兼容性及推荐用法，不得通过强行覆盖依赖版本解决兼容问题。

## 三、总体架构要求

采用模块化单体架构。

整个服务作为一个独立部署的 Spring Boot 应用，但内部必须按照业务领域和技术职责进行模块划分，保证各模块低耦合、高内聚。

主要包含以下业务模块：

1. MQTT 设备通信模块。
2. 邮件发送模块。
3. gRPC 服务接口模块。
4. HTTP 管理接口模块。
5. 配置管理模块。
6. 消息发送记录及任务管理模块。
7. 安全认证与权限控制模块。

架构要求：

- Controller 负责 HTTP 接口。
- gRPC Service 负责 gRPC 接口。
- Application Service 负责业务编排。
- Domain 负责核心业务模型及领域规则。
- Infrastructure 负责数据库、MQTT、邮件供应商等外部基础设施集成。
- DTO、Entity、Domain Model 职责明确，不允许混用。
- 外部组件必须通过接口和适配器接入。
- 不允许 Controller 直接操作 Repository。
- 不允许在业务代码中硬编码 MQTT 和邮件服务商配置。
- 不允许将核心业务逻辑全部堆积在 Service 类中。

设计时考虑未来可能将 MQTT 模块、邮件模块独立拆分成微服务，但当前不需要拆成多个独立应用。

## 四、MQTT 设备通信模块

### 4.1 MQTT 基础要求

采用外部 MQTT Broker，优先支持 EMQX。

Spring Boot 服务作为 MQTT 发布客户端，与 Broker 建立连接，为平台其他服务提供设备消息发布能力。

设备端通过 MQTT 协议直接连接 Broker，不经过 Spring Boot HTTP 服务转发消息。

要求：

- 支持 MQTT 5.0。
- 支持 TCP、TLS。
- 支持 QoS 0、QoS 1、QoS 2。
- 支持 Retained Message。
- 支持 Client ID。
- 支持 Keep Alive。
- 支持 Clean Start 和 Session Expiry。
- 支持不同 Broker 配置。
- 支持 MQTT 连接异常重连。
- 支持连接状态监控。
- 支持连接池或合理的长连接复用机制。
- 支持消息过期时间。
- 支持设备离线后的会话管理。

MQTT Broker 必须与 Spring Boot 应用独立部署。

通过 MQTT Broker 适配器屏蔽不同 Broker 的差异，避免业务代码直接依赖 EMQX 的具体实现。

### 4.2 设备通过 HTTP 获取 MQTT 配置

提供 HTTP 接口，设备经过身份认证后获取自己的 MQTT 连接配置。

参考接口：

`GET /api/v1/device/mqtt/config`

返回配置至少包含：

- Broker 地址。
- MQTT 端口。
- MQTT 协议版本。
- 是否启用 TLS。
- Client ID。
- Username。
- Password。
- Keep Alive。
- Clean Start。
- Session Expiry。
- QoS 默认值。
- 设备发布 Topic。
- 设备订阅 Topic。
- Topic 权限范围。
- 配置版本号。

要求：

1. 根据当前设备身份返回对应 MQTT 配置。
2. 设备只能获取自己的配置，不得获取其他设备的连接凭证。
3. 不同设备可以使用不同的 MQTT 连接参数及权限。
4. 支持配置变更和配置版本管理。
5. 支持设备凭证生成、轮换、禁用和撤销。
6. MQTT 用户名和密码需要具备足够的随机性。
7. 设备只能订阅和发布授权范围内的 Topic。
8. 严禁向设备暴露 Broker 管理账号及管理 API 凭证。
9. 返回的 MQTT 配置不得包含不必要的敏感信息。
10. 设备认证应支持与现有平台身份认证体系集成，不重新实现一套用户中心。

需要设计合理的 MQTT 身份认证和 ACL 权限机制，保证设备不能通过修改 Topic 访问其他设备的数据。

### 4.3 MQTT 配置管理 HTTP 接口

提供完整的 MQTT 配置管理 HTTP API。

管理范围包括：

**Broker 管理：**

- 新增 Broker。
- 修改 Broker。
- 查询 Broker。
- 删除 Broker。
- 启用、禁用 Broker。
- 测试 Broker 连接。
- 查看 Broker 运行状态。

**MQTT 接入配置管理：**

- 新增 MQTT 接入配置。
- 修改 MQTT 接入配置。
- 查询 MQTT 接入配置。
- 删除 MQTT 接入配置。
- 配置默认 Broker。
- 配置设备连接参数。
- 配置设备 Topic 规则。
- 配置 QoS、Keep Alive 等参数。
- 配置 TLS。
- 配置设备身份认证策略。

**设备 MQTT 凭证管理：**

- 创建设备 MQTT 凭证。
- 查询设备 MQTT 配置。
- 轮换设备凭证。
- 禁用设备凭证。
- 撤销设备凭证。
- 查询设备当前配置版本。

配置管理必须支持数据校验、权限控制、操作审计及敏感数据加密。

密码等敏感字段不能在普通查询接口中明文返回。

### 4.4 gRPC 向设备发送 MQTT 消息

为平台其他业务服务提供 gRPC 接口，允许其他服务通过设备 ID 向指定设备发送 MQTT 消息。

定义 Protobuf 服务，例如：

`MqttMessageService`

至少提供：

- `PublishToDevice`：向指定设备发送消息。
- `BatchPublishToDevices`：向多个设备批量发送消息。
- `PublishToTopic`：向指定授权 Topic 发送消息。

发送请求包含：

- tenantId（租户 ID，预留多租户能力）。
- deviceId（设备 ID）。
- messageId（消息唯一 ID）。
- payload（消息内容）。
- contentType（消息内容类型）。
- qos。
- retained。
- messageExpiryInterval。

要求：

1. 调用方通过 gRPC 发送请求。
2. 服务根据 deviceId 查找对应 MQTT 配置。
3. 自动生成或解析经过授权的 Topic。
4. 调用 MQTT Broker 发布消息。
5. 不允许普通业务服务任意指定未授权 Topic。
6. 支持单设备和批量设备消息发送。
7. 支持 QoS 设置。
8. 支持消息发送结果返回。
9. 支持消息发送记录及失败原因查询。
10. 支持 gRPC 调用超时、异常处理及必要的重试机制。
11. 支持请求幂等，避免重复发送。
12. 支持多租户数据隔离。

特别注意：

MQTT QoS 1/2 只能提供对应的 MQTT 协议交付保障，Broker 接受消息不等于设备业务逻辑已经处理消息。

如需要确认设备实际收到并处理消息，应预留基于设备 ACK 的业务确认机制。

## 五、邮件发送模块

### 5.1 邮件发送能力

为平台其他业务服务提供 gRPC 邮件发送接口。

定义 Protobuf 服务：

`EmailService`

至少提供：

- `SendEmail`：发送邮件。
- `BatchSendEmail`：批量发送邮件。
- `GetEmailStatus`：查询邮件任务发送状态。

邮件请求包含：

- requestId（请求唯一 ID）。
- senderId（邮件发送方 ID）。
- to（收件人）。
- cc（抄送人）。
- bcc（密送人）。
- subject（邮件主题）。
- textBody（纯文本内容）。
- htmlBody（HTML 内容）。
- attachments（邮件附件）。

要求：

1. 业务服务通过 gRPC 调用邮件服务。
2. 支持指定 senderId 选择邮件发送方。
3. senderId 为空时，使用已配置的默认邮件发送方。
4. 支持不同业务使用不同邮件发送方。
5. 支持多个 SMTP 账号。
6. 支持邮件发送方启用、禁用和默认配置。
7. 支持纯文本邮件。
8. 支持 HTML 邮件。
9. 支持抄送和密送。
10. 支持附件，限制附件大小和类型。
11. 支持请求幂等，防止重复发送。
12. 记录每封邮件的发送状态、发送时间、失败原因和供应商返回信息。
13. 不允许将 SMTP 用户名、密码等敏感信息返回给调用方。
14. 支持邮件发送异常处理、限流、超时和失败重试。

### 5.2 邮件发送方及供应商适配

采用邮件供应商适配器模式。

第一阶段优先实现 SMTP。

邮件发送方配置至少包含：

- senderId。
- 发送方名称。
- 发件人邮箱。
- 发件人显示名称。
- 邮件服务商类型。
- SMTP Host。
- SMTP Port。
- SMTP Username。
- SMTP Password。
- SMTP Auth。
- SMTP SSL。
- SMTP STARTTLS。
- Connection Timeout。
- Read Timeout。
- 默认发送方标记。
- 每分钟发送限制。
- 每日发送限制。
- 启用状态。

需要将邮件发送方配置与实际供应商实现解耦。

未来应能方便地扩展：

- SMTP。
- Amazon SES。
- SendGrid。
- Mailgun。
- 其他邮件 API 服务商。

第一阶段不必全部实现，但必须预留清晰的扩展接口。

### 5.3 邮件任务及发送机制

建议采用可靠的异步发送机制：

1. gRPC 接收邮件请求。
2. 校验发送方、收件人及邮件内容。
3. 将邮件任务和必要的发送信息持久化。
4. 返回任务 ID 和受理结果。
5. 后台 Worker 执行邮件发送。
6. 成功后记录发送成功状态。
7. 失败后根据重试策略执行重试。
8. 超过最大重试次数后进入失败终态。
9. 支持通过 gRPC 或 HTTP 查询邮件状态。

至少设计以下状态：

- PENDING。
- PROCESSING。
- SUCCESS。
- RETRYING。
- FAILED。

需要考虑服务重启后的任务恢复、并发消费、幂等和重复发送问题。

可以优先采用数据库任务表与可靠任务调度机制实现第一阶段，不强制引入 RabbitMQ 或 Kafka。

当未来发送量增长时，应能通过任务调度适配层扩展为独立消息队列。

### 5.4 邮件发送方管理 HTTP 接口

提供完整的邮件发送方管理 HTTP API。

至少包含：

- 新增邮件发送方。
- 修改邮件发送方。
- 删除邮件发送方。
- 查询邮件发送方列表。
- 查询邮件发送方详情。
- 启用邮件发送方。
- 禁用邮件发送方。
- 设置默认邮件发送方。
- 测试 SMTP 连接。
- 发送测试邮件。
- 查询邮件发送记录。
- 查询邮件任务详情。
- 查询发送失败原因。
- 手动重试失败任务。

要求：

1. 支持多个邮件发送方。
2. 支持不同业务选择不同邮件发送方。
3. 支持默认发送方配置。
4. 修改 SMTP 配置后能够正确更新连接资源。
5. 敏感配置必须加密存储。
6. 普通查询接口不得返回 SMTP Password。
7. 修改密码时支持独立更新。
8. 删除正在使用的发送方时进行依赖校验。
9. 所有管理操作需要记录审计日志。

## 六、HTTP API 设计要求

HTTP API 统一使用 RESTful 风格。

统一接口规范：

- URL 版本控制：`/api/v1`
- 使用 JSON 作为默认数据交换格式。
- 统一响应结构。
- 统一分页参数。
- 统一异常处理。
- 统一参数校验。
- 统一错误码。
- 统一时间格式，采用 ISO 8601。
- 支持 OpenAPI 3 文档。

统一响应结构示例：

{
  "code": 0,
  "message": "success",
  "data": {},
  "timestamp": "2026-01-01T12:00:00Z"
}

HTTP 管理接口与设备接口必须区分权限。

管理接口必须进行管理员身份认证和 RBAC 权限校验；设备接口必须验证设备身份。

## 七、gRPC 设计要求

gRPC 使用 Protobuf 定义通信契约。

建议目录：

`src/main/proto/`

分别定义：

- mqtt_message_service.proto
- email_service.proto

要求：

1. 使用明确的 package 和服务版本。
2. 请求和响应字段命名规范。
3. 保留 Protobuf 字段编号，不随意复用。
4. 提供统一错误码和 gRPC Status 映射。
5. 实现服务端拦截器。
6. 支持调用身份认证。
7. 支持 TLS，生产环境支持 mTLS。
8. 支持 Deadline 和超时。
9. 支持健康检查。
10. 支持服务接口文档。
11. 生成 Java Stub，并提供给其他 Java 服务调用。
12. 保留其他语言调用能力。

需要同时提供 Proto 文件和 Java 调用示例。

## 八、安全设计

安全性必须作为生产级功能实现。

至少包括：

1. 管理接口身份认证。
2. 管理接口 RBAC 权限控制。
3. 设备身份认证。
4. gRPC 服务间身份认证。
5. MQTT 设备独立认证。
6. MQTT Topic 级别 ACL 控制。
7. MQTT TLS。
8. gRPC TLS / mTLS。
9. SMTP 密码加密存储。
10. MQTT 密码加密存储。
11. 使用环境变量或外部密钥管理系统管理主密钥。
12. 敏感数据日志脱敏。
13. HTTP 和 gRPC 调用限流。
14. 防止重放及重复请求。
15. 操作审计。
16. 租户隔离。
17. 输入参数合法性校验。

不允许在源代码、配置文件、Docker 镜像中硬编码生产环境密钥。

## 九、数据模型设计

使用 PostgreSQL。

结合业务需求设计数据库表，至少考虑以下实体：

MQTT：

- mqtt_broker：MQTT Broker 配置信息。
- mqtt_access_config：MQTT 接入配置。
- mqtt_device_credential：设备 MQTT 凭证。
- mqtt_topic_acl：设备 Topic 权限。
- mqtt_publish_record：MQTT 消息发送记录。

邮件：

- email_sender：邮件发送方。
- email_sender_config：邮件发送连接配置。
- email_task：邮件发送任务。
- email_recipient：邮件收件人。
- email_attachment：邮件附件信息。
- email_send_record：邮件发送记录。

通用：

- operation_audit_log：操作审计日志。

以上仅为建议，允许根据领域模型进行合理调整。

要求：

1. 主键使用 UUID 或经过合理设计的 ID 策略。
2. 关键字段建立必要索引。
3. 考虑租户 ID。
4. 创建时间和更新时间统一管理。
5. 敏感字段加密。
6. 设置合理的唯一约束。
7. 考虑数据状态和逻辑删除。
8. 发送记录需要考虑数据增长及历史归档。
9. 通过 Flyway 管理数据库 DDL。
10. 提供完整的初始化 SQL 和数据库迁移脚本。

## 十、监控及运维

通过 Spring Boot Actuator 和 Micrometer 提供运行监控。

至少监控：

MQTT：

- Broker 连接状态。
- 重连次数。
- 消息发送总量。
- 消息发送成功量。
- 消息发送失败量。
- 消息发布延迟。

邮件：

- 待发送任务数。
- 邮件发送成功量。
- 邮件发送失败量。
- 邮件重试量。
- 邮件发送延迟。

系统：

- HTTP 请求量。
- HTTP 接口耗时。
- gRPC 请求量。
- gRPC 调用耗时。
- JVM 状态。
- 数据库连接池状态。
- Worker 状态。

提供：

- Liveness。
- Readiness。
- 统一日志格式。
- Trace ID。
- 错误日志。
- 关键业务操作审计。

## 十一、项目目录结构

请采用清晰、规范、容易理解的目录组织方式。

建议按业务模块及分层组织，而不是按照 Java 技术类型简单堆放所有代码。

示例：

im-service/
├── pom.xml
├── README.md
├── Dockerfile
├── docker-compose.yml
├── docs/
│   ├── architecture.md
│   ├── database.md
│   ├── http-api.md
│   ├── grpc-api.md
│   ├── mqtt.md
│   └── deployment.md
├── proto/
│   ├── mqtt/
│   └── email/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── ...
│   │   └── resources/
│   │       ├── application.yml
│   │       └── db/migration/
│   └── test/
│       └── java/
└── scripts/

具体目录可以根据最终架构优化，但必须保证模块职责清晰，避免过度设计。

## 十二、测试要求

必须编写自动化测试。

至少包含：

- Domain 单元测试。
- Application Service 单元测试。
- Repository 集成测试。
- HTTP Controller 测试。
- gRPC 接口测试。
- MQTT 发布测试。
- 邮件发送测试。
- 邮件任务重试测试。
- 幂等性测试。
- 权限及数据隔离测试。
- 异常场景测试。

优先使用 JUnit 5、Mockito 和 Testcontainers。

核心业务逻辑必须具备测试覆盖，不能仅生成没有实际断言的测试文件。

## 十三、Docker 部署要求

提供 Dockerfile 和 docker-compose.yml。

第一阶段至少支持以下基础设施：

- im-service
- PostgreSQL
- EMQX

可根据实际架构增加必要组件，但禁止为了使用某项技术而引入不必要的中间件。

提供：

- 开发环境配置。
- 测试环境配置。
- 生产环境配置示例。
- 环境变量说明。
- 数据持久化配置。
- 服务健康检查。
- 启动和停止脚本。
- 数据库初始化及升级说明。

## 十四、开发实施要求

请按照以下顺序开展工作：

第一阶段：架构设计

1. 分析所有需求。
2. 输出系统架构图。
3. 确定模块边界。
4. 确定核心业务流程。
5. 确定数据库模型。
6. 确定 REST API。
7. 确定 gRPC Protobuf 契约。
8. 确定 MQTT 与邮件供应商适配方案。

第二阶段：项目初始化

1. 创建 Maven 工程。
2. 配置 Java 25。
3. 配置 Spring Boot 4.1.x。
4. 配置 Spring Cloud 2025.1.x。
5. 配置代码规范。
6. 配置数据库及 Flyway。
7. 配置 OpenAPI。
8. 配置 gRPC。

第三阶段：核心功能实现

1. 实现 MQTT Broker 管理。
2. 实现 MQTT 设备凭证管理。
3. 实现设备 MQTT 配置获取接口。
4. 实现 MQTT 消息 gRPC 发布接口。
5. 实现邮件发送方管理。
6. 实现 SMTP 适配器。
7. 实现邮件发送 gRPC 接口。
8. 实现邮件任务及重试机制。
9. 实现安全、审计及监控。

第四阶段：测试及交付

1. 编译整个项目。
2. 执行自动化测试。
3. 修复编译错误和测试错误。
4. 验证 Docker Compose 部署。
5. 补充完整项目文档。
6. 提供 HTTP 和 gRPC 调用示例。

## 十五、最终交付标准

必须交付真正可运行的项目，而不是只有架构图或空壳代码。

最终需要具备：

1. 完整 Maven 项目。
2. 完整数据库 DDL 和 Flyway 迁移文件。
3. 完整 HTTP API。
4. 完整 gRPC Protobuf 接口。
5. 可用的 MQTT Broker 集成。
6. 可用的邮件 SMTP 集成。
7. 完整的配置管理能力。
8. 完整的身份认证与权限校验。
9. 自动化测试。
10. Docker 部署配置。
11. 完整开发及部署文档。
12. HTTP 和 gRPC 使用示例。

禁止：

- 只输出伪代码。
- 只实现 Controller，不实现业务逻辑。
- 只定义接口，不提供实际实现。
- 使用大量 TODO 代替业务实现。
- 为了让代码编译而随意删除需求。
- 使用不兼容的依赖版本。
- 将敏感配置明文存储。
- 在没有验证的情况下宣称功能已经实现。

如果存在第三方服务账号、生产环境密钥等外部条件无法满足，可以提供真实的集成实现和可配置的测试环境，但必须明确说明需要用户提供的配置。

每完成一个阶段，都必须保证当前阶段代码能够正常编译，并尽可能执行相关测试。

最终以一个可以独立部署、独立运行、可扩展、具备生产环境演进能力的 Java 通信基础服务为交付目标。