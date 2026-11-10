# 项目名称：统一日志服务（Log Service）

## 一、项目定位

你是一名资深 Rust 后端架构师、分布式系统架构师，需要设计并实现一个生产级、可独立部署的统一日志服务。

该服务属于互联网基础设施平台中的基础中间件，供其他业务系统统一接入，实现日志采集、传输、存储、查询、全文检索、统计分析和管理。

本项目采用 Rust 技术栈，以 Axum 作为 HTTP Web 框架，以 Tonic 作为 gRPC 框架，以 Apache Kafka 作为消息队列，以 ClickHouse 作为日志存储和分析引擎。

核心要求：

1. 支持业务服务直接通过 Kafka 投递日志。
2. 支持业务服务通过 gRPC 接口投递日志。
3. Kafka 和 gRPC 两种接入方式使用同一套日志数据规范。
4. gRPC 接收的日志必须转发到 Kafka，不能直接写入 ClickHouse。
5. 使用 Rust Worker 消费 Kafka，并批量写入 ClickHouse。
6. 支持日志查询、全文检索、条件过滤、详情查看和统计分析。
7. 提供 REST API，便于未来管理平台和 Web 前端集成。
8. 支持日志保留、异常重试、死信队列、数据脱敏和系统监控。
9. 整个日志服务可以独立部署、独立扩容和独立维护。

不要只输出架构设计，必须实际编写可以构建、运行和测试的完整项目代码。

## 二、技术栈

采用以下技术：

### 核心技术

- 编程语言：Rust Stable。
- 异步运行时：Tokio。
- HTTP Web 框架：Axum。
- gRPC 框架：Tonic。
- Protobuf：Prost。
- 消息队列：Apache Kafka。
- Kafka Rust 客户端：rust-rdkafka。
- 日志存储：ClickHouse。
- ClickHouse Rust 客户端：官方 clickhouse-rs（clickhouse crate）。
- 序列化：Serde + serde_json。
- 时间处理：chrono 或 time。
- HTTP 中间件：Tower + tower-http。
- 日志与链路追踪：tracing + tracing-subscriber。
- 指标采集：Prometheus + metrics 或 OpenTelemetry。
- API 文档：OpenAPI + utoipa。
- 配置管理：TOML + 环境变量。

依赖要求：

1. 优先选择成熟、活跃维护、兼容 Tokio 的 Rust Crate。
2. 版本以实施时的稳定版本为准，检查 Axum、Tonic、Prost 和 Tower 的兼容性。
3. 固定依赖版本，并提交 Cargo.lock。
4. 禁止使用没有必要的实验性依赖。
5. ClickHouse 默认使用官方 Rust 客户端，通过 HTTP RowBinary 等高效格式进行读写；批量写入必须经过性能测试。
6. 不引入 ORM，直接使用 ClickHouse 客户端和参数化 SQL。
7. 不允许自行实现 Kafka 客户端或 ClickHouse 网络协议。

## 三、整体架构

采用统一日志接入、异步消费和集中存储的架构。

### 3.1 日志接入流程

方式一：Kafka 直接投递

业务服务
    ↓
Kafka Topic：logs.raw.v1
    ↓
Rust Log Worker
    ↓
ClickHouse

方式二：gRPC 接口投递

业务服务
    ↓
Tonic gRPC Server
    ↓
日志格式校验、认证、脱敏
    ↓
Kafka Producer
    ↓
Kafka Topic：logs.raw.v1
    ↓
Rust Log Worker
    ↓
ClickHouse

两种接入方式必须统一进入 logs.raw.v1。

无论采用哪种方式，最终存储的数据结构和查询方式必须完全一致。

### 3.2 服务运行模式

一个 Rust 项目，一套核心业务代码，支持不同运行角色：

1. api 模式：
   - Axum HTTP REST Server。
   - Tonic gRPC Server。
   - Kafka Producer。
   - 日志查询和统计服务。

2. worker 模式：
   - Kafka Consumer。
   - 日志校验和转换。
   - 批量缓冲。
   - ClickHouse 批量写入。
   - 异常消息处理。

3. all 模式：
   - 开发环境使用。
   - 同时启动 API 和 Worker。

生产部署优先将 API 和 Worker 作为独立进程或容器运行，允许分别扩容。

API 与 Worker 必须复用同一套领域模型和业务规则，不得复制两套业务逻辑。

### 3.3 服务端口

建议：

- Axum HTTP：8080。
- Tonic gRPC：9090。
- ClickHouse HTTP：8123。
- ClickHouse Native：9000。
- Kafka：按部署配置。

Axum 和 Tonic 可以使用独立监听端口，共享 Tokio 运行时和必要的应用状态。

不要为了共用端口而引入不必要的 HTTP/2 协议复用复杂度。

## 四、统一日志数据规范

所有业务服务必须使用统一 JSON 数据结构。

示例：

{
  "schemaVersion": "1.0",
  "eventId": "550e8400-e29b-41d4-a716-446655440000",
  "@timestamp": "2026-11-10T10:20:30.123Z",
  "level": "ERROR",
  "serviceName": "order-service",
  "serviceVersion": "1.0.0",
  "environment": "prod",
  "hostName": "server-01",
  "logger": "com.example.OrderService",
  "threadName": "worker-01",
  "message": "Order creation failed",
  "traceId": "trace-123456",
  "spanId": "span-123456",
  "requestId": "request-123456",
  "tenantId": "tenant-001",
  "exception": {
    "type": "SQLException",
    "message": "Connection timeout",
    "stackTrace": "..."
  },
  "attributes": {
    "orderId": "10001",
    "userId": "20001"
  }
}

### 字段定义

| 字段 | 类型 | 说明 |
|---|---|---|
| schemaVersion | string | 数据结构版本 |
| eventId | UUID | 日志唯一标识 |
| @timestamp | datetime | 日志产生时间，UTC |
| level | string | TRACE、DEBUG、INFO、WARN、ERROR、FATAL |
| serviceName | string | 业务服务名称 |
| serviceVersion | string | 业务服务版本 |
| environment | string | dev、test、staging、prod |
| hostName | string | 来源服务器 |
| logger | string | Logger 名称 |
| threadName | string | 线程名称 |
| message | string | 日志正文 |
| traceId | string | 链路追踪 ID |
| spanId | string | Span ID |
| requestId | string | 请求 ID |
| tenantId | string | 租户 ID |
| exception | object | 异常详情，可为空 |
| attributes | object | 扩展业务属性 |

要求：

1. 必须提供 JSON Schema 文件。
2. 明确必填字段和可选字段。
3. 所有时间字段统一使用 UTC。
4. 由服务端设置 receivedAt，记录日志接收时间。
5. eventId 必须稳定，调用方重试时必须复用原来的 eventId。
6. 统一提供 Rust 结构体和序列化、反序列化实现。
7. gRPC Proto 和 Kafka JSON 必须能够转换到同一个内部 LogEvent 模型。
8. 扩展字段不能无限制地动态创建 ClickHouse 列。
9. 对 attributes 设置大小、深度和字段数量限制。
10. 预留 schemaVersion 兼容和升级机制。

需要实现敏感信息过滤，至少处理：

- password
- accessToken
- refreshToken
- authorization
- cookie
- secret
- apiKey

支持配置脱敏规则，禁止敏感信息直接进入持久化存储。

## 五、gRPC 日志投递

使用 Tonic + Prost 实现真正的 gRPC 服务。

禁止使用 HTTP POST 模拟 gRPC。

Proto 文件建议：

proto/
  log/v1/ingestion.proto

定义服务：

LogIngestionService

主要 RPC：

1. IngestBatch
   - 单次请求提交多条日志。
   - 返回接收数量、拒绝数量及错误详情。
   - 适合业务服务批量上报。

2. StreamLogs
   - 支持客户端流式发送日志。
   - 服务端进行流量控制和批量投递。
   - 用于持续日志上报场景。

每条日志的 Protobuf 字段必须与统一 LogEvent 模型对应。

建议使用：
- google.protobuf.Timestamp 表示时间。
- google.protobuf.Struct 或明确的扩展结构表示 attributes。
- ExceptionInfo 表示异常详情。

### gRPC 处理要求

1. gRPC 接口收到请求后进行身份认证。
2. 校验每条日志的数据合法性。
3. 校验通过后转换成统一 LogEvent。
4. 统一序列化为 Kafka JSON 消息。
5. 投递到 logs.raw.v1。
6. 等待 Kafka Broker 确认后再返回接收成功。
7. Kafka 投递失败时返回明确的 gRPC 错误。
8. 不允许返回成功但实际上没有投递成功。
9. 支持单批日志部分成功、部分失败。
10. 对请求大小、日志数量、单条日志大小设置可配置限制。
11. 实现 gRPC 超时、并发限制和背压。
12. 使用 TLS 或 mTLS，支持服务身份认证。
13. 将租户身份与实际传入的 tenantId 进行校验。

建议默认限制：

- 单条日志最大 256 KiB。
- 单次批量请求最大 4 MiB。
- 单次批量数量默认不超过 500 条。

所有限制都必须外部配置化。

### gRPC 返回语义

成功接收只代表 Kafka 已经确认接收消息，不代表 ClickHouse 已经完成持久化。

返回信息至少包括：

- requestId
- acceptedCount
- rejectedCount
- 每条失败日志的索引及原因

正确映射 gRPC Status Code，不允许用统一 OK 掩盖失败。

## 六、Kafka 接入与消费

### 6.1 Topic 设计

主要 Topic：

logs.raw.v1

异常 Topic：

logs.dlq.v1

必要时可以扩展：

logs.retry.v1

要求：

1. Kafka 消息使用统一 JSON 格式。
2. gRPC 投递和业务服务直接投递完全一致。
3. 设置合理的分区数量，支持水平扩容。
4. 设置副本数量和 min.insync.replicas。
5. Producer 使用 acks=all。
6. 启用生产者幂等能力。
7. 设置合理的重试、压缩和超时参数。
8. 支持配置消息保留时间。
9. 支持 Kafka ACL、SASL 和 TLS。
10. 禁止把业务服务的内部敏感信息写入 Kafka Header。

Kafka 消息 Key 默认优先使用 eventId，必要时支持配置 traceId 以便保持同一 Trace 的分区内顺序。

### 6.2 Rust Kafka Producer

使用 rust-rdkafka。

要求：

- 实现异步生产者。
- 支持批量发送。
- 处理消息投递确认。
- 处理生产者异常。
- 支持连接恢复。
- 监控消息投递延迟及失败次数。

### 6.3 Rust Kafka Consumer

使用 StreamConsumer。

Consumer Group：

log-service-writer

要求：

1. 支持多实例并行消费。
2. 支持分区自动再均衡。
3. 禁止开启不符合可靠性要求的自动提交。
4. 必须采用手动 Offset 提交。
5. 日志只有成功写入 ClickHouse 后才能提交对应 Kafka Offset。
6. 批量消息中存在异常时，必须正确区分永久错误和临时错误。
7. 无效格式消息进入 DLQ。
8. ClickHouse 暂时不可用时进行退避重试，不能直接丢弃消息。
9. 发生消费者重启后支持从已提交 Offset 恢复。
10. 正确处理多分区批量消费及每个分区的连续 Offset 提交。

投递语义：

采用 At-least-once（至少一次）语义。

不能声称端到端 Exactly-once。

使用 eventId 作为日志唯一标识，提供重复消息处理能力和明确的去重策略。需要说明 ClickHouse 的后台合并去重不是即时事务去重，不能假设所有重复数据立即消失。

## 七、ClickHouse 日志存储

### 7.1 技术要求

使用 ClickHouse 作为唯一核心日志存储引擎。

禁止将原始日志同时保存到 MySQL 或 PostgreSQL。

不使用 Elasticsearch、OpenSearch、Loki 作为额外存储。

### 7.2 数据库和表

数据库：

log_center

主表建议：

logs

采用 MergeTree 系列引擎。

优先评估 ReplacingMergeTree(ingest_version)，结合 eventId 实现重复消息的最终去重，并明确其后台合并及查询一致性限制。

初步字段设计：

- event_id UUID
- schema_version LowCardinality(String)
- log_time DateTime64(3, 'UTC')
- ingest_time DateTime64(3, 'UTC')
- ingest_version UInt64
- level LowCardinality(String)
- service_name LowCardinality(String)
- service_version LowCardinality(String)
- environment LowCardinality(String)
- host_name LowCardinality(String)
- logger String
- thread_name String
- message String
- trace_id String
- span_id String
- request_id String
- tenant_id String
- exception_type String
- exception_message String
- stack_trace String
- attributes_json String

根据需要可以增加 exception_fingerprint 等分析字段。

### 7.3 索引和排序

必须根据实际查询场景设计：

1. PARTITION BY 使用 toYYYYMM(log_time) 等低基数时间分区策略。
2. ORDER BY 初始方案可考虑：
   (tenant_id, environment, service_name, toDate(log_time), log_time, event_id)
3. 根据数据量和查询情况调整排序键。
4. message 建立 Text Index。
5. stack_trace 视实际查询频率决定是否建立 Text Index。
6. trace_id、request_id 等字段可以评估 Bloom Filter 跳数索引。
7. 不要为所有字段盲目建立索引。
8. 使用 EXPLAIN indexes 验证索引是否实际生效。
9. 不允许无限制创建分区。
10. 不允许按照每个服务动态创建一张表。

ClickHouse 版本必须支持生产级 Text Index，建议优先使用 26.2 或以上稳定版本。

中英文全文搜索需要分别评估合适的 tokenizer。支持中文日志时，优先评估 ClickHouse 支持的 chinese tokenizer，并通过实际中文日志进行测试。

### 7.4 日志生命周期

使用 ClickHouse TTL 实现日志自动过期清理。

默认保留 30 天。

要求：

- 保留期限可配置。
- 支持按照时间自动删除过期日志。
- 根据数据量设置合理分区和 TTL 策略。
- 监控磁盘空间、数据 Parts、合并任务和写入压力。
- 明确 TTL 清理由后台合并执行，并非到期瞬间删除。
- 为未来冷数据归档预留能力。

### 7.5 日志批量写入

Rust Worker 必须实现客户端批量缓冲。

建议配置：

- batch_max_rows：最大批量行数。
- batch_max_bytes：最大批量字节数。
- batch_flush_interval_ms：最大等待刷新时间。
- max_concurrent_inserts：最大并发写入数。
- insert_timeout_ms：写入超时。
- retry_backoff：重试策略。

任一刷新条件满足时触发批量写入。

不能每条日志执行一次 INSERT。

不能无上限缓存日志。

当 Kafka 消费速度大于 ClickHouse 写入速度时，必须保持背压机制。

建议优先使用 Rust 官方 clickhouse 客户端提供的批量 Insert/InStrict 或 Inserter 等实际可用 API，先验证接口和版本，不得自行编造方法。

## 八、日志查询 REST API

使用 Axum 实现查询接口。

日志投递不提供 HTTP 接口，日志投递只能通过 Kafka 或 gRPC 完成。

查询和管理使用 REST API。

### 8.1 日志列表

POST /api/v1/logs/query

请求支持：

- startTime
- endTime
- levels
- serviceNames
- environments
- hostNames
- traceId
- spanId
- requestId
- tenantId
- exceptionType
- keyword
- pageSize
- cursor

支持多条件组合查询。

要求：

1. 按日志时间倒序。
2. 支持全文关键字搜索。
3. 支持服务、环境、级别和时间过滤。
4. 支持租户数据隔离。
5. 支持稳定的 Keyset/Cursor 分页。
6. 不依赖无限增大的 OFFSET。
7. 限制单次查询的时间范围。
8. 限制最大返回数量。
9. 设置 SQL 执行超时和并发限制。
10. 对用户输入严格校验，不能直接拼接 SQL。
11. 所有查询必须采用参数绑定。
12. 支持查询条件和执行耗时记录。

返回日志列表、分页游标及 hasMore 等信息。

大数据量场景不要默认执行全表精确 COUNT。

### 8.2 日志详情

GET /api/v1/logs/{eventId}

返回完整日志内容。

包括：

- 基础字段。
- 日志正文。
- 异常信息。
- 完整堆栈。
- Trace 信息。
- attributes。

### 8.3 日志统计

提供：

GET /api/v1/analytics/overview

统计：

- 日志总量。
- 各日志级别数量。
- 各服务日志数量。
- 各环境日志数量。
- ERROR 占比。
- FATAL 占比。

GET /api/v1/analytics/trends

支持：

- 分钟趋势。
- 小时趋势。
- 天趋势。

GET /api/v1/analytics/top-errors

支持统计：

- Top 异常类型。
- Top 异常服务。
- Top 异常信息。
- 异常发生次数。
- 最近发生时间。

所有聚合统计必须尽可能直接通过 ClickHouse SQL 完成，不允许把大量日志取到 Rust 内存中再计算。

合理设计时间桶和聚合字段，限制高基数聚合查询。

## 九、可视化管理

第一阶段使用 Grafana + 官方 ClickHouse Data Source。

要求：

1. Docker Compose 集成 Grafana。
2. 自动配置 ClickHouse Data Source。
3. 提供基础日志 Dashboard。
4. 支持日志时间趋势。
5. 支持不同日志级别分布。
6. 支持各业务服务日志数量统计。
7. 支持 ERROR 日志查询。
8. 支持 Top 异常分析。
9. 支持 Explore 日志检索。
10. 提供 Dashboard JSON 导入文件。

Grafana 使用独立只读 ClickHouse 账号。

Grafana 仅部署在可信管理网络，不向业务服务开放 ClickHouse 权限。

同时保留完整 REST API，未来可以自己实现 Web 日志管理界面，不依赖 Grafana 才能完成日志查询。

## 十、认证、授权和安全

本日志服务属于基础中间件，应当支持接入已有的统一认证和授权体系。

如果项目已经存在统一认证中心、授权中心，必须优先复用。

权限区分：

- 日志投递权限。
- 日志查询权限。
- 日志管理权限。
- 日志运维权限。

要求：

1. gRPC 使用 mTLS 或安全的服务身份认证。
2. Kafka 使用 ACL、SASL 和必要的 TLS。
3. Axum REST API 必须支持身份认证。
4. ClickHouse 不能直接暴露给外部业务服务。
5. Rust API 和 Worker 使用最小权限账号。
6. Grafana 使用只读账号。
7. 多租户查询必须在服务端强制附加租户条件。
8. 不得信任调用方任意填写的 tenantId。
9. 敏感数据必须脱敏。
10. 不记录密码、Token 等敏感认证信息。

## 十一、监控与可观测性

通过 tracing、Prometheus 和 OpenTelemetry 等成熟组件提供监控能力。

至少包括：

### gRPC

- 请求数量。
- 接收成功数量。
- 拒绝数量。
- 请求延迟。
- Kafka 投递失败次数。
- 活跃连接数量。

### Kafka

- 消息生产数量。
- 生产失败数量。
- Consumer Lag。
- 消费速率。
- 重试次数。
- DLQ 消息数量。

### ClickHouse

- 写入行数。
- 写入字节数。
- 批量写入耗时。
- 写入失败次数。
- 查询耗时。
- 查询失败次数。
- 数据库存储空间。
- 活跃 Parts 数量。

### Rust 服务

- CPU。
- 内存。
- Tokio 任务运行情况。
- 活跃请求。
- 错误率。
- 进程健康状态。

特别要求：

日志服务自身的运行日志不能无条件再次进入自己的日志采集链路，防止形成无限循环。

## 十二、错误处理和可靠性

必须覆盖以下故障场景：

1. Kafka 暂时不可用。
2. ClickHouse 暂时不可用。
3. Worker 进程突然退出。
4. Kafka 消费者重新平衡。
5. 批量写入部分失败。
6. 错误 JSON。
7. 消息重复投递。
8. 大量日志突发。
9. 日志超出大小限制。
10. gRPC 客户端连接中断。
11. 磁盘空间不足。
12. ClickHouse 达到查询资源限制。

要求：

- 明确重试和退避策略。
- 失败消息不得静默丢弃。
- 正确管理 Kafka Offset。
- 重要操作记录监控指标。
- 提供 DLQ 查询与重放机制。
- 避免无限重试毒丸消息。
- 实现优雅关闭及未完成任务处理。
- 具备合理的连接池、限流、超时和背压。

## 十三、项目目录结构

采用清晰、可维护、便于后期拆分的模块化结构。

建议：

log-service/
├── Cargo.toml
├── Cargo.lock
├── build.rs
├── config/
│   ├── default.toml
│   ├── development.toml
│   ├── production.toml
│   └── config.example.toml
├── proto/
│   └── log/
│       └── v1/
│           └── ingestion.proto
├── migrations/
│   └── clickhouse/
│       ├── 001_create_database.sql
│       ├── 002_create_logs_table.sql
│       ├── 003_create_indexes.sql
│       └── 004_create_ttl.sql
├── schemas/
│   └── log-event-v1.schema.json
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   ├── common/
│   ├── domain/
│   │   ├── log_event.rs
│   │   ├── log_level.rs
│   │   └── error.rs
│   ├── application/
│   │   ├── ingestion/
│   │   ├── query/
│   │   └── analytics/
│   ├── transport/
│   │   ├── grpc/
│   │   │   └── ingestion/
│   │   └── http/
│   │       ├── routes/
│   │       ├── handlers/
│   │       └── middleware/
│   ├── infrastructure/
│   │   ├── kafka/
│   │   │   ├── producer.rs
│   │   │   └── consumer.rs
│   │   ├── clickhouse/
│   │   │   ├── client.rs
│   │   │   ├── repository.rs
│   │   │   └── models.rs
│   │   └── security/
│   ├── worker/
│   │   ├── consumer_loop.rs
│   │   ├── batch_buffer.rs
│   │   ├── processor.rs
│   │   ├── writer.rs
│   │   └── dlq.rs
│   └── observability/
├── tests/
├── deploy/
│   ├── docker/
│   ├── docker-compose.yml
│   ├── grafana/
│   └── scripts/
└── docs/
    ├── architecture.md
    ├── data-schema.md
    ├── grpc-api.md
    ├── rest-api.md
    ├── kafka.md
    ├── clickhouse.md
    └── deployment.md

以上是建议结构，可以根据实际实现进行合理调整，但必须保持职责清晰。

## 十四、部署要求

提供 Docker Compose 开发环境。

至少包括：

- Kafka。
- ClickHouse。
- Grafana。
- Log Service API。
- Log Service Worker。

要求：

1. 提供可运行的 Docker Compose 配置。
2. 使用固定的镜像版本，禁止 latest 标签。
3. 配置持久化数据卷。
4. 支持容器健康检查。
5. 提供数据库初始化 SQL。
6. 提供 Topic 初始化脚本。
7. 提供 Grafana Data Source 自动配置。
8. 提供环境变量示例。
9. 密码、密钥不能硬编码在代码中。
10. 提供启动、停止、重启、查看日志等操作说明。

开发环境可以使用单节点 Kafka 和单节点 ClickHouse。

生产部署文档必须说明 Kafka 和 ClickHouse 的高可用、备份恢复、容量规划及水平扩容方案。不能把单节点 Docker Compose 宣称为高可用生产方案。

## 十五、测试要求

必须编写：

1. LogEvent JSON Schema 校验测试。
2. Protobuf 与内部 LogEvent 转换测试。
3. gRPC 单条日志投递测试。
4. gRPC 批量日志投递测试。
5. gRPC 流式投递测试。
6. Kafka 直接投递测试。
7. Kafka 消费测试。
8. Kafka 消费失败与恢复测试。
9. ClickHouse 批量写入测试。
10. ClickHouse 全文检索测试。
11. ClickHouse 多条件组合查询测试。
12. 日志 Cursor 分页测试。
13. 日志聚合统计测试。
14. 日志 TTL 配置测试。
15. 重复 eventId 处理测试。
16. DLQ 处理测试。
17. 多租户隔离测试。
18. 敏感信息脱敏测试。
19. Kafka 故障时的 gRPC 返回测试。
20. ClickHouse 故障时的消费重试测试。

使用 Testcontainers 或其他真实测试基础设施进行关键链路集成测试，不允许只通过 Mock 证明整个日志链路可用。

## 十六、性能测试

需要提供基准测试程序和测试说明。

测试场景：

- 单条 gRPC 日志投递。
- gRPC 批量日志投递。
- Kafka 直接投递。
- 多生产者并发投递。
- Worker 批量消费。
- ClickHouse 批量写入。
- 全文检索性能。
- 多条件查询性能。
- 大时间范围统计性能。

输出：

- 日志吞吐量（条/秒）。
- 接入延迟。
- Kafka 投递延迟。
- Kafka 消费延迟。
- ClickHouse 写入延迟。
- 查询 P50、P95、P99。
- CPU 和内存使用情况。
- Kafka 积压恢复情况。

不得在没有实际测试的情况下宣称系统能够达到某个性能指标。

## 十七、实施顺序

请按照以下阶段进行实施。

### 第一阶段：架构和数据设计

1. 输出系统整体架构图。
2. 输出日志数据流转图。
3. 输出 Kafka Topic 设计。
4. 输出 gRPC Proto 定义。
5. 输出统一 JSON Schema。
6. 输出 ClickHouse 表结构和索引设计。
7. 输出 REST API 规范。
8. 输出项目目录结构。

### 第二阶段：项目基础设施

1. 初始化 Rust 项目。
2. 配置 Axum。
3. 配置 Tonic + Prost。
4. 配置 Kafka Producer。
5. 配置 Kafka Consumer。
6. 配置 ClickHouse 客户端。
7. 实现统一配置、错误处理和日志监控。

### 第三阶段：日志接入和存储

1. 实现 gRPC 日志接收。
2. 实现 Kafka 消息生产。
3. 支持 Kafka 直接投递。
4. 实现统一数据模型转换。
5. 实现日志校验和脱敏。
6. 实现 Kafka 消费 Worker。
7. 实现批量缓冲。
8. 实现 ClickHouse 批量写入。
9. 实现失败处理、重试和 DLQ。

### 第四阶段：查询和分析

1. 实现日志列表查询。
2. 实现日志全文检索。
3. 实现日志详情。
4. 实现 Cursor 分页。
5. 实现日志级别统计。
6. 实现业务服务统计。
7. 实现时间趋势。
8. 实现 Top 异常统计。

### 第五阶段：监控和可视化

1. 配置 Prometheus 指标。
2. 配置 Grafana ClickHouse 数据源。
3. 创建日志 Dashboard。
4. 创建异常统计 Dashboard。
5. 创建系统运行监控 Dashboard。

### 第六阶段：部署与验收

1. 完成 Docker Compose。
2. 完成初始化脚本。
3. 完成自动化测试。
4. 完成性能测试。
5. 验证 Kafka 直投完整链路。
6. 验证 gRPC 投递完整链路。
7. 验证数据查询和分析。
8. 验证故障恢复和消息重放。
9. 完成部署及运维文档。

## 十八、最终交付要求

必须交付完整的可运行项目，包括：

- Rust 源代码。
- Cargo.toml 和 Cargo.lock。
- Protobuf 文件。
- JSON Schema。
- ClickHouse DDL。
- Kafka Topic 初始化脚本。
- Docker Compose。
- Grafana Dashboard。
- REST API 文档。
- gRPC API 文档。
- 完整配置示例。
- 自动化测试代码。
- 性能测试程序。
- README.md。
- 架构设计文档。
- 部署运维手册。
- 业务服务接入示例。

## 十九、重要开发约束

1. 不允许只生成架构图和空接口。
2. 不允许用伪代码代替实际实现。
3. 不允许让 gRPC 接收日志后直接写 ClickHouse。
4. 不允许 HTTP 接口承担日志投递功能。
5. 不允许 Kafka 和 gRPC 使用不同的日志数据结构。
6. 不允许每条日志单独写入 ClickHouse。
7. 不允许无上限缓存消息。
8. 不允许因 ClickHouse 临时异常而直接丢弃日志。
9. 不允许无限创建 ClickHouse 索引和分区。
10. 不允许把大批日志读入 Rust 内存进行统计。
11. 不允许在代码中硬编码敏感配置。
12. 不允许声称实现了 Exactly-once，除非有经过验证的端到端机制及相应证明。
13. 不允许忽略多租户数据隔离。
14. 不允许忽略 Kafka Offset 和重复消费问题。
15. 不要引入 Data Prepper、Logstash 等重复处理组件。
16. 不要为了微服务架构而引入不必要的服务。
17. 不得编造 Rust Crate API、ClickHouse SQL 参数或配置项，必须以当前版本官方文档为准。
18. 每完成一个阶段都必须检查代码能否正常构建、启动和测试。
19. 遇到技术方案不确定时，先查阅官方文档，再做实现。
20. 最终必须保证 Kafka、gRPC、Rust Worker、ClickHouse 形成完整可验证的日志处理链路。

最终目标：

建设一个采用 Rust + Axum + Tonic + Kafka + ClickHouse 的独立日志中心，所有业务服务可以通过 Kafka 或 gRPC 统一投递日志，服务统一完成日志存储、查询、全文检索、统计分析和管理，为未来整个互联网基础设施平台提供通用日志能力。