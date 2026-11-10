-- 002: 创建日志主表
-- 使用 ReplacingMergeTree(ingest_version) 实现最终去重
-- 注意：ReplacingMergeTree 去重是后台合并，不保证查询时实时生效
CREATE TABLE IF NOT EXISTS log_center.logs
(
    event_id            UUID                         COMMENT '日志唯一标识',
    schema_version      LowCardinality(String)        COMMENT '数据结构版本',
    log_time            DateTime64(3, 'UTC')         COMMENT '日志产生时间',
    ingest_time         DateTime64(3, 'UTC')         COMMENT '日志接收时间(服务端)',
    ingest_version      UInt64                       COMMENT '摄入版本(用于去重)',
    level               LowCardinality(String)        COMMENT '日志级别',
    service_name        LowCardinality(String)        COMMENT '服务名',
    service_version     LowCardinality(String)        COMMENT '服务版本',
    environment         LowCardinality(String)        COMMENT '环境',
    host_name           LowCardinality(String)        COMMENT '主机名',
    logger              String                       COMMENT 'Logger名称',
    thread_name         String                       COMMENT '线程名',
    message             String                       COMMENT '日志正文',
    trace_id            String                       COMMENT '链路追踪ID',
    span_id             String                       COMMENT 'Span ID',
    request_id          String                       COMMENT '请求ID',
    tenant_id           String                       COMMENT '租户ID',
    exception_type      String                       COMMENT '异常类型',
    exception_message   String                       COMMENT '异常消息',
    stack_trace         String                       COMMENT '堆栈',
    attributes_json     String                       COMMENT '扩展属性JSON',
    -- TTL: 默认保留 30 天
    TTL log_time + INTERVAL 30 DAY
)
ENGINE = ReplacingMergeTree(ingest_version)
PARTITION BY toYYYYMM(log_time)
ORDER BY (
    tenant_id,
    environment,
    service_name,
    toDate(log_time),
    log_time,
    event_id
)
PRIMARY KEY (
    tenant_id,
    environment,
    service_name,
    toDate(log_time)
)
SETTINGS
    index_granularity = 8192,
    merge_with_ttl_timeout = 14400,
    ttl_only_drop_parts = 0;
