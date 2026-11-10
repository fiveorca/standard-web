-- 004: 死信队列表 (ClickHouse 侧存储格式错误或处理失败的消息)
CREATE TABLE IF NOT EXISTS log_center.dlq_logs
(
    event_id            Nullable(UUID)               COMMENT '原始event_id',
    original_payload    String                       COMMENT '原始消息JSON',
    error_reason        String                       COMMENT '失败原因',
    error_stage         String                       COMMENT '失败阶段: PARSE / VALIDATE / SCHEMA / KAFKA / CLICKHOUSE',
    failed_at           DateTime64(3, 'UTC')         COMMENT '失败时间',
    kafka_topic         String                       COMMENT '来源Topic',
    kafka_partition     Int32                        COMMENT '来源分区',
    kafka_offset        Int64                        COMMENT '来源Offset'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(failed_at)
ORDER BY (failed_at, error_stage);

-- 005: Grafana 只读用户
CREATE USER IF NOT EXISTS grafana_readonly IDENTIFIED BY '${GRAFANA_PASSWORD}';
GRANT SELECT ON log_center.* TO grafana_readonly;
