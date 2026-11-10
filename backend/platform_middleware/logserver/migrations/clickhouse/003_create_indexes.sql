-- 003: 创建跳数索引
-- 根据实际查询场景启用
-- ClickHouse 26.2+ 支持生产级 Text Index

-- message 全文索引 (使用 tokenbf_v1 或 ngrambf_v1 做快速过滤)
-- 注意：Text Index 需要 ClickHouse 26.2+，默认使用 bloom filter 索引
ALTER TABLE log_center.logs ADD INDEX IF NOT EXISTS idx_message_bloom message TYPE bloom_filter GRANULARITY 4;

-- trace_id bloom filter 索引
ALTER TABLE log_center.logs ADD INDEX IF NOT EXISTS idx_trace_id_bloom trace_id TYPE bloom_filter GRANULARITY 4;

-- request_id bloom filter 索引
ALTER TABLE log_center.logs ADD INDEX IF NOT EXISTS idx_request_id_bloom request_id TYPE bloom_filter GRANULARITY 4;

-- exception_type bloom filter 索引
ALTER TABLE log_center.logs ADD INDEX IF NOT EXISTS idx_exception_type_bloom exception_type TYPE bloom_filter GRANULARITY 4;
