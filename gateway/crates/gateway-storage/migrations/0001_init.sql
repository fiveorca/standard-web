-- ======================================================================
-- 0001_init.sql —— 控制面初始 Schema
-- ----------------------------------------------------------------------
-- 设计原则（见需求文档第十章）：
--   1. 所有表都有明确主键
--   2. 资源表采用 "关键列 + JSONB 载荷" 混合模型
--   3. 时间字段统一 TIMESTAMPTZ（UTC）
--   4. 高频查询字段（id / enabled / updated_at / version）建立索引
--   5. 配置版本、实例应用记录、审计日志分开存放
--   6. 敏感信息（API Key / 密码）只保存摘要或掩码，不落明文
--
-- 注意：本迁移只负责建表；资源初始化由控制面 API 写入。
-- ======================================================================

-- ----------------------------------------------------------------------
-- 资源表（统一结构）
-- ----------------------------------------------------------------------
-- 每个资源表包含：
--   id          业务主键（字符串，由管理员指定）
--   name        人类可读名称
--   enabled     是否启用
--   version     资源版本号（乐观锁）
--   payload     完整领域对象（与 YAML schema 一致）
--   created_at / updated_at
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS services (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_services_enabled ON services (enabled);
CREATE INDEX IF NOT EXISTS idx_services_updated_at ON services (updated_at DESC);

CREATE TABLE IF NOT EXISTS upstreams (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_upstreams_enabled ON upstreams (enabled);
CREATE INDEX IF NOT EXISTS idx_upstreams_updated_at ON upstreams (updated_at DESC);

CREATE TABLE IF NOT EXISTS upstream_endpoints (
    id          TEXT PRIMARY KEY,
    upstream_id TEXT NOT NULL REFERENCES upstreams (id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    weight      INTEGER NOT NULL DEFAULT 1,
    zone        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_upstream_endpoints_upstream ON upstream_endpoints (upstream_id);

CREATE TABLE IF NOT EXISTS routes (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes (enabled);
CREATE INDEX IF NOT EXISTS idx_routes_updated_at ON routes (updated_at DESC);

CREATE TABLE IF NOT EXISTS consumers (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_consumers_enabled ON consumers (enabled);

CREATE TABLE IF NOT EXISTS consumer_credentials (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_consumer_credentials_enabled ON consumer_credentials (enabled);

-- ----------------------------------------------------------------------
-- 策略表
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_policies_enabled ON auth_policies (enabled);

CREATE TABLE IF NOT EXISTS rate_limit_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_policies_enabled ON rate_limit_policies (enabled);

CREATE TABLE IF NOT EXISTS retry_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_retry_policies_enabled ON retry_policies (enabled);

CREATE TABLE IF NOT EXISTS circuit_breaker_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_circuit_breaker_policies_enabled ON circuit_breaker_policies (enabled);

CREATE TABLE IF NOT EXISTS timeout_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_timeout_policies_enabled ON timeout_policies (enabled);

CREATE TABLE IF NOT EXISTS cors_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cors_policies_enabled ON cors_policies (enabled);

CREATE TABLE IF NOT EXISTS request_transform_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_request_transform_policies_enabled
    ON request_transform_policies (enabled);

CREATE TABLE IF NOT EXISTS response_transform_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_response_transform_policies_enabled
    ON response_transform_policies (enabled);

-- ----------------------------------------------------------------------
-- 插件表
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS plugins (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_plugins_enabled ON plugins (enabled);

CREATE TABLE IF NOT EXISTS plugin_configs (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_plugin_configs_enabled ON plugin_configs (enabled);

-- ----------------------------------------------------------------------
-- 配置版本
-- ----------------------------------------------------------------------
-- snapshot 保存"发布那一刻"编译后的完整资源集合（canonical JSON）。
-- 回滚 = 读取历史 snapshot 并作为新版本重新发布，版本号单调递增。
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_versions (
    version         BIGINT PRIMARY KEY,
    checksum        TEXT NOT NULL,
    schema_version  TEXT NOT NULL,
    status          TEXT NOT NULL,
    snapshot        JSONB NOT NULL,
    created_by      TEXT NOT NULL,
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_config_versions_created_at
    ON config_versions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_versions_status
    ON config_versions (status);

-- ----------------------------------------------------------------------
-- 实例应用记录（与配置版本分开记录）
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_publish_records (
    id           TEXT PRIMARY KEY,
    version      BIGINT NOT NULL REFERENCES config_versions (version) ON DELETE CASCADE,
    checksum     TEXT NOT NULL,
    status       TEXT NOT NULL,
    instance_id  TEXT NOT NULL,
    message      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_config_publish_records_version
    ON config_publish_records (version);
CREATE INDEX IF NOT EXISTS idx_config_publish_records_created_at
    ON config_publish_records (created_at DESC);

-- ----------------------------------------------------------------------
-- 审计日志
-- ----------------------------------------------------------------------
-- detail 只保存变更摘要；禁止写入密钥、密码、Token 明文。
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id             TEXT PRIMARY KEY,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource_kind  TEXT,
    resource_id    TEXT,
    version        BIGINT,
    detail         TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_version ON audit_logs (version);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
