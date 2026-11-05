-- ======================================================================
-- 0002_platform.sql —— Phase 7 平台化资源
-- ----------------------------------------------------------------------
-- 新增资源表沿用 0001_init.sql 的统一结构（关键列 + JSONB 载荷），
-- 便于控制面通用 CRUD 直接复用。
--
-- 新增资源：
--   tenants      租户（多租户隔离）
--   certificates TLS 证书（PEM 文本）
--   api_specs    OpenAPI 规范文档（导入源）
--   waf_policies WAF 策略
--   quota_policies 配额策略
--   clusters     集群 / 多地域描述
-- ======================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tenants_enabled ON tenants (enabled);

CREATE TABLE IF NOT EXISTS certificates (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_certificates_enabled ON certificates (enabled);

CREATE TABLE IF NOT EXISTS api_specs (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_specs_enabled ON api_specs (enabled);

CREATE TABLE IF NOT EXISTS waf_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_waf_policies_enabled ON waf_policies (enabled);

CREATE TABLE IF NOT EXISTS quota_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_quota_policies_enabled ON quota_policies (enabled);

CREATE TABLE IF NOT EXISTS clusters (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    version     BIGINT NOT NULL DEFAULT 1,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_clusters_enabled ON clusters (enabled);
