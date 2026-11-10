-- 通用文件系统服务初始数据库结构
-- PostgreSQL 14+

-- 存储提供者配置。Access Key / Secret Key 只保存 AES-GCM 密文，禁止明文。
CREATE TABLE IF NOT EXISTS storage_provider (
    id                  UUID PRIMARY KEY,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    type                TEXT NOT NULL CHECK (type IN ('LOCAL', 'S3', 'OSS')),
    endpoint            TEXT,
    region              TEXT,
    bucket              TEXT,
    root_path           TEXT,
    access_key_cipher   TEXT,
    secret_key_cipher   TEXT,
    access_key_env      TEXT,
    secret_key_env      TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    is_default          BOOLEAN NOT NULL DEFAULT FALSE,
    allow_upload        BOOLEAN NOT NULL DEFAULT TRUE,
    allow_download      BOOLEAN NOT NULL DEFAULT TRUE,
    allow_delete        BOOLEAN NOT NULL DEFAULT TRUE,
    options             JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_health_status  TEXT,
    last_health_message TEXT,
    last_checked_at     TIMESTAMPTZ,
    version             INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS storage_provider_code_uq ON storage_provider (lower(code));
CREATE UNIQUE INDEX IF NOT EXISTS storage_provider_default_uq ON storage_provider (is_default) WHERE is_default;
CREATE INDEX IF NOT EXISTS storage_provider_enabled_idx ON storage_provider (enabled, type);

-- 物理文件对象。同一存储提供者内按 SHA-256 去重。
CREATE TABLE IF NOT EXISTS file_object (
    id                  UUID PRIMARY KEY,
    storage_provider_id UUID NOT NULL REFERENCES storage_provider(id),
    object_key          TEXT NOT NULL,
    temp_key            TEXT,
    sha256              TEXT,
    file_size           BIGINT NOT NULL DEFAULT 0,
    mime_type           TEXT,
    extension           TEXT,
    etag                TEXT,
    status              TEXT NOT NULL DEFAULT 'PENDING_UPLOAD'
                        CHECK (status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED', 'MIGRATING', 'ACTIVE',
                                          'PENDING_DELETE', 'DELETED', 'FAILED', 'QUARANTINED')),
    delete_after        TIMESTAMPTZ,
    delete_attempts     INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    verified_at         TIMESTAMPTZ,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT file_object_sha_len CHECK (sha256 IS NULL OR length(sha256) = 64)
);
CREATE UNIQUE INDEX IF NOT EXISTS file_object_key_uq ON file_object (storage_provider_id, object_key);
CREATE UNIQUE INDEX IF NOT EXISTS file_object_sha_uq
    ON file_object (storage_provider_id, sha256)
    WHERE sha256 IS NOT NULL AND status IN ('ACTIVE', 'MIGRATING', 'PENDING_DELETE');
CREATE INDEX IF NOT EXISTS file_object_status_idx ON file_object (status, updated_at);
CREATE INDEX IF NOT EXISTS file_object_delete_idx ON file_object (status, delete_after);
CREATE INDEX IF NOT EXISTS file_object_provider_active_idx ON file_object (storage_provider_id, status, file_size);

-- 业务文件记录。多个记录可引用同一个物理文件对象。
CREATE TABLE IF NOT EXISTS file_record (
    id                  UUID PRIMARY KEY,
    file_object_id      UUID REFERENCES file_object(id),
    storage_provider_id UUID NOT NULL REFERENCES storage_provider(id),
    original_filename   TEXT NOT NULL,
    display_name        TEXT,
    file_size           BIGINT NOT NULL DEFAULT 0,
    mime_type           TEXT,
    extension           TEXT,
    source_type         TEXT NOT NULL,
    source_id           TEXT,
    business_id         TEXT,
    creator             TEXT,
    tenant_id           UUID,
    status              TEXT NOT NULL DEFAULT 'PENDING_UPLOAD'
                        CHECK (status IN ('PENDING_UPLOAD', 'ACTIVE', 'DELETED', 'EXPIRED', 'FAILED', 'QUARANTINED')),
    sha256              TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT file_record_sha_len CHECK (sha256 IS NULL OR length(sha256) = 64)
);
CREATE INDEX IF NOT EXISTS file_record_object_idx ON file_record (file_object_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS file_record_source_idx ON file_record (source_type, source_id, created_at DESC);
CREATE INDEX IF NOT EXISTS file_record_business_idx ON file_record (business_id, created_at DESC) WHERE business_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS file_record_tenant_idx ON file_record (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS file_record_status_idx ON file_record (status, created_at DESC);
CREATE INDEX IF NOT EXISTS file_record_creator_idx ON file_record (creator, created_at DESC) WHERE creator IS NOT NULL;

-- 上传任务：服务端上传、分片上传、客户端直传、客户端分片直传。
CREATE TABLE IF NOT EXISTS upload_session (
    id                  UUID PRIMARY KEY,
    file_id             UUID NOT NULL REFERENCES file_record(id),
    file_object_id      UUID NOT NULL REFERENCES file_object(id),
    storage_provider_id UUID NOT NULL REFERENCES storage_provider(id),
    mode                TEXT NOT NULL CHECK (mode IN ('SERVER', 'MULTIPART', 'DIRECT', 'DIRECT_MULTIPART')),
    status              TEXT NOT NULL DEFAULT 'CREATED'
                        CHECK (status IN ('CREATED', 'UPLOADING', 'UPLOADED', 'CONFIRMING', 'CONFIRMED',
                                          'EXPIRED', 'CANCELLED', 'FAILED')),
    object_key          TEXT NOT NULL,
    temp_key            TEXT NOT NULL,
    multipart_id        TEXT,
    expected_size       BIGINT,
    received_size       BIGINT NOT NULL DEFAULT 0,
    sha256              TEXT,
    parts_total         INTEGER,
    parts_completed     INTEGER NOT NULL DEFAULT 0,
    idempotency_key     TEXT,
    expires_at          TIMESTAMPTZ NOT NULL,
    confirmed_at        TIMESTAMPTZ,
    cancelled_at        TIMESTAMPTZ,
    error_message       TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT upload_session_sha_len CHECK (sha256 IS NULL OR length(sha256) = 64)
);
CREATE UNIQUE INDEX IF NOT EXISTS upload_session_idem_uq
    ON upload_session (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS upload_session_expiry_idx ON upload_session (status, expires_at);
CREATE INDEX IF NOT EXISTS upload_session_file_idx ON upload_session (file_id);
CREATE INDEX IF NOT EXISTS upload_session_stale_idx ON upload_session (status, updated_at);

-- 服务端分片上传的分片元数据。
CREATE TABLE IF NOT EXISTS upload_part (
    upload_id           UUID NOT NULL REFERENCES upload_session(id) ON DELETE CASCADE,
    part_number         INTEGER NOT NULL,
    file_size           BIGINT NOT NULL DEFAULT 0,
    etag                TEXT,
    sha256              TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_number)
);

-- 文件来源字典，仅用于登记和统计，来源标识本身保持可扩展。
CREATE TABLE IF NOT EXISTS file_source (
    id                  UUID PRIMARY KEY,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS file_source_code_uq ON file_source (lower(code));

-- 存储操作审计日志。
CREATE TABLE IF NOT EXISTS storage_operation_log (
    id                  UUID PRIMARY KEY,
    operation           TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'SKIPPED')),
    storage_provider_id UUID,
    file_object_id      UUID,
    file_id             UUID,
    upload_id           UUID,
    object_key          TEXT,
    bytes               BIGINT,
    duration_ms         BIGINT,
    trace_id            TEXT,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS storage_operation_log_created_idx ON storage_operation_log (created_at DESC);
CREATE INDEX IF NOT EXISTS storage_operation_log_file_idx ON storage_operation_log (file_id, created_at DESC);
CREATE INDEX IF NOT EXISTS storage_operation_log_op_idx ON storage_operation_log (operation, created_at DESC);

-- 清理任务与执行结果。
CREATE TABLE IF NOT EXISTS file_cleanup_task (
    id                  UUID PRIMARY KEY,
    type                TEXT NOT NULL CHECK (type IN ('ORPHAN_SCAN', 'PHYSICAL_DELETE', 'CONSISTENCY_CHECK',
                                                      'UPLOAD_EXPIRY', 'MANUAL_CLEANUP')),
    status              TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    dry_run             BOOLEAN NOT NULL DEFAULT FALSE,
    storage_provider_id UUID,
    scanned             INTEGER NOT NULL DEFAULT 0,
    deleted             INTEGER NOT NULL DEFAULT 0,
    repaired            INTEGER NOT NULL DEFAULT 0,
    failed              INTEGER NOT NULL DEFAULT 0,
    details             JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message       TEXT,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS file_cleanup_task_created_idx ON file_cleanup_task (created_at DESC);
CREATE INDEX IF NOT EXISTS file_cleanup_task_type_idx ON file_cleanup_task (type, status, created_at DESC);

-- 分布式任务互斥锁。
CREATE TABLE IF NOT EXISTS job_lock (
    name                TEXT PRIMARY KEY,
    owner               TEXT NOT NULL,
    locked_until        TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
