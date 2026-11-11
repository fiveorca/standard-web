-- IM 通信服务初始数据库结构
-- PostgreSQL 14+

-- ---------------------------------------------------------------------------
-- MQTT
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS mqtt_broker (
    id                       UUID PRIMARY KEY,
    code                     TEXT NOT NULL,
    name                     TEXT NOT NULL,
    broker_type              TEXT NOT NULL DEFAULT 'EMQX' CHECK (broker_type IN ('EMQX', 'GENERIC')),
    host                     TEXT NOT NULL,
    tcp_port                 INTEGER NOT NULL DEFAULT 1883,
    tls_port                 INTEGER,
    protocol_version         TEXT NOT NULL DEFAULT '5.0',
    tls_enabled              BOOLEAN NOT NULL DEFAULT FALSE,
    username                 TEXT,
    password_cipher          TEXT,
    client_id_prefix         TEXT,
    keep_alive_seconds       INTEGER NOT NULL DEFAULT 60,
    clean_start              BOOLEAN NOT NULL DEFAULT TRUE,
    session_expiry_seconds   BIGINT NOT NULL DEFAULT 0,
    connect_timeout_seconds  INTEGER NOT NULL DEFAULT 10,
    reconnect_delay_seconds  INTEGER NOT NULL DEFAULT 5,
    max_inflight             INTEGER NOT NULL DEFAULT 100,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    is_default               BOOLEAN NOT NULL DEFAULT FALSE,
    status                   TEXT NOT NULL DEFAULT 'UNKNOWN'
                             CHECK (status IN ('UNKNOWN', 'CONNECTED', 'DISCONNECTED', 'ERROR')),
    status_message           TEXT,
    last_connected_at        TIMESTAMPTZ,
    last_checked_at          TIMESTAMPTZ,
    reconnect_count          BIGINT NOT NULL DEFAULT 0,
    options_json             TEXT NOT NULL DEFAULT '{}',
    version                  INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_broker_code_uq ON mqtt_broker (lower(code));
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_broker_default_uq ON mqtt_broker (is_default) WHERE is_default;
CREATE INDEX IF NOT EXISTS mqtt_broker_enabled_idx ON mqtt_broker (enabled, status);

CREATE TABLE IF NOT EXISTS mqtt_access_config (
    id                                UUID PRIMARY KEY,
    tenant_id                         UUID,
    broker_id                         UUID NOT NULL REFERENCES mqtt_broker(id),
    code                              TEXT NOT NULL,
    name                              TEXT NOT NULL,
    enabled                           BOOLEAN NOT NULL DEFAULT TRUE,
    is_default                        BOOLEAN NOT NULL DEFAULT FALSE,
    protocol_version                  TEXT NOT NULL DEFAULT '5.0',
    default_qos                       INTEGER NOT NULL DEFAULT 1 CHECK (default_qos BETWEEN 0 AND 2),
    keep_alive_seconds                INTEGER NOT NULL DEFAULT 60,
    clean_start                       BOOLEAN NOT NULL DEFAULT TRUE,
    session_expiry_seconds            BIGINT NOT NULL DEFAULT 0,
    message_expiry_interval_seconds   BIGINT NOT NULL DEFAULT 0,
    retain_default                    BOOLEAN NOT NULL DEFAULT FALSE,
    publish_topic_template            TEXT NOT NULL DEFAULT 'devices/{deviceId}/up',
    subscribe_topic_template          TEXT NOT NULL DEFAULT 'devices/{deviceId}/down',
    service_topic_prefix              TEXT NOT NULL DEFAULT 'tenants/',
    tls_enabled                       BOOLEAN NOT NULL DEFAULT FALSE,
    auth_mode                         TEXT NOT NULL DEFAULT 'CREDENTIAL'
                                      CHECK (auth_mode IN ('CREDENTIAL', 'PLATFORM_JWT')),
    config_version                    INTEGER NOT NULL DEFAULT 1,
    metadata_json                     TEXT NOT NULL DEFAULT '{}',
    deleted                           BOOLEAN NOT NULL DEFAULT FALSE,
    version                           INTEGER NOT NULL DEFAULT 0,
    created_at                        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_access_config_code_uq
    ON mqtt_access_config (lower(code)) WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_access_config_default_uq
    ON mqtt_access_config (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE is_default AND NOT deleted;
CREATE INDEX IF NOT EXISTS mqtt_access_config_tenant_idx ON mqtt_access_config (tenant_id) WHERE NOT deleted;
CREATE INDEX IF NOT EXISTS mqtt_access_config_broker_idx ON mqtt_access_config (broker_id) WHERE NOT deleted;

CREATE TABLE IF NOT EXISTS mqtt_device_credential (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID,
    device_id           TEXT NOT NULL,
    access_config_id    UUID NOT NULL REFERENCES mqtt_access_config(id),
    broker_id           UUID NOT NULL REFERENCES mqtt_broker(id),
    username            TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    password_cipher     TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED', 'EXPIRED')),
    config_version      INTEGER NOT NULL DEFAULT 1,
    expires_at          TIMESTAMPTZ,
    last_auth_at        TIMESTAMPTZ,
    rotated_at          TIMESTAMPTZ,
    disabled_reason     TEXT,
    deleted             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_device_username_uq
    ON mqtt_device_credential (username) WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_device_tenant_device_uq
    ON mqtt_device_credential (tenant_id, device_id) WHERE NOT deleted AND tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_device_global_device_uq
    ON mqtt_device_credential (device_id) WHERE NOT deleted AND tenant_id IS NULL;
CREATE INDEX IF NOT EXISTS mqtt_device_config_idx ON mqtt_device_credential (access_config_id) WHERE NOT deleted;
CREATE INDEX IF NOT EXISTS mqtt_device_status_idx ON mqtt_device_credential (status, expires_at) WHERE NOT deleted;

CREATE TABLE IF NOT EXISTS mqtt_topic_acl (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID,
    access_config_id    UUID NOT NULL REFERENCES mqtt_access_config(id) ON DELETE CASCADE,
    subject_type        TEXT NOT NULL CHECK (subject_type IN ('DEVICE', 'SERVICE')),
    subject_id          TEXT NOT NULL,
    topic_pattern       TEXT NOT NULL,
    action              TEXT NOT NULL CHECK (action IN ('PUBLISH', 'SUBSCRIBE')),
    effect              TEXT NOT NULL DEFAULT 'ALLOW' CHECK (effect IN ('ALLOW', 'DENY')),
    qos_max             INTEGER NOT NULL DEFAULT 2 CHECK (qos_max BETWEEN 0 AND 2),
    priority            INTEGER NOT NULL DEFAULT 0,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mqtt_topic_acl_subject_idx
    ON mqtt_topic_acl (access_config_id, subject_type, subject_id, action) WHERE enabled;

CREATE TABLE IF NOT EXISTS mqtt_publish_record (
    id                              UUID PRIMARY KEY,
    tenant_id                       UUID,
    message_id                      TEXT NOT NULL,
    device_id                       TEXT,
    topic                           TEXT NOT NULL,
    content_type                    TEXT,
    payload_hash                    TEXT NOT NULL,
    payload_size                    INTEGER NOT NULL DEFAULT 0,
    qos                             INTEGER NOT NULL DEFAULT 1 CHECK (qos BETWEEN 0 AND 2),
    retained                        BOOLEAN NOT NULL DEFAULT FALSE,
    message_expiry_interval_seconds BIGINT NOT NULL DEFAULT 0,
    status                          TEXT NOT NULL DEFAULT 'PENDING'
                                    CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
    broker_id                       UUID REFERENCES mqtt_broker(id),
    error_code                      TEXT,
    error_message                   TEXT,
    trace_id                        TEXT,
    source                          TEXT NOT NULL DEFAULT 'GRPC',
    published_at                    TIMESTAMPTZ,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_publish_message_uq
    ON mqtt_publish_record (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), message_id);
CREATE INDEX IF NOT EXISTS mqtt_publish_tenant_idx ON mqtt_publish_record (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS mqtt_publish_device_idx ON mqtt_publish_record (tenant_id, device_id, created_at DESC)
    WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS mqtt_publish_status_idx ON mqtt_publish_record (status, created_at DESC);

-- ---------------------------------------------------------------------------
-- Email
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS email_sender (
    id                UUID PRIMARY KEY,
    tenant_id         UUID,
    code              TEXT NOT NULL,
    name              TEXT NOT NULL,
    from_address      TEXT NOT NULL,
    from_name         TEXT,
    provider_type     TEXT NOT NULL DEFAULT 'SMTP' CHECK (provider_type IN ('SMTP')),
    is_default        BOOLEAN NOT NULL DEFAULT FALSE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    rate_per_minute   INTEGER NOT NULL DEFAULT 60,
    rate_per_day      INTEGER NOT NULL DEFAULT 5000,
    deleted           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS email_sender_code_uq ON email_sender (lower(code)) WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS email_sender_default_uq
    ON email_sender (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE is_default AND NOT deleted;
CREATE INDEX IF NOT EXISTS email_sender_tenant_idx ON email_sender (tenant_id) WHERE NOT deleted;

CREATE TABLE IF NOT EXISTS email_sender_config (
    id                      UUID PRIMARY KEY,
    sender_id               UUID NOT NULL REFERENCES email_sender(id) ON DELETE CASCADE,
    smtp_host               TEXT NOT NULL,
    smtp_port               INTEGER NOT NULL DEFAULT 587,
    smtp_username           TEXT,
    smtp_password_cipher    TEXT,
    smtp_auth               BOOLEAN NOT NULL DEFAULT TRUE,
    ssl_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    starttls_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    connection_timeout_ms   INTEGER NOT NULL DEFAULT 10000,
    read_timeout_ms         INTEGER NOT NULL DEFAULT 30000,
    write_timeout_ms        INTEGER NOT NULL DEFAULT 30000,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS email_sender_config_sender_uq ON email_sender_config (sender_id);

CREATE TABLE IF NOT EXISTS email_task (
    id                   UUID PRIMARY KEY,
    tenant_id            UUID,
    request_id           TEXT NOT NULL,
    sender_id            UUID NOT NULL REFERENCES email_sender(id),
    subject              TEXT,
    text_body            TEXT,
    html_body            TEXT,
    status               TEXT NOT NULL DEFAULT 'PENDING'
                         CHECK (status IN ('PENDING', 'PROCESSING', 'SUCCESS', 'RETRYING', 'FAILED')),
    attempt_count        INTEGER NOT NULL DEFAULT 0,
    max_attempts         INTEGER NOT NULL DEFAULT 5,
    next_retry_at        TIMESTAMPTZ,
    last_error_code      TEXT,
    last_error_message   TEXT,
    provider_message_id  TEXT,
    accepted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at           TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ,
    locked_by            TEXT,
    locked_at            TIMESTAMPTZ,
    trace_id             TEXT,
    payload_size         INTEGER NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS email_task_request_uq
    ON email_task (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), request_id);
CREATE INDEX IF NOT EXISTS email_task_queue_idx ON email_task (status, next_retry_at, created_at);
CREATE INDEX IF NOT EXISTS email_task_tenant_idx ON email_task (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS email_task_sender_idx ON email_task (sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS email_task_locked_idx ON email_task (status, locked_at);

CREATE TABLE IF NOT EXISTS email_recipient (
    id                UUID PRIMARY KEY,
    task_id           UUID NOT NULL REFERENCES email_task(id) ON DELETE CASCADE,
    recipient_type    TEXT NOT NULL CHECK (recipient_type IN ('TO', 'CC', 'BCC')),
    address           TEXT NOT NULL,
    display_name      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_recipient_task_idx ON email_recipient (task_id);

CREATE TABLE IF NOT EXISTS email_attachment (
    id                UUID PRIMARY KEY,
    task_id           UUID NOT NULL REFERENCES email_task(id) ON DELETE CASCADE,
    filename          TEXT NOT NULL,
    content_type      TEXT,
    file_size         BIGINT NOT NULL DEFAULT 0,
    storage_path      TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_attachment_task_idx ON email_attachment (task_id);

CREATE TABLE IF NOT EXISTS email_send_record (
    id                   UUID PRIMARY KEY,
    task_id              UUID NOT NULL REFERENCES email_task(id) ON DELETE CASCADE,
    sender_id            UUID NOT NULL,
    attempt              INTEGER NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED')),
    provider             TEXT NOT NULL,
    provider_message_id  TEXT,
    error_code           TEXT,
    error_message        TEXT,
    duration_ms          BIGINT NOT NULL DEFAULT 0,
    response_detail      TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_send_record_task_idx ON email_send_record (task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS email_send_record_sender_idx ON email_send_record (sender_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 通用
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS operation_audit_log (
    id                UUID PRIMARY KEY,
    tenant_id         UUID,
    actor             TEXT,
    actor_type        TEXT,
    action            TEXT NOT NULL,
    resource_type     TEXT,
    resource_id       TEXT,
    method            TEXT,
    path              TEXT,
    status            INTEGER,
    ip_address        TEXT,
    user_agent        TEXT,
    trace_id          TEXT,
    duration_ms       BIGINT,
    detail_json       TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS operation_audit_created_idx ON operation_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS operation_audit_tenant_idx ON operation_audit_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS operation_audit_action_idx ON operation_audit_log (action, created_at DESC);
