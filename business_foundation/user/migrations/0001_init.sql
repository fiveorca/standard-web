-- 用户中心初始数据库结构
-- PostgreSQL 14+

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    username            TEXT NOT NULL,
    email               TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    phone               TEXT,
    phone_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    display_name        TEXT,
    avatar_url          TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('active', 'pending', 'disabled', 'locked', 'frozen',
                                          'deleting', 'deleted')),
    source              TEXT NOT NULL DEFAULT 'registration',
    remark              TEXT,
    last_active_at      TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_username_uq
    ON users (tenant_id, lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq
    ON users (lower(email)) WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_uq
    ON users (phone) WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_tenant_status_idx ON users (tenant_id, status);
CREATE INDEX IF NOT EXISTS users_created_idx ON users (created_at DESC);

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    gender              TEXT CHECK (gender IN ('male', 'female', 'other', 'undisclosed')),
    birthday            DATE,
    bio                 TEXT,
    region              TEXT,
    timezone            TEXT,
    locale              TEXT,
    website             TEXT,
    company             TEXT,
    job_title           TEXT,
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb,
    completeness        SMALLINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_attributes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    data_type           TEXT NOT NULL DEFAULT 'string'
                        CHECK (data_type IN ('string', 'number', 'boolean', 'date', 'enum', 'array')),
    required            BOOLEAN NOT NULL DEFAULT FALSE,
    default_value       JSONB,
    options             JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation          JSONB NOT NULL DEFAULT '{}'::jsonb,
    user_type           TEXT,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS user_attributes_code_uq
    ON user_attributes (tenant_id, lower(code)) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS user_attribute_values (
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attribute_id        UUID NOT NULL REFERENCES user_attributes(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    value               JSONB NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, attribute_id)
);

CREATE TABLE IF NOT EXISTS user_contacts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL CHECK (kind IN ('email', 'phone')),
    value               TEXT NOT NULL,
    normalized_value    TEXT NOT NULL,
    verified            BOOLEAN NOT NULL DEFAULT FALSE,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS user_contacts_value_uq
    ON user_contacts (kind, normalized_value);
CREATE INDEX IF NOT EXISTS user_contacts_user_idx ON user_contacts (user_id, kind);

CREATE TABLE IF NOT EXISTS user_groups (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    parent_id           UUID REFERENCES user_groups(id) ON DELETE SET NULL,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    path                TEXT NOT NULL DEFAULT '',
    level               INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    tags                JSONB NOT NULL DEFAULT '[]'::jsonb,
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS user_groups_code_uq
    ON user_groups (tenant_id, lower(code)) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS user_groups_parent_idx ON user_groups (tenant_id, parent_id);

CREATE TABLE IF NOT EXISTS user_group_members (
    group_id            UUID NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    joined_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS user_group_members_user_idx ON user_group_members (user_id);

CREATE TABLE IF NOT EXISTS organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    parent_id           UUID REFERENCES organizations(id) ON DELETE SET NULL,
    kind                TEXT NOT NULL DEFAULT 'company'
                        CHECK (kind IN ('company', 'department', 'team', 'other')),
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    path                TEXT NOT NULL DEFAULT '',
    level               INTEGER NOT NULL DEFAULT 0,
    leader_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_code_uq
    ON organizations (tenant_id, lower(code)) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS organizations_parent_idx ON organizations (tenant_id, parent_id);

CREATE TABLE IF NOT EXISTS departments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id           UUID REFERENCES departments(id) ON DELETE SET NULL,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    path                TEXT NOT NULL DEFAULT '',
    level               INTEGER NOT NULL DEFAULT 0,
    leader_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    extra               JSONB NOT NULL DEFAULT '{}'::jsonb,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS departments_code_uq
    ON departments (organization_id, lower(code)) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS departments_parent_idx ON departments (tenant_id, parent_id);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    title               TEXT,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at             TIMESTAMPTZ,
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS organization_members_user_idx ON organization_members (user_id);

CREATE TABLE IF NOT EXISTS department_members (
    department_id       UUID NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    title               TEXT,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at             TIMESTAMPTZ,
    PRIMARY KEY (department_id, user_id)
);
CREATE INDEX IF NOT EXISTS department_members_user_idx ON department_members (user_id);

CREATE TABLE IF NOT EXISTS user_organization_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id     UUID,
    department_id       UUID,
    action              TEXT NOT NULL CHECK (action IN ('join', 'leave', 'transfer', 'primary_changed')),
    operator_id         UUID,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_org_history_user_idx
    ON user_organization_history (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS user_account_links (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    provider_subject    TEXT NOT NULL,
    linked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ,
    UNIQUE (user_id, provider),
    UNIQUE (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS user_registration_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    username            TEXT NOT NULL,
    email               TEXT,
    phone               TEXT,
    source              TEXT NOT NULL DEFAULT 'web',
    channel             TEXT,
    campaign            TEXT,
    invite_code         TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'rejected', 'completed')),
    reviewer_id         UUID,
    reviewed_at         TIMESTAMPTZ,
    reject_reason       TEXT,
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_registration_status_idx
    ON user_registration_records (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS user_tags (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag                 TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, tag)
);
CREATE INDEX IF NOT EXISTS user_tags_tag_idx ON user_tags (tenant_id, tag);

CREATE TABLE IF NOT EXISTS user_status_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_status         TEXT,
    to_status           TEXT NOT NULL,
    reason              TEXT,
    operator_id         UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_status_history_user_idx
    ON user_status_history (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS user_audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    actor_id            UUID,
    action              TEXT NOT NULL,
    resource_type       TEXT,
    resource_id         TEXT,
    result              TEXT NOT NULL DEFAULT 'success',
    ip                  TEXT,
    user_agent          TEXT,
    trace_id            TEXT,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_audit_logs_tenant_idx
    ON user_audit_logs (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS outbox_events (
    id                  UUID PRIMARY KEY,
    event_type          TEXT NOT NULL,
    aggregate_type      TEXT NOT NULL,
    aggregate_id        TEXT NOT NULL,
    payload             JSONB NOT NULL,
    trace_id            TEXT,
    version             INTEGER NOT NULL DEFAULT 1,
    occurred_at         TIMESTAMPTZ NOT NULL,
    published_at        TIMESTAMPTZ,
    attempts            INTEGER NOT NULL DEFAULT 0,
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error          TEXT,
    dead_lettered_at    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
    ON outbox_events (next_attempt_at) WHERE published_at IS NULL AND dead_lettered_at IS NULL;

CREATE TABLE IF NOT EXISTS inbox_events (
    event_id            UUID NOT NULL,
    consumer            TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    aggregate_id        TEXT,
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    status              TEXT NOT NULL DEFAULT 'processed'
                        CHECK (status IN ('processed', 'failed')),
    error               TEXT,
    processed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, consumer)
);
