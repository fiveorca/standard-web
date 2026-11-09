-- 认证授权中心初始数据库结构
-- PostgreSQL 14+

CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS tenants_code_uq ON tenants (lower(code)) WHERE deleted_at IS NULL;

INSERT INTO tenants (id, code, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS identities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    username            TEXT NOT NULL,
    email               TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    phone               TEXT,
    phone_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    display_name        TEXT,
    avatar_url          TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'active', 'disabled', 'locked', 'deleting', 'deleted')),
    status_reason       TEXT,
    mfa_enforced        BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       TEXT,
    password_updated_at TIMESTAMPTZ,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    version             INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS identities_tenant_username_uq
    ON identities (tenant_id, lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS identities_email_uq
    ON identities (lower(email)) WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS identities_phone_uq
    ON identities (phone) WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS identities_tenant_status_idx ON identities (tenant_id, status);
CREATE INDEX IF NOT EXISTS identities_created_idx ON identities (created_at DESC);

CREATE TABLE IF NOT EXISTS identity_identifiers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    kind                TEXT NOT NULL CHECK (kind IN ('username', 'email', 'phone')),
    value               TEXT NOT NULL,
    normalized_value    TEXT NOT NULL,
    verified_at         TIMESTAMPTZ,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_identifiers_value_uq
    ON identity_identifiers (kind, normalized_value);
CREATE INDEX IF NOT EXISTS identity_identifiers_identity_idx ON identity_identifiers (identity_id);

CREATE TABLE IF NOT EXISTS identity_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type     TEXT NOT NULL CHECK (credential_type IN ('password')),
    secret_hash         TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_credentials_type_uq
    ON identity_credentials (identity_id, credential_type);

CREATE TABLE IF NOT EXISTS password_history (
    id                  BIGSERIAL PRIMARY KEY,
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    password_hash       TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_history_identity_idx ON password_history (identity_id, created_at DESC);

CREATE TABLE IF NOT EXISTS verification_codes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    identity_id         UUID REFERENCES identities(id) ON DELETE CASCADE,
    purpose             TEXT NOT NULL
                        CHECK (purpose IN ('login', 'register', 'reset_password', 'verify_email', 'verify_phone',
                                           'change_email', 'change_phone', 'mfa_reset', 'high_risk')),
    channel             TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    target              TEXT NOT NULL,
    code_hash           TEXT NOT NULL,
    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 5,
    consumed_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS verification_codes_lookup_idx
    ON verification_codes (purpose, channel, target, created_at DESC);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    client_id           TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    ip                  TEXT,
    user_agent          TEXT,
    device_id           TEXT,
    device_name         TEXT,
    amr                 JSONB NOT NULL DEFAULT '["pwd"]'::jsonb,
    acr                 TEXT NOT NULL DEFAULT 'urn:auth:acr:pwd',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT
);
CREATE INDEX IF NOT EXISTS auth_sessions_identity_idx ON auth_sessions (identity_id, status);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_idx ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    client_id           TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    family_id           UUID NOT NULL,
    previous_id         UUID REFERENCES refresh_tokens(id),
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'rotated', 'revoked', 'expired')),
    scope               TEXT NOT NULL DEFAULT '',
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    rotated_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    ip                  TEXT,
    user_agent          TEXT
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_identity_idx ON refresh_tokens (identity_id, status);

CREATE TABLE IF NOT EXISTS authorization_codes (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash               TEXT NOT NULL UNIQUE,
    client_id               TEXT NOT NULL,
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    identity_id             UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    session_id              UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    redirect_uri            TEXT NOT NULL,
    scope                   TEXT NOT NULL,
    nonce                   TEXT,
    state                   TEXT,
    code_challenge          TEXT,
    code_challenge_method   TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
    auth_time               TIMESTAMPTZ NOT NULL DEFAULT now(),
    amr                     JSONB NOT NULL DEFAULT '["pwd"]'::jsonb,
    acr                     TEXT NOT NULL DEFAULT 'urn:auth:acr:pwd',
    consumed_at             TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS authorization_codes_client_idx ON authorization_codes (client_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   UUID NOT NULL REFERENCES tenants(id),
    client_id                   TEXT NOT NULL UNIQUE,
    client_secret_hash          TEXT,
    name                        TEXT NOT NULL,
    description                 TEXT,
    kind                        TEXT NOT NULL DEFAULT 'confidential'
                                CHECK (kind IN ('confidential', 'public')),
    redirect_uris               JSONB NOT NULL DEFAULT '[]'::jsonb,
    post_logout_redirect_uris   JSONB NOT NULL DEFAULT '[]'::jsonb,
    grant_types                 JSONB NOT NULL DEFAULT '["authorization_code"]'::jsonb,
    scopes                      JSONB NOT NULL DEFAULT '[]'::jsonb,
    status                      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    require_pkce                BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_ttl_secs       INTEGER,
    refresh_token_ttl_secs      INTEGER,
    id_token_ttl_secs           INTEGER,
    metadata                    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_clients_tenant_idx ON oauth_clients (tenant_id);

CREATE TABLE IF NOT EXISTS oauth_scopes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    description         TEXT,
    is_default          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_scopes_tenant_name_uq ON oauth_scopes (tenant_id, name);

INSERT INTO oauth_scopes (tenant_id, name, description, is_default) VALUES
    ('00000000-0000-0000-0000-000000000001', 'openid', 'OpenID Connect subject identifier', TRUE),
    ('00000000-0000-0000-0000-000000000001', 'profile', 'Basic profile claims', TRUE),
    ('00000000-0000-0000-0000-000000000001', 'email', 'Email claims', TRUE),
    ('00000000-0000-0000-0000-000000000001', 'phone', 'Phone claims', FALSE),
    ('00000000-0000-0000-0000-000000000001', 'offline_access', 'Issue refresh tokens', TRUE),
    ('00000000-0000-0000-0000-000000000001', 'internal', 'Internal service APIs', FALSE)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS oauth_consents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    scopes              JSONB NOT NULL DEFAULT '[]'::jsonb,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_consents_uq
    ON oauth_consents (identity_id, client_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS identity_providers (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   UUID NOT NULL REFERENCES tenants(id),
    code                        TEXT NOT NULL,
    name                        TEXT NOT NULL,
    kind                        TEXT NOT NULL CHECK (kind IN ('oidc', 'oauth2', 'github', 'apple', 'saml')),
    enabled                     BOOLEAN NOT NULL DEFAULT TRUE,
    issuer                      TEXT,
    authorization_endpoint      TEXT,
    token_endpoint              TEXT,
    userinfo_endpoint           TEXT,
    jwks_uri                    TEXT,
    client_id                   TEXT,
    client_secret_encrypted     TEXT,
    private_key_encrypted       TEXT,
    redirect_uri                TEXT,
    scopes                      JSONB NOT NULL DEFAULT '[]'::jsonb,
    attribute_mapping           JSONB NOT NULL DEFAULT '{}'::jsonb,
    auto_register               BOOLEAN NOT NULL DEFAULT FALSE,
    link_by_verified_email      BOOLEAN NOT NULL DEFAULT FALSE,
    config                      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_providers_tenant_code_uq ON identity_providers (tenant_id, code);

CREATE TABLE IF NOT EXISTS external_identities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    provider_id         UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    provider_code       TEXT NOT NULL,
    subject             TEXT NOT NULL,
    email               TEXT,
    display_name        TEXT,
    raw                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    linked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS external_identities_subject_uq
    ON external_identities (provider_id, subject);
CREATE INDEX IF NOT EXISTS external_identities_identity_idx ON external_identities (identity_id);

CREATE TABLE IF NOT EXISTS mfa_factors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    name                TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    secret_encrypted    TEXT,
    credential          JSONB,
    sign_count          BIGINT NOT NULL DEFAULT 0,
    last_used_step      BIGINT,
    verified_at         TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mfa_factors_name_uq ON mfa_factors (identity_id, kind, name);
CREATE INDEX IF NOT EXISTS mfa_factors_identity_idx ON mfa_factors (identity_id, status);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    code_hash           TEXT NOT NULL UNIQUE,
    used_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_recovery_codes_identity_idx ON mfa_recovery_codes (identity_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kid                     TEXT NOT NULL UNIQUE,
    algorithm               TEXT NOT NULL,
    private_key_encrypted   TEXT NOT NULL,
    public_pem              TEXT NOT NULL,
    public_jwk              JSONB NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'retired', 'revoked')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at              TIMESTAMPTZ,
    not_after               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS signing_keys_status_idx ON signing_keys (status);

CREATE TABLE IF NOT EXISTS roles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    kind                TEXT NOT NULL DEFAULT 'tenant'
                        CHECK (kind IN ('system', 'tenant', 'organization', 'resource')),
    scope               TEXT NOT NULL DEFAULT 'tenant'
                        CHECK (scope IN ('global', 'tenant', 'organization', 'resource')),
    parent_id           UUID REFERENCES roles(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    is_builtin          BOOLEAN NOT NULL DEFAULT FALSE,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS roles_scope_code_uq
    ON roles (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), code)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS permissions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    category            TEXT NOT NULL DEFAULT 'general',
    kind                TEXT NOT NULL DEFAULT 'action'
                        CHECK (kind IN ('api', 'menu', 'button', 'data', 'resource', 'action')),
    parent_id           UUID REFERENCES permissions(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS permissions_scope_code_uq
    ON permissions (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), code)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    tenant_id           UUID REFERENCES tenants(id),
    granted_by          UUID,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS role_permissions_permission_idx ON role_permissions (permission_id);

CREATE TABLE IF NOT EXISTS user_roles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    organization_id     UUID,
    resource_type       TEXT,
    resource_id         TEXT,
    scope               TEXT NOT NULL DEFAULT 'tenant'
                        CHECK (scope IN ('global', 'tenant', 'organization', 'resource')),
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until         TIMESTAMPTZ,
    granted_by          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    revoked_by          UUID,
    version             INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS user_roles_active_uq
    ON user_roles (identity_id, role_id,
                   COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
                   COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid),
                   COALESCE(resource_type, ''), COALESCE(resource_id, ''))
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS user_roles_identity_idx ON user_roles (identity_id, tenant_id);
CREATE INDEX IF NOT EXISTS user_roles_role_idx ON user_roles (role_id);

CREATE TABLE IF NOT EXISTS user_permissions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    permission_id       UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    effect              TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until         TIMESTAMPTZ,
    granted_by          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS user_permissions_active_uq
    ON user_permissions (identity_id, permission_id, tenant_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS user_permissions_identity_idx ON user_permissions (identity_id, tenant_id);

CREATE TABLE IF NOT EXISTS resource_types (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS resource_types_uq
    ON resource_types (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), code);

CREATE TABLE IF NOT EXISTS resource_relations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    resource_type       TEXT NOT NULL,
    resource_id         TEXT NOT NULL,
    relation            TEXT NOT NULL
                        CHECK (relation IN ('owner', 'editor', 'viewer', 'member', 'admin', 'reader')),
    subject_type        TEXT NOT NULL CHECK (subject_type IN ('identity', 'role', 'organization', 'group', 'tenant')),
    subject_id          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS resource_relations_uq
    ON resource_relations (resource_type, resource_id, relation, subject_type, subject_id);
CREATE INDEX IF NOT EXISTS resource_relations_subject_idx ON resource_relations (subject_type, subject_id);
CREATE INDEX IF NOT EXISTS resource_relations_resource_idx ON resource_relations (tenant_id, resource_type, resource_id);

CREATE TABLE IF NOT EXISTS identity_org_memberships (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    organization_id     UUID,
    department_id       UUID,
    department_path     TEXT,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_org_memberships_uq
    ON identity_org_memberships (identity_id,
                                 COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid),
                                 COALESCE(department_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX IF NOT EXISTS identity_org_memberships_dept_idx
    ON identity_org_memberships (tenant_id, department_id);
CREATE INDEX IF NOT EXISTS identity_org_memberships_identity_idx
    ON identity_org_memberships (identity_id);

CREATE TABLE IF NOT EXISTS authorization_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    name                TEXT NOT NULL,
    description         TEXT,
    effect              TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    subject_type        TEXT,
    subject_id          TEXT,
    action              TEXT,
    resource_type       TEXT,
    resource_id         TEXT,
    condition           JSONB NOT NULL DEFAULT '{}'::jsonb,
    priority            INTEGER NOT NULL DEFAULT 100,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS authorization_policies_lookup_idx
    ON authorization_policies (tenant_id, enabled, priority);

CREATE TABLE IF NOT EXISTS api_resources (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    method              TEXT NOT NULL,
    path_pattern        TEXT NOT NULL,
    permission_id       UUID REFERENCES permissions(id) ON DELETE SET NULL,
    description         TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS api_resources_uq
    ON api_resources (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), upper(method), path_pattern)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS menu_resources (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    parent_id           UUID REFERENCES menu_resources(id) ON DELETE CASCADE,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    route               TEXT,
    icon                TEXT,
    menu_type           TEXT NOT NULL DEFAULT 'menu' CHECK (menu_type IN ('directory', 'menu', 'link', 'external')),
    sort_order          INTEGER NOT NULL DEFAULT 0,
    visible             BOOLEAN NOT NULL DEFAULT TRUE,
    permission_id       UUID REFERENCES permissions(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS menu_resources_uq
    ON menu_resources (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), code)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS button_resources (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    menu_id             UUID REFERENCES menu_resources(id) ON DELETE CASCADE,
    api_resource_id     UUID REFERENCES api_resources(id) ON DELETE SET NULL,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    permission_id       UUID REFERENCES permissions(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS button_resources_uq
    ON button_resources (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), code)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS data_permissions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    role_id             UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       UUID REFERENCES permissions(id) ON DELETE CASCADE,
    scope_type          TEXT NOT NULL
                        CHECK (scope_type IN ('all', 'self', 'department', 'department_and_children',
                                              'departments', 'users', 'custom')),
    scope_config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS data_permissions_role_idx ON data_permissions (tenant_id, role_id);

CREATE TABLE IF NOT EXISTS saml_idp_configs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL UNIQUE REFERENCES tenants(id),
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    entity_id               TEXT NOT NULL,
    idp_name                TEXT NOT NULL DEFAULT 'Auth Center',
    sso_url                 TEXT NOT NULL,
    slo_url                 TEXT NOT NULL,
    certificate_pem         TEXT NOT NULL,
    private_key_encrypted   TEXT NOT NULL,
    metadata_xml            TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS saml_sp_configs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    code                TEXT NOT NULL,
    entity_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    metadata_xml        TEXT NOT NULL,
    acs_url             TEXT NOT NULL,
    slo_url             TEXT,
    audience            TEXT NOT NULL,
    name_id_format      TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    attribute_mapping   JSONB NOT NULL DEFAULT '{}'::jsonb,
    certificate_pem     TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS saml_sp_configs_code_uq ON saml_sp_configs (tenant_id, code);
CREATE UNIQUE INDEX IF NOT EXISTS saml_sp_configs_entity_uq ON saml_sp_configs (tenant_id, entity_id);

CREATE TABLE IF NOT EXISTS saml_replay_cache (
    assertion_id        TEXT PRIMARY KEY,
    tenant_id           UUID REFERENCES tenants(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_replay_cache_expires_idx ON saml_replay_cache (expires_at);

CREATE TABLE IF NOT EXISTS security_audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID,
    actor_id            UUID,
    actor_type          TEXT NOT NULL DEFAULT 'user',
    action              TEXT NOT NULL,
    resource_type       TEXT,
    resource_id         TEXT,
    result              TEXT NOT NULL DEFAULT 'success' CHECK (result IN ('success', 'failure', 'denied')),
    ip                  TEXT,
    user_agent          TEXT,
    trace_id            TEXT,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash           TEXT,
    hash                TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_audit_logs_tenant_idx ON security_audit_logs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_audit_logs_actor_idx ON security_audit_logs (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_audit_logs_action_idx ON security_audit_logs (action, created_at DESC);

CREATE TABLE IF NOT EXISTS outbox_events (
    id                  UUID PRIMARY KEY,
    event_type          TEXT NOT NULL,
    aggregate_type      TEXT NOT NULL,
    aggregate_id        TEXT NOT NULL,
    payload             JSONB NOT NULL,
    trace_id            TEXT,
    version             INTEGER NOT NULL DEFAULT 1,
    occurred_at         TIMESTAMPTZ NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'publishing', 'published', 'dead')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_events_dispatch_idx ON outbox_events (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS inbox_events (
    event_id            UUID NOT NULL,
    consumer            TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    payload             JSONB NOT NULL,
    status              TEXT NOT NULL DEFAULT 'received'
                        CHECK (status IN ('received', 'processed', 'failed')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at        TIMESTAMPTZ,
    PRIMARY KEY (event_id, consumer)
);

-- 内置权限目录
INSERT INTO permissions (tenant_id, code, name, category, kind) VALUES
    (NULL, 'admin:access', '访问管理后台', 'system', 'action'),
    (NULL, 'identity:read', '查询身份', 'identity', 'action'),
    (NULL, 'identity:write', '管理身份', 'identity', 'action'),
    (NULL, 'mfa:reset', '重置 MFA', 'identity', 'action'),
    (NULL, 'role:read', '查询角色', 'rbac', 'action'),
    (NULL, 'role:write', '管理角色', 'rbac', 'action'),
    (NULL, 'permission:read', '查询权限', 'rbac', 'action'),
    (NULL, 'permission:write', '管理权限', 'rbac', 'action'),
    (NULL, 'user_role:read', '查询用户角色', 'rbac', 'action'),
    (NULL, 'user_role:write', '管理用户角色', 'rbac', 'action'),
    (NULL, 'tenant:read', '查询租户', 'tenant', 'action'),
    (NULL, 'tenant:write', '管理租户', 'tenant', 'action'),
    (NULL, 'client:read', '查询 OAuth 客户端', 'oauth', 'action'),
    (NULL, 'client:write', '管理 OAuth 客户端', 'oauth', 'action'),
    (NULL, 'scope:read', '查询 OAuth Scope', 'oauth', 'action'),
    (NULL, 'scope:write', '管理 OAuth Scope', 'oauth', 'action'),
    (NULL, 'api:read', '查询 API 资源', 'authorization', 'action'),
    (NULL, 'api:write', '管理 API 资源', 'authorization', 'action'),
    (NULL, 'menu:read', '查询菜单', 'authorization', 'action'),
    (NULL, 'menu:write', '管理菜单', 'authorization', 'action'),
    (NULL, 'button:read', '查询按钮', 'authorization', 'action'),
    (NULL, 'button:write', '管理按钮', 'authorization', 'action'),
    (NULL, 'data:read', '查询数据权限', 'authorization', 'action'),
    (NULL, 'data:write', '管理数据权限', 'authorization', 'action'),
    (NULL, 'resource:read', '查询资源授权', 'authorization', 'action'),
    (NULL, 'resource:write', '管理资源授权', 'authorization', 'action'),
    (NULL, 'policy:read', '查询授权策略', 'authorization', 'action'),
    (NULL, 'policy:write', '管理授权策略', 'authorization', 'action'),
    (NULL, 'audit:read', '查询审计日志', 'audit', 'action'),
    (NULL, 'signing_key:rotate', '轮换签名密钥', 'security', 'action'),
    (NULL, 'idp:manage', '管理身份提供商', 'federation', 'action'),
    (NULL, 'saml:manage', '管理 SAML 配置', 'saml', 'action')
ON CONFLICT DO NOTHING;

INSERT INTO permissions (tenant_id, code, name, category, kind) VALUES
    (NULL, 'authz:check', '调用授权检查接口', 'authorization', 'action')
ON CONFLICT DO NOTHING;

INSERT INTO roles (tenant_id, code, name, description, kind, scope, is_builtin)
VALUES (NULL, 'super_admin', '超级管理员', '拥有全部管理权限的内置全局角色', 'system', 'global', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.code = 'super_admin' AND r.tenant_id IS NULL AND p.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO resource_types (tenant_id, code, name, description) VALUES
    (NULL, 'document', '文档', '通用文档资源'),
    (NULL, 'project', '项目', '项目资源'),
    (NULL, 'file', '文件', '文件资源'),
    (NULL, 'folder', '文件夹', '文件夹资源')
ON CONFLICT DO NOTHING;
