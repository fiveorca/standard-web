//! 初始化种子数据：默认管理员、内置权限、平台角色、控制台 OAuth 客户端与 SAML IdP。

use serde_json::json;
use uuid::Uuid;

use crate::application::identity::CreateIdentityInput;
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::shared::{random_token, AppError, AppResult, DEFAULT_TENANT_ID};

const ADMIN_ROLE_CODE: &str = "platform-admin";

const BUILTIN_PERMISSIONS: &[(&str, &str, &str)] = &[
    ("admin:access", "访问管理后台", "system"),
    ("authz:check", "执行授权决策", "system"),
    ("identity:manage", "管理身份", "identity"),
    ("role:manage", "管理角色与权限", "identity"),
    ("oauth:manage", "管理 OAuth 客户端", "oauth"),
    ("audit:read", "查看审计日志", "audit"),
    ("saml:manage", "管理 SAML 配置", "saml"),
    ("tenant:manage", "管理租户", "system"),
    ("internal:events", "接收内部事件", "system"),
];

pub async fn seed(state: &AppState) -> AppResult<()> {
    state.ensure_tenant(DEFAULT_TENANT_ID).await?;
    let permission_ids = seed_permissions(state).await?;
    let role_id = seed_admin_role(state).await?;
    for permission_id in &permission_ids {
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id, granted_by)
             VALUES ($1, $2, NULL)
             ON CONFLICT (role_id, permission_id) DO NOTHING",
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&state.pool)
        .await?;
    }
    seed_admin(state, role_id).await?;
    seed_console_client(state).await?;
    seed_user_center_client(state).await?;
    if state.config.saml.enabled {
        state.saml_idp_config(DEFAULT_TENANT_ID).await?;
    }
    Ok(())
}

async fn seed_permissions(state: &AppState) -> AppResult<Vec<Uuid>> {
    let mut ids = Vec::with_capacity(BUILTIN_PERMISSIONS.len());
    for (code, name, category) in BUILTIN_PERMISSIONS {
        let existing = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM permissions WHERE tenant_id IS NULL AND code = $1 AND deleted_at IS NULL",
        )
        .bind(code)
        .fetch_optional(&state.pool)
        .await?;
        let id = match existing {
            Some(id) => {
                sqlx::query("UPDATE permissions SET name = $2, category = $3 WHERE id = $1")
                    .bind(id)
                    .bind(name)
                    .bind(category)
                    .execute(&state.pool)
                    .await?;
                id
            }
            None => {
                sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO permissions (tenant_id, code, name, category, kind, status)
                     VALUES (NULL, $1, $2, $3, 'action', 'active')
                     RETURNING id",
                )
                .bind(code)
                .bind(name)
                .bind(category)
                .fetch_one(&state.pool)
                .await?
            }
        };
        ids.push(id);
    }
    Ok(ids)
}

async fn seed_admin_role(state: &AppState) -> AppResult<Uuid> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM roles WHERE tenant_id = $1 AND lower(code) = lower($2) AND deleted_at IS NULL",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(ADMIN_ROLE_CODE)
    .fetch_optional(&state.pool)
    .await?
    {
        return Ok(id);
    }
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO roles (tenant_id, code, name, description, kind, scope, status)
         VALUES ($1, $2, '平台管理员', '内置平台管理员角色', 'system', 'tenant', 'active')
         RETURNING id",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(ADMIN_ROLE_CODE)
    .fetch_one(&state.pool)
    .await?;
    Ok(id)
}

async fn seed_admin(state: &AppState, role_id: Uuid) -> AppResult<()> {
    let username =
        std::env::var("AUTH_SEED_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let email = std::env::var("AUTH_SEED_ADMIN_EMAIL").ok();
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM identities WHERE tenant_id = $1 AND lower(username) = lower($2) AND deleted_at IS NULL",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?;
    let identity_id = if let Some((id,)) = existing {
        id
    } else {
        let (password, generated) = match std::env::var("AUTH_SEED_ADMIN_PASSWORD") {
            Ok(value) if value.len() >= 8 => (value, false),
            _ => (random_token(18), true),
        };
        let meta = RequestMeta::new(None, Some("seed".to_string()), None);
        let identity = state
            .create_identity(
                CreateIdentityInput {
                    tenant_id: DEFAULT_TENANT_ID,
                    username: username.clone(),
                    email: email.clone(),
                    phone: None,
                    password: Some(password.clone()),
                    display_name: Some("平台管理员".to_string()),
                    avatar_url: None,
                    status: Some("active".to_string()),
                    email_verified: email.is_some(),
                    phone_verified: false,
                    metadata: json!({ "seeded": true }),
                    require_email_verification: false,
                    source: "seed".to_string(),
                },
                &meta,
            )
            .await?;
        if generated {
            tracing::warn!(
                username = %username,
                password = %password,
                "已生成初始管理员账号，请立即登录并修改密码（设置 AUTH_SEED_ADMIN_PASSWORD 可自定义）"
            );
        }
        identity.id
    };

    sqlx::query(
        "INSERT INTO user_roles (tenant_id, identity_id, role_id, granted_by, status)
         VALUES ($1, $2, $3, NULL, 'active')
         ON CONFLICT (tenant_id, identity_id, role_id) DO NOTHING",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(identity_id)
    .bind(role_id)
    .execute(&state.pool)
    .await
    .map_err(|error| AppError::server_error(format!("分配管理员角色失败: {error}")))?;
    Ok(())
}

async fn seed_console_client(state: &AppState) -> AppResult<()> {
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM oauth_clients WHERE client_id = $1")
            .bind("auth-console")
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_some() {
        return Ok(());
    }
    let secret = random_token(32);
    let secret_hash = state.password.hash(secret.clone()).await?;
    let base = state.config.base_url();
    sqlx::query(
        "INSERT INTO oauth_clients
            (tenant_id, client_id, client_secret_hash, name, description, kind, redirect_uris,
             post_logout_redirect_uris, grant_types, scopes, require_pkce)
         VALUES ($1, 'auth-console', $2, '认证控制台', '内置管理控制台客户端', 'confidential',
                 $3, $4, $5, $6, TRUE)",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(&secret_hash)
    .bind(json!([format!("{base}/")]))
    .bind(json!([format!("{base}/")]))
    .bind(json!([
        "authorization_code",
        "refresh_token",
        "client_credentials"
    ]))
    .bind(json!([
        "openid",
        "profile",
        "email",
        "phone",
        "offline_access",
        "internal"
    ]))
    .execute(&state.pool)
    .await?;
    tracing::warn!(
        client_id = "auth-console",
        client_secret = %secret,
        "已创建内置控制台客户端，请安全保存 client_secret"
    );
    Ok(())
}

/// 用户中心使用的服务账号客户端（client_credentials）。
async fn seed_user_center_client(state: &AppState) -> AppResult<()> {
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM oauth_clients WHERE client_id = $1")
            .bind("user-center")
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_some() {
        return Ok(());
    }
    let secret = std::env::var("AUTH_SEED_USER_CENTER_SECRET")
        .ok()
        .filter(|value| value.len() >= 16)
        .unwrap_or_else(|| random_token(32));
    let secret_hash = state.password.hash(secret.clone()).await?;
    sqlx::query(
        "INSERT INTO oauth_clients
            (tenant_id, client_id, client_secret_hash, name, description, kind, redirect_uris,
             post_logout_redirect_uris, grant_types, scopes, require_pkce)
         VALUES ($1, 'user-center', $2, '用户中心', '内置用户中心服务客户端', 'confidential',
                 $3, $4, $5, $6, FALSE)",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(&secret_hash)
    .bind(json!([]))
    .bind(json!([]))
    .bind(json!(["client_credentials"]))
    .bind(json!(["internal"]))
    .execute(&state.pool)
    .await?;
    tracing::warn!(
        client_id = "user-center",
        client_secret = %secret,
        "已创建内置用户中心客户端，请将 secret 配置到用户中心 auth.service_client_secret"
    );
    Ok(())
}
