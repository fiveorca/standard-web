//! 领域模型。
//!
//! 数据行结构直接映射数据库字段，业务规则通过方法或独立函数实现。
//! DTO 与数据实体保持分离：API 请求/响应类型定义在 `api` 层。

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// 认证主体状态。
pub const IDENTITY_PENDING: &str = "pending";
pub const IDENTITY_ACTIVE: &str = "active";
pub const IDENTITY_DISABLED: &str = "disabled";
pub const IDENTITY_LOCKED: &str = "locked";
pub const IDENTITY_DELETING: &str = "deleting";
pub const IDENTITY_DELETED: &str = "deleted";

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Identity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub mfa_enforced: bool,
    pub failed_attempts: i32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_ip: Option<String>,
    pub password_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Value,
    pub version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Identity {
    pub fn is_active(&self) -> bool {
        self.status == IDENTITY_ACTIVE
    }

    pub fn is_login_allowed(&self) -> bool {
        matches!(self.status.as_str(), IDENTITY_ACTIVE | IDENTITY_PENDING)
            && self.deleted_at.is_none()
    }

    pub fn is_locked_now(&self) -> bool {
        self.locked_until
            .map(|until| until > chrono::Utc::now())
            .unwrap_or(false)
    }

    pub fn masked_email(&self) -> Option<String> {
        self.email.as_deref().map(crate::shared::util::mask_email)
    }

    pub fn masked_phone(&self) -> Option<String> {
        self.phone.as_deref().map(crate::shared::util::mask_phone)
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct IdentityIdentifier {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub kind: String,
    pub value: String,
    pub normalized_value: String,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityCredential {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub credential_type: String,
    pub secret_hash: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuthSession {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<String>,
    pub status: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub amr: Value,
    pub acr: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoke_reason: Option<String>,
}

impl AuthSession {
    pub fn amr_list(&self) -> Vec<String> {
        serde_json::from_value(self.amr.clone()).unwrap_or_else(|_| vec!["pwd".to_string()])
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub session_id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub token_hash: String,
    pub family_id: Uuid,
    pub previous_id: Option<Uuid>,
    pub status: String,
    pub scope: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub auth_time: chrono::DateTime<chrono::Utc>,
    pub amr: Value,
    pub acr: String,
    pub consumed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OAuthClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub redirect_uris: Value,
    pub post_logout_redirect_uris: Value,
    pub grant_types: Value,
    pub scopes: Value,
    pub status: String,
    pub require_pkce: bool,
    pub access_token_ttl_secs: Option<i32>,
    pub refresh_token_ttl_secs: Option<i32>,
    pub id_token_ttl_secs: Option<i32>,
    pub metadata: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl OAuthClient {
    pub fn redirect_uri_allowed(&self, candidate: &str) -> bool {
        self.redirect_uris
            .as_array()
            .map(|items| items.iter().any(|item| item.as_str() == Some(candidate)))
            .unwrap_or(false)
    }

    pub fn post_logout_redirect_allowed(&self, candidate: &str) -> bool {
        self.post_logout_redirect_uris
            .as_array()
            .map(|items| items.iter().any(|item| item.as_str() == Some(candidate)))
            .unwrap_or(false)
    }

    pub fn is_public(&self) -> bool {
        self.kind == "public"
    }

    pub fn has_grant(&self, grant: &str) -> bool {
        self.grant_types
            .as_array()
            .map(|items| items.iter().any(|item| item.as_str() == Some(grant)))
            .unwrap_or(false)
    }

    pub fn allows_scope(&self, scope: &str) -> bool {
        self.allowed_scopes().iter().any(|item| item == scope)
    }

    pub fn allowed_scopes(&self) -> Vec<String> {
        self.scopes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn allowed_grants(&self) -> Vec<String> {
        self.grant_types
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OAuthScope {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_default: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OAuthConsent {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub client_id: String,
    pub tenant_id: Uuid,
    pub scopes: Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl OAuthConsent {
    pub fn scope_list(&self) -> Vec<String> {
        self.scopes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: Option<String>,
    #[serde(skip_serializing)]
    pub client_secret_encrypted: Option<String>,
    #[serde(skip_serializing)]
    pub private_key_encrypted: Option<String>,
    pub redirect_uri: Option<String>,
    pub scopes: Value,
    pub attribute_mapping: Value,
    pub auto_register: bool,
    pub link_by_verified_email: bool,
    pub config: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub provider_id: Uuid,
    pub provider_code: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub raw: Value,
    pub linked_at: chrono::DateTime<chrono::Utc>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MfaFactor {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub kind: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing)]
    pub secret_encrypted: Option<String>,
    pub credential: Option<Value>,
    pub sign_count: i64,
    pub last_used_step: Option<i64>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKey {
    pub id: Uuid,
    pub kid: String,
    pub algorithm: String,
    pub private_key_encrypted: String,
    pub public_pem: String,
    pub public_jwk: Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub activated_at: chrono::DateTime<chrono::Utc>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub status: String,
    pub settings: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub scope: String,
    pub parent_id: Option<Uuid>,
    pub status: String,
    pub is_builtin: bool,
    pub metadata: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub kind: String,
    pub parent_id: Option<Uuid>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserRole {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub role_id: Uuid,
    pub tenant_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub scope: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    pub granted_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_by: Option<Uuid>,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserPermissionGrant {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub permission_id: Uuid,
    pub tenant_id: Uuid,
    pub effect: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    pub granted_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuthorizationPolicy {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub condition: Value,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ApiResource {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub method: String,
    pub path_pattern: String,
    pub permission_id: Option<Uuid>,
    pub description: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MenuResource {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub route: Option<String>,
    pub icon: Option<String>,
    pub menu_type: String,
    pub sort_order: i32,
    pub visible: bool,
    pub permission_id: Option<Uuid>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ButtonResource {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub menu_id: Option<Uuid>,
    pub api_resource_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub permission_id: Option<Uuid>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DataPermission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role_id: Option<Uuid>,
    pub permission_id: Option<Uuid>,
    pub scope_type: String,
    pub scope_config: Value,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ResourceRelation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_type: String,
    pub resource_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SamlIdpConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub enabled: bool,
    pub entity_id: String,
    pub idp_name: String,
    pub sso_url: String,
    pub slo_url: String,
    pub certificate_pem: String,
    #[serde(skip_serializing)]
    pub private_key_encrypted: String,
    pub metadata_xml: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SamlSpConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub code: String,
    pub entity_id: String,
    pub name: String,
    pub metadata_xml: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub audience: String,
    pub name_id_format: String,
    pub attribute_mapping: Value,
    pub certificate_pem: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub tenant_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub actor_type: String,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
    pub detail: Value,
    pub prev_hash: Option<String>,
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ────────────────────────────── Token ──────────────────────────────

/// Access Token / ID Token 通用声明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scope: String,
    pub sid: String,
    #[serde(default)]
    pub amr: Vec<String>,
    pub acr: String,
    /// `access` / `id` / `mfa` / `id_token_hint`
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// MFA 中间态 token 声明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaPendingClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub tenant_id: String,
    pub client_id: String,
    pub typ: String,
    pub pending_mfa: bool,
    pub scope: String,
}

/// 已通过认证的请求上下文。
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<String>,
    pub session_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub amr: Vec<String>,
    pub acr: String,
    pub claims: TokenClaims,
    pub via_cookie: bool,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
}

impl AuthContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|item| item == scope)
    }

    pub fn is_internal(&self) -> bool {
        self.has_scope("internal")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceRef {
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRequest {
    pub subject_id: Uuid,
    pub tenant_id: Uuid,
    pub permission: String,
    #[serde(default)]
    pub resource: Option<ResourceRef>,
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataScopeKind {
    All,
    SelfOnly,
    Department,
    DepartmentAndChildren,
    Departments,
    Users,
    Custom,
}

impl DataScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::SelfOnly => "self",
            Self::Department => "department",
            Self::DepartmentAndChildren => "department_and_children",
            Self::Departments => "departments",
            Self::Users => "users",
            Self::Custom => "custom",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "self" => Some(Self::SelfOnly),
            "department" => Some(Self::Department),
            "department_and_children" => Some(Self::DepartmentAndChildren),
            "departments" => Some(Self::Departments),
            "users" => Some(Self::Users),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// 可执行的数据范围过滤描述。调用方必须使用参数化查询应用它。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataScope {
    pub kind: DataScopeKind,
    pub tenant_id: Uuid,
    pub department_ids: Vec<String>,
    pub user_ids: Vec<String>,
    pub custom: Option<Value>,
}

impl DataScope {
    pub fn all(tenant_id: Uuid) -> Self {
        Self {
            kind: DataScopeKind::All,
            tenant_id,
            department_ids: Vec::new(),
            user_ids: Vec::new(),
            custom: None,
        }
    }

    pub fn self_only(tenant_id: Uuid, identity_id: Uuid) -> Self {
        Self {
            kind: DataScopeKind::SelfOnly,
            tenant_id,
            department_ids: Vec::new(),
            user_ids: vec![identity_id.to_string()],
            custom: None,
        }
    }

    /// 生成 SQL 片段与绑定参数（仅用于受控的列名/固定模板，不接受用户输入拼接）。
    pub fn sql_predicate(
        &self,
        user_column: &str,
        department_column: &str,
        index: usize,
    ) -> (String, Vec<String>) {
        match self.kind {
            DataScopeKind::All => (format!("{user_column} IS NOT NULL"), Vec::new()),
            DataScopeKind::SelfOnly => (
                format!("{user_column} = ${index}::uuid"),
                self.user_ids.clone(),
            ),
            DataScopeKind::Users => (
                format!("{user_column} = ANY(${index}::uuid[])"),
                self.user_ids.clone(),
            ),
            DataScopeKind::Department => (
                format!("{department_column} = ANY(${index}::uuid[])"),
                self.department_ids.clone(),
            ),
            DataScopeKind::Departments | DataScopeKind::DepartmentAndChildren => (
                format!("{department_column} = ANY(${index}::uuid[])"),
                self.department_ids.clone(),
            ),
            DataScopeKind::Custom => (format!("{user_column} IS NOT NULL"), Vec::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRef {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub scope: String,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_roles: Vec<String>,
    pub denied_by_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_scope: Option<DataScope>,
}

impl AuthzDecision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            matched_roles: Vec::new(),
            denied_by_policy: None,
            data_scope: None,
        }
    }

    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            matched_roles: Vec::new(),
            denied_by_policy: None,
            data_scope: None,
        }
    }
}

/// 用户在当前租户下的有效授权快照。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EffectiveGrants {
    pub roles: Vec<RoleRef>,
    pub permissions: HashSet<String>,
    pub denied_permissions: HashSet<String>,
    pub data_permissions: Vec<DataPermission>,
    pub computed_at: i64,
}

// ────────────────────────────── 事件 ──────────────────────────────

pub const EVENT_IDENTITY_REGISTERED: &str = "auth.identity.registered";
pub const EVENT_IDENTITY_ACTIVATED: &str = "auth.identity.activated";
pub const EVENT_IDENTITY_DISABLED: &str = "auth.identity.disabled";
pub const EVENT_IDENTITY_DELETED: &str = "auth.identity.deleted";
pub const EVENT_IDENTITY_RESTORED: &str = "auth.identity.restored";
pub const EVENT_CREDENTIALS_CHANGED: &str = "auth.identity.credentials_changed";
pub const EVENT_USER_ROLES_CHANGED: &str = "auth.user_roles.changed";
pub const EVENT_PERMISSIONS_CHANGED: &str = "auth.permissions.changed";
pub const EVENT_TENANT_MEMBERSHIP_CHANGED: &str = "auth.tenant_membership.changed";

#[derive(Debug, Clone, Serialize)]
pub struct DomainEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub payload: Value,
}

impl DomainEvent {
    pub fn new(
        event_type: impl Into<String>,
        aggregate_type: impl Into<String>,
        aggregate_id: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            event_id: Uuid::now_v7(),
            event_type: event_type.into(),
            aggregate_type: aggregate_type.into(),
            aggregate_id: aggregate_id.into(),
            occurred_at: chrono::Utc::now(),
            version: 1,
            trace_id: None,
            payload,
        }
    }

    pub fn with_trace(mut self, trace_id: Option<String>) -> Self {
        self.trace_id = trace_id;
        self
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OutboxEventRow {
    pub id: Uuid,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub payload: Value,
    pub trace_id: Option<String>,
    pub version: i32,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub next_attempt_at: chrono::DateTime<chrono::Utc>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
