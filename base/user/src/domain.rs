//! 领域模型。

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
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
    pub source: String,
    pub remark: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub registered_at: DateTime<Utc>,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub gender: Option<String>,
    pub birthday: Option<NaiveDate>,
    pub bio: Option<String>,
    pub region: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub website: Option<String>,
    pub company: Option<String>,
    pub job_title: Option<String>,
    pub extra: Value,
    pub completeness: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserAttribute {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub data_type: String,
    pub required: bool,
    pub default_value: Option<Value>,
    pub options: Value,
    pub validation: Value,
    pub user_type: Option<String>,
    pub sort_order: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserAttributeValue {
    pub user_id: Uuid,
    pub attribute_id: Uuid,
    pub tenant_id: Uuid,
    pub value: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserContact {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub kind: String,
    pub value: String,
    pub normalized_value: String,
    pub verified: bool,
    pub is_primary: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserGroup {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub path: String,
    pub level: i32,
    pub status: String,
    pub tags: Value,
    pub extra: Value,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub kind: String,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub path: String,
    pub level: i32,
    pub leader_id: Option<Uuid>,
    pub status: String,
    pub extra: Value,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Department {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub organization_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub path: String,
    pub level: i32,
    pub leader_id: Option<Uuid>,
    pub status: String,
    pub extra: Value,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationMember {
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub title: Option<String>,
    pub is_primary: bool,
    pub joined_at: DateTime<Utc>,
    pub left_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DepartmentMember {
    pub department_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub title: Option<String>,
    pub is_primary: bool,
    pub joined_at: DateTime<Utc>,
    pub left_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountLink {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_subject: String,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RegistrationRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub source: String,
    pub channel: Option<String>,
    pub campaign: Option<String>,
    pub invite_code: Option<String>,
    pub status: String,
    pub reviewer_id: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub reject_reason: Option<String>,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserTag {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub tag: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct StatusHistory {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub from_status: Option<String>,
    pub to_status: String,
    pub reason: Option<String>,
    pub operator_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub claims: Value,
}

/// 认证中心事件信封。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: Uuid,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

fn default_version() -> i32 {
    1
}
