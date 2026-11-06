//! 经过网关验证的身份信息。

use serde::Serialize;

/// 认证方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Jwt,
    ApiKey,
}

impl AuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthType::Jwt => "jwt",
            AuthType::ApiKey => "api_key",
        }
    }
}

/// 认证成功的身份。
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub tenant: Option<String>,
    pub auth_type: AuthType,
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// 原始 JWT，用于 Token Relay（仅保存在内存，不写日志）。
    pub token: Option<String>,
    pub api_key_id: Option<String>,
}

impl Identity {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// 满足任意一个 scope 即可。
    pub fn has_any_scope(&self, scopes: &[String]) -> bool {
        scopes.iter().any(|s| self.has_scope(s))
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_any_role(&self, roles: &[String]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }
}
