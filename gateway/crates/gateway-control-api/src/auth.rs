//! Admin API 认证与 RBAC。
//!
//! # 设计
//!
//! Phase 3 使用**静态 Bearer Token 清单**：
//!   - `admin`：可读写资源、发布、回滚
//!   - `viewer`：只读资源、版本、审计
//!
//! 每个 token 绑定一个 `actor` 名称（写入审计日志），**审计日志中不得出现 token**。
//!
//! # 为什么默认拒绝
//!
//! 如果没有配置任何 token，所有请求都应返回 401，而不是放行——管理接口
//! 默认绑定 127.0.0.1，但仍然不能假设网络边界可靠。
//!
//! # 常量时间比较
//!
//! token 比较使用 [`subtle::ConstantTimeEq`]，避免通过响应时间猜测 token。

use serde::Serialize;
use subtle::ConstantTimeEq;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::state::AdminState;

/// 管理员角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// 读写权限（含发布/回滚）
    Admin,
    /// 只读权限
    Viewer,
}

impl Role {
    /// 是否具备写权限。
    pub fn can_write(self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// 已认证的管理员身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// 操作者名称（写入审计日志）
    pub actor: String,
    /// 角色
    pub role: Role,
}

impl Principal {
    /// 要求 admin 权限；viewer 调用写接口时返回 403。
    pub fn require_admin(&self) -> Result<(), crate::error::ApiError> {
        if self.role.can_write() {
            Ok(())
        } else {
            Err(crate::error::ApiError::forbidden("admin role required for write operations"))
        }
    }
}

/// 一条静态 token 配置。
#[derive(Debug, Clone)]
struct TokenEntry {
    /// token 明文（仅保存在进程内存，不写日志）
    token: String,
    /// 绑定的操作者名称
    actor: String,
    /// 角色
    role: Role,
}

/// 静态 Token 认证器。
#[derive(Debug, Clone, Default)]
pub struct AdminAuth {
    entries: Vec<TokenEntry>,
}

impl AdminAuth {
    /// 空认证器：所有请求都会被拒绝（默认安全）。
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 追加一个 token。
    pub fn add_token(&mut self, token: impl Into<String>, actor: impl Into<String>, role: Role) {
        let token = token.into();
        // 空 token 会与缺失 Authorization 混淆，直接忽略
        if token.trim().is_empty() {
            return;
        }
        self.entries.push(TokenEntry {
            token,
            actor: actor.into(),
            role,
        });
    }

    /// 解析逗号分隔的 token 清单并批量添加。
    ///
    /// 每项支持两种写法：
    /// - `token`：actor 使用 `default_actor`
    /// - `token:actor`：显式指定 actor
    ///
    /// 示例：`token-a:alice,token-b:bob`。空白项会被忽略。
    pub fn add_spec(&mut self, spec: &str, default_actor: &str, role: Role) {
        // enumerate 直接提供序号，避免手工维护循环计数器
        for (index, part) in spec.split(',').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
            let (token, actor) = match part.split_once(':') {
                Some((token, actor)) => (token.trim(), actor.trim()),
                None => (part, default_actor),
            };
            // 多个未命名 token 使用 default_actor、default_actor-1、... 区分
            let actor = if actor.is_empty() {
                if index == 0 {
                    default_actor.to_string()
                } else {
                    format!("{default_actor}-{index}")
                }
            } else {
                actor.to_string()
            };
            self.add_token(token, actor, role);
        }
    }

    /// 是否已配置任何 token。
    pub fn is_configured(&self) -> bool {
        !self.entries.is_empty()
    }

    /// 校验 token 并返回身份。
    ///
    /// 所有 token 都会参与比较（不提前 return），减少时序差异。
    pub fn authenticate(&self, presented: &str) -> Option<Principal> {
        let mut matched: Option<&TokenEntry> = None;
        for entry in &self.entries {
            // ConstantTimeEq 返回 Choice；转为 bool 后与"是否已匹配"累积。
            // 比较本身对每个 token 都会执行，不会因为提前匹配而跳过。
            let is_equal: bool = entry.token.as_bytes().ct_eq(presented.as_bytes()).into();
            if is_equal && matched.is_none() {
                matched = Some(entry);
            }
        }
        matched.map(|entry| Principal {
            actor: entry.actor.clone(),
            role: entry.role,
        })
    }
}

/// Axum 提取器：从 `Authorization: Bearer <token>` 解析管理员身份。
///
/// 任何 handler 只要参数中出现 [`Principal`]，请求就必须携带有效 token，
/// 否则在提取阶段直接返回 401。
impl FromRequestParts<AdminState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;

        // RFC 7235：认证方案大小写不敏感
        let (scheme, token) = header_value
            .split_once(' ')
            .ok_or_else(|| ApiError::unauthorized("malformed Authorization header"))?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(ApiError::unauthorized("only Bearer authentication is supported"));
        }

        state
            .auth
            .authenticate(token.trim())
            .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_returns_role_and_actor() {
        let mut auth = AdminAuth::empty();
        auth.add_token("admin-token", "alice", Role::Admin);
        auth.add_token("viewer-token", "bob", Role::Viewer);

        let principal = auth.authenticate("admin-token").expect("admin");
        assert_eq!(principal.actor, "alice");
        assert_eq!(principal.role, Role::Admin);

        assert!(auth.authenticate("wrong-token").is_none());
        assert!(!AdminAuth::empty().is_configured());
    }
}
