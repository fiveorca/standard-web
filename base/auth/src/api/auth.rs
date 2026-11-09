//! 面向终端用户的认证 API。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::application::session::{LoginContext, LoginOutcome};
use crate::bootstrap::AppState;
use crate::domain::AuthContext;
use crate::middleware::security::enforce_rate_limit;
use crate::shared::response::{empty, ok, Page, PageQuery};
use crate::shared::{AppError, AppResult};

use super::{clear_auth_cookies, request_meta, resolve_tenant, token_response};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/login/otp/request", post(login_otp_request))
        .route("/api/v1/auth/login/otp", post(login_otp))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/password/change", post(change_password))
        .route("/api/v1/auth/password/forgot", post(forgot_password))
        .route("/api/v1/auth/password/reset", post(reset_password))
        .route(
            "/api/v1/auth/email/verify/request",
            post(request_email_verification),
        )
        .route(
            "/api/v1/auth/email/verify",
            post(confirm_email_verification),
        )
        .route(
            "/api/v1/auth/phone/verify/request",
            post(request_phone_verification),
        )
        .route(
            "/api/v1/auth/phone/verify",
            post(confirm_phone_verification),
        )
        .route(
            "/api/v1/auth/contact/change/request",
            post(request_contact_change),
        )
        .route("/api/v1/auth/contact/change", post(confirm_contact_change))
        .route(
            "/api/v1/auth/sessions",
            get(list_sessions).delete(revoke_other_sessions),
        )
        .route("/api/v1/auth/sessions/{id}", delete(revoke_session))
        .route(
            "/api/v1/auth/sessions/devices/{device_id}",
            delete(revoke_device),
        )
        .route("/api/v1/auth/sessions/{id}/device", post(rename_device))
        .route("/api/v1/auth/login-history", get(login_history))
        .route("/api/v1/auth/mfa", get(mfa_status))
        .route("/api/v1/auth/mfa/totp/start", post(start_totp))
        .route("/api/v1/auth/mfa/totp/confirm", post(confirm_totp))
        .route("/api/v1/auth/mfa/recovery-codes", post(regenerate_recovery))
        .route("/api/v1/auth/mfa/verify", post(verify_mfa))
        .route(
            "/api/v1/auth/mfa/webauthn/register/start",
            post(webauthn_register_start),
        )
        .route(
            "/api/v1/auth/mfa/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route(
            "/api/v1/auth/mfa/webauthn/verify/start",
            post(webauthn_verify_start),
        )
        .route(
            "/api/v1/auth/mfa/webauthn/verify/finish",
            post(webauthn_verify_finish),
        )
        .route("/api/v1/auth/mfa/factors/{id}", delete(disable_mfa_factor))
        .route("/api/v1/auth/consents", get(list_consents))
        .route("/api/v1/auth/consents/{client_id}", delete(revoke_consent))
        .route("/api/v1/auth/federated/links", get(list_federation_links))
        .route(
            "/api/v1/auth/federated/links/{provider}",
            delete(unlink_federation),
        )
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    enforce_rate_limit(
        &state,
        "register",
        &format!("{tenant_id}"),
        &state.config.security.login_rate_limit,
    )
    .await?;
    let meta = request_meta(&state, &headers);
    let identity = state
        .create_identity(
            crate::application::identity::CreateIdentityInput {
                tenant_id,
                username: body.username,
                email: body.email,
                phone: body.phone,
                password: Some(body.password),
                display_name: body.display_name,
                avatar_url: None,
                status: None,
                email_verified: false,
                phone_verified: false,
                metadata: json!({ "source": "registration" }),
                require_email_verification: false,
                source: "registration".to_string(),
            },
            &meta,
        )
        .await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    identifier: String,
    password: String,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    let meta = request_meta(&state, &headers);
    enforce_rate_limit(
        &state,
        "login",
        &format!(
            "{}|{}",
            meta.ip.clone().unwrap_or_default(),
            body.identifier
        ),
        &state.config.security.login_rate_limit,
    )
    .await?;
    let ctx = LoginContext {
        tenant_id,
        client_id: Some(crate::application::session::DEFAULT_CLIENT_ID.to_string()),
        device_id: body.device_id,
        device_name: body.device_name,
        ip: meta.ip,
        user_agent: meta.user_agent,
        trace_id: meta.trace_id,
    };
    let scope = body
        .scope
        .unwrap_or_else(|| state.config.oauth.default_scope.clone());
    let outcome = state
        .login_with_password(tenant_id, &body.identifier, &body.password, &scope, &ctx)
        .await?;
    Ok(match outcome {
        LoginOutcome::Authenticated { tokens } => token_response(&state, tokens),
        LoginOutcome::MfaRequired {
            mfa_token,
            factors,
            expires_in,
        } => ok(json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
            "factors": factors,
            "expires_in": expires_in,
        }))
        .into_response(),
    })
}

#[derive(Debug, Deserialize)]
struct OtpRequest {
    identifier: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

async fn login_otp_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<OtpRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    let meta = request_meta(&state, &headers);
    enforce_rate_limit(
        &state,
        "otp",
        &format!(
            "{}|{}",
            meta.ip.clone().unwrap_or_default(),
            body.identifier
        ),
        &state.config.security.otp_rate_limit,
    )
    .await?;
    let found = state
        .identity_by_login(tenant_id, &body.identifier)
        .await?
        .ok_or_else(|| AppError::bad_request("账号不存在"))?;
    let identity = found.identity;
    let channel = body
        .channel
        .or_else(|| identity.email.as_ref().map(|_| "email".to_string()))
        .or_else(|| identity.phone.as_ref().map(|_| "sms".to_string()))
        .ok_or_else(|| AppError::bad_request("账号没有可用于接收验证码的联系方式"))?;
    let target = match channel.as_str() {
        "email" => identity.email.clone(),
        "sms" | "phone" => identity.phone.clone(),
        _ => None,
    }
    .ok_or_else(|| AppError::bad_request("账号没有对应的联系方式"))?;
    state
        .issue_verification_code(
            tenant_id,
            Some(identity.id),
            "login",
            if channel == "email" { "email" } else { "sms" },
            &target,
        )
        .await?;
    Ok(ok(json!({ "sent": true, "channel": channel })).into_response())
}

#[derive(Debug, Deserialize)]
struct OtpLoginRequest {
    identifier: String,
    code: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn login_otp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<OtpLoginRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    let meta = request_meta(&state, &headers);
    enforce_rate_limit(
        &state,
        "otp-verify",
        &format!(
            "{}|{}",
            meta.ip.clone().unwrap_or_default(),
            body.identifier
        ),
        &state.config.security.otp_rate_limit,
    )
    .await?;
    let channel = body.channel.unwrap_or_else(|| {
        if body.identifier.contains('@') {
            "email".to_string()
        } else {
            "sms".to_string()
        }
    });
    let ctx = LoginContext {
        tenant_id,
        client_id: Some(crate::application::session::DEFAULT_CLIENT_ID.to_string()),
        device_id: None,
        device_name: None,
        ip: meta.ip,
        user_agent: meta.user_agent,
        trace_id: meta.trace_id,
    };
    let scope = body
        .scope
        .unwrap_or_else(|| state.config.oauth.default_scope.clone());
    let outcome = state
        .login_with_otp(
            tenant_id,
            &body.identifier,
            &channel,
            &body.code,
            &scope,
            &ctx,
        )
        .await?;
    Ok(match outcome {
        LoginOutcome::Authenticated { tokens } => token_response(&state, tokens),
        LoginOutcome::MfaRequired {
            mfa_token,
            factors,
            expires_in,
        } => ok(json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
            "factors": factors,
            "expires_in": expires_in,
        }))
        .into_response(),
    })
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
    #[serde(default)]
    client_id: Option<String>,
}

async fn refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RefreshRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let tokens = state
        .refresh_tokens(
            &body.refresh_token,
            body.client_id.as_deref(),
            meta.ip,
            meta.user_agent,
        )
        .await?;
    Ok(token_response(&state, tokens))
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    #[serde(default)]
    all_devices: bool,
}

async fn logout(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<LogoutRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let session_id = ctx
        .session_id
        .ok_or_else(|| AppError::unauthorized("缺少会话"))?;
    state
        .logout(
            ctx.identity_id,
            session_id,
            &ctx.claims.jti,
            ctx.claims.exp,
            body.all_devices,
            &meta,
        )
        .await?;
    let mut response = empty().into_response();
    clear_auth_cookies(&state, response.headers_mut());
    Ok(response)
}

async fn me(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let authorization = state
        .my_authorization(ctx.identity_id, ctx.tenant_id)
        .await?;
    Ok(ok(json!({
        "identity": identity,
        "session_id": ctx.session_id,
        "scopes": ctx.scopes,
        "amr": ctx.amr,
        "acr": ctx.acr,
        "authorization": authorization,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .change_password(
            ctx.identity_id,
            &body.current_password,
            &body.new_password,
            &meta,
        )
        .await?;
    let mut response = empty().into_response();
    clear_auth_cookies(&state, response.headers_mut());
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct ForgotPasswordRequest {
    identifier: String,
    #[serde(default)]
    tenant: Option<String>,
}

async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    state
        .request_password_reset(tenant_id, &body.identifier)
        .await?;
    Ok(ok(json!({ "accepted": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct ResetPasswordRequest {
    identifier: String,
    code: String,
    #[serde(default)]
    channel: Option<String>,
    new_password: String,
    #[serde(default)]
    tenant: Option<String>,
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ResetPasswordRequest>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, body.tenant.as_deref()).await?;
    let meta = request_meta(&state, &headers);
    let channel = body.channel.unwrap_or_else(|| {
        if body.identifier.contains('@') {
            "email".to_string()
        } else {
            "sms".to_string()
        }
    });
    state
        .reset_password(
            tenant_id,
            &body.identifier,
            &body.code,
            &channel,
            &body.new_password,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "reset": true })).into_response())
}

async fn request_email_verification(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let email = identity
        .email
        .ok_or_else(|| AppError::bad_request("账号未绑定邮箱"))?;
    state
        .issue_verification_code(
            identity.tenant_id,
            Some(identity.id),
            "verify_email",
            "email",
            &email,
        )
        .await?;
    Ok(ok(json!({ "sent": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct CodeTargetRequest {
    #[serde(default)]
    target: Option<String>,
    code: String,
}

async fn confirm_email_verification(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<CodeTargetRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let email = body
        .target
        .or(identity.email)
        .ok_or_else(|| AppError::bad_request("账号未绑定邮箱"))?;
    state
        .consume_verification_code("verify_email", "email", &email, &body.code)
        .await?;
    state
        .mark_contact_verified(identity.id, "email", &email)
        .await?;
    Ok(ok(json!({ "verified": true })).into_response())
}

async fn request_phone_verification(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let phone = identity
        .phone
        .ok_or_else(|| AppError::bad_request("账号未绑定手机号"))?;
    state
        .issue_verification_code(
            identity.tenant_id,
            Some(identity.id),
            "verify_phone",
            "sms",
            &phone,
        )
        .await?;
    Ok(ok(json!({ "sent": true })).into_response())
}

async fn confirm_phone_verification(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<CodeTargetRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let phone = body
        .target
        .or(identity.phone)
        .ok_or_else(|| AppError::bad_request("账号未绑定手机号"))?;
    state
        .consume_verification_code("verify_phone", "sms", &phone, &body.code)
        .await?;
    state
        .mark_contact_verified(identity.id, "sms", &phone)
        .await?;
    Ok(ok(json!({ "verified": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct ContactChangeRequest {
    channel: String,
    new_value: String,
}

async fn request_contact_change(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<ContactChangeRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let (channel, purpose, target) = match body.channel.as_str() {
        "email" => ("email", "change_email", body.new_value.clone()),
        "sms" | "phone" => ("sms", "change_phone", body.new_value.clone()),
        _ => return Err(AppError::bad_request("不支持的联系方式类型")),
    };
    state
        .issue_verification_code(
            identity.tenant_id,
            Some(identity.id),
            purpose,
            channel,
            &target,
        )
        .await?;
    Ok(ok(json!({ "sent": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct ContactConfirmRequest {
    channel: String,
    new_value: String,
    code: String,
}

async fn confirm_contact_change(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ContactConfirmRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .change_contact(
            ctx.identity_id,
            &body.channel,
            &body.new_value,
            &body.code,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "changed": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct SessionsQuery {
    #[serde(default)]
    active_only: Option<bool>,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<SessionsQuery>,
) -> AppResult<Response> {
    let sessions = state
        .list_sessions(ctx.identity_id, query.active_only.unwrap_or(true))
        .await?;
    let views: Vec<crate::application::session::SessionView> = sessions
        .into_iter()
        .map(crate::application::session::SessionView::from)
        .collect();
    Ok(ok(json!({ "items": views, "current": ctx.session_id })).into_response())
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let session_id = super::parse_uuid(&id, "session_id")?;
    let session = state.get_session(session_id).await?;
    if session.identity_id != ctx.identity_id {
        return Err(AppError::forbidden("无权操作该会话"));
    }
    state.revoke_session(session_id, "user_revoked").await?;
    Ok(empty().into_response())
}

async fn revoke_other_sessions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let session_id = ctx
        .session_id
        .ok_or_else(|| AppError::unauthorized("缺少会话"))?;
    let count = state
        .revoke_other_sessions(ctx.identity_id, session_id)
        .await?;
    Ok(ok(json!({ "revoked": count })).into_response())
}

async fn revoke_device(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(device_id): Path<String>,
) -> AppResult<Response> {
    let count = state.revoke_by_device(ctx.identity_id, &device_id).await?;
    Ok(ok(json!({ "revoked": count })).into_response())
}

#[derive(Debug, Deserialize)]
struct RenameDeviceRequest {
    device_name: String,
}

async fn rename_device(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<RenameDeviceRequest>,
) -> AppResult<Response> {
    let session_id = super::parse_uuid(&id, "session_id")?;
    let session = state
        .update_device(ctx.identity_id, session_id, &body.device_name)
        .await?;
    Ok(ok(json!({ "session": session })).into_response())
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    limit: Option<i64>,
}

async fn login_history(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<HistoryQuery>,
) -> AppResult<Response> {
    let rows = state
        .login_history(ctx.identity_id, query.limit.unwrap_or(20))
        .await?;
    Ok(ok(json!({ "items": rows })).into_response())
}

async fn mfa_status(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let status = state.mfa_status(&identity).await?;
    Ok(ok(status).into_response())
}

#[derive(Debug, Deserialize, Default)]
struct TotpStartRequest {
    #[serde(default)]
    name: Option<String>,
}

async fn start_totp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<TotpStartRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let enrollment = state.start_totp_enrollment(&identity, body.name).await?;
    Ok(ok(enrollment).into_response())
}

#[derive(Debug, Deserialize)]
struct TotpConfirmRequest {
    factor_id: Uuid,
    code: String,
}

async fn confirm_totp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<TotpConfirmRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let codes = state
        .confirm_totp_enrollment(&identity, body.factor_id, &body.code)
        .await?;
    Ok(ok(json!({ "confirmed": true, "recovery_codes": codes })).into_response())
}

async fn regenerate_recovery(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let codes = state.regenerate_recovery_codes(&identity).await?;
    Ok(ok(codes).into_response())
}

#[derive(Debug, Deserialize)]
struct MfaVerifyRequest {
    mfa_token: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

async fn verify_mfa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MfaVerifyRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    enforce_rate_limit(
        &state,
        "mfa",
        &format!("{}|{}", meta.ip.clone().unwrap_or_default(), body.mfa_token),
        &state.config.security.otp_rate_limit,
    )
    .await?;
    let claims = state.verify_mfa_token(&body.mfa_token).await?;
    let identity_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("MFA Token 的 subject 非法"))?;
    let identity = state.get_identity(identity_id).await?;
    let amr = if let Some(code) = body.code.as_deref() {
        state.verify_totp_for_login(&identity, code).await?;
        vec!["pwd".to_string(), "otp".to_string()]
    } else if let Some(code) = body.recovery_code.as_deref() {
        state.verify_recovery_code(&identity, code).await?;
        vec!["pwd".to_string(), "recovery".to_string()]
    } else {
        return Err(AppError::validation("code", "缺少 MFA 验证码"));
    };
    let ctx = LoginContext {
        tenant_id: identity.tenant_id,
        client_id: Some(claims.client_id.clone()),
        device_id: None,
        device_name: None,
        ip: meta.ip,
        user_agent: meta.user_agent,
        trace_id: meta.trace_id,
    };
    let tokens = state.complete_mfa_login(&claims, amr, &ctx).await?;
    Ok(token_response(&state, tokens))
}

async fn webauthn_register_start(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let ceremony = state.webauthn_registration_start(&identity).await?;
    Ok(ok(ceremony).into_response())
}

#[derive(Debug, Deserialize)]
struct WebauthnRegisterFinish {
    response: serde_json::Value,
    #[serde(default)]
    name: Option<String>,
}

async fn webauthn_register_finish(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<WebauthnRegisterFinish>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let factor = state
        .webauthn_registration_finish(&identity, body.response, body.name)
        .await?;
    Ok(ok(factor).into_response())
}

#[derive(Debug, Deserialize)]
struct WebauthnVerifyStart {
    mfa_token: String,
}

async fn webauthn_verify_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<WebauthnVerifyStart>,
) -> AppResult<Response> {
    let claims = state.verify_mfa_token(&body.mfa_token).await?;
    let identity_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("MFA Token 的 subject 非法"))?;
    let identity = state.get_identity(identity_id).await?;
    let ceremony = state.webauthn_login_start(&identity).await?;
    Ok(ok(ceremony).into_response())
}

#[derive(Debug, Deserialize)]
struct WebauthnVerifyFinish {
    mfa_token: String,
    response: serde_json::Value,
}

async fn webauthn_verify_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WebauthnVerifyFinish>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let claims = state.verify_mfa_token(&body.mfa_token).await?;
    let identity_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("MFA Token 的 subject 非法"))?;
    let identity = state.get_identity(identity_id).await?;
    state
        .webauthn_login_finish(&identity, body.response)
        .await?;
    let ctx = LoginContext {
        tenant_id: identity.tenant_id,
        client_id: Some(claims.client_id.clone()),
        device_id: None,
        device_name: None,
        ip: meta.ip,
        user_agent: meta.user_agent,
        trace_id: meta.trace_id,
    };
    let tokens = state
        .complete_mfa_login(
            &claims,
            vec!["pwd".to_string(), "webauthn".to_string()],
            &ctx,
        )
        .await?;
    Ok(token_response(&state, tokens))
}

#[derive(Debug, Deserialize)]
struct DisableFactorRequest {
    #[serde(default)]
    password: Option<String>,
}

async fn disable_mfa_factor(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<DisableFactorRequest>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let factor_id = super::parse_uuid(&id, "factor_id")?;
    state
        .disable_mfa_factor(&identity, factor_id, body.password.as_deref())
        .await?;
    Ok(empty().into_response())
}

async fn list_consents(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let consents = state.list_user_consents(ctx.identity_id).await?;
    Ok(ok(json!({ "items": consents })).into_response())
}

async fn revoke_consent(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(client_id): Path<String>,
) -> AppResult<Response> {
    state
        .revoke_user_consent(ctx.identity_id, &client_id)
        .await?;
    Ok(empty().into_response())
}

async fn list_federation_links(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let links = state.federation_list_links(ctx.identity_id).await?;
    Ok(ok(json!({ "items": links })).into_response())
}

async fn unlink_federation(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(provider): Path<String>,
) -> AppResult<Response> {
    state.federation_unlink(ctx.identity_id, &provider).await?;
    Ok(empty().into_response())
}

/// 供 admin 复用。
pub fn _page<T>(items: Vec<T>, total: i64, query: &PageQuery) -> Page<T> {
    Page::new(items, total, query)
}
