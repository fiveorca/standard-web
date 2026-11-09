//! 身份联邦端点：发起授权与回调。

use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::AppState;
use crate::middleware::auth::OptionalAuth;
use crate::protocol::federation::FederationCallbackParams;
use crate::shared::response::ok;
use crate::shared::{AppError, AppResult};

use super::{request_meta, resolve_tenant, token_response};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/federated/{provider}/start", get(start))
        .route(
            "/api/v1/auth/federated/{provider}/callback",
            get(callback).post(callback_post),
        )
        .route("/api/v1/auth/federated/saml/acs", post(saml_acs))
}

#[derive(Debug, Deserialize, Default)]
struct StartQuery {
    #[serde(default)]
    link: Option<bool>,
    #[serde(default)]
    redirect_after: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

async fn start(
    State(state): State<Arc<AppState>>,
    auth: OptionalAuth,
    Path(provider): Path<String>,
    Query(query): Query<StartQuery>,
) -> AppResult<Response> {
    let ctx = auth.0;
    let link_identity = if query.link.unwrap_or(false) {
        Some(
            ctx.as_ref()
                .map(|context| context.identity_id)
                .ok_or_else(|| AppError::unauthorized("绑定第三方账号需要先登录"))?,
        )
    } else {
        None
    };
    let tenant_id = match ctx.as_ref() {
        Some(context) => context.tenant_id,
        None => resolve_tenant(&state, query.tenant.as_deref()).await?,
    };
    let redirect_after = query.redirect_after.map(|target| {
        crate::security::redirect::safe_post_login_redirect(
            &target,
            &state.config.server.cors_allowed_origins,
            "/",
        )
    });
    let start = state
        .federation_start(tenant_id, &provider, link_identity, redirect_after)
        .await?;
    Ok(ok(start).into_response())
}

async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> AppResult<Response> {
    handle_callback(state, provider, headers, query.params, query.tenant).await
}

async fn callback_post(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(tenant): Query<CallbackTenant>,
    Form(params): Form<FederationCallbackParams>,
) -> AppResult<Response> {
    handle_callback(state, provider, headers, params, tenant.tenant).await
}

#[derive(Debug, Deserialize, Default)]
struct CallbackQuery {
    #[serde(flatten)]
    params: FederationCallbackParams,
    #[serde(default)]
    tenant: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CallbackTenant {
    #[serde(default)]
    tenant: Option<String>,
}

async fn handle_callback(
    state: Arc<AppState>,
    provider: String,
    headers: HeaderMap,
    params: FederationCallbackParams,
    tenant: Option<String>,
) -> AppResult<Response> {
    let tenant_id = resolve_tenant(&state, tenant.as_deref()).await?;
    let meta = request_meta(&state, &headers);
    let outcome = state
        .federation_callback(tenant_id, &provider, params, &meta)
        .await?;
    if let Some(target) = outcome.redirect_after.as_deref() {
        if let Some(tokens) = outcome.tokens.clone() {
            let mut response = Redirect::to(target).into_response();
            let csrf = crate::shared::util::random_token(32);
            super::append_cookie(
                response.headers_mut(),
                crate::security::cookie::session_cookie(&state.config, &tokens.access_token),
            );
            super::append_cookie(
                response.headers_mut(),
                crate::security::cookie::csrf_cookie(&state.config, &csrf),
            );
            return Ok(response);
        }
    }
    if let Some(tokens) = outcome.tokens {
        Ok(token_response(&state, tokens))
    } else {
        Ok(ok(json!({
            "linked": true,
            "identity_id": outcome.identity.id,
        }))
        .into_response())
    }
}

#[derive(Debug, Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState", default)]
    relay_state: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

/// 认证中心作为 SP 接收第三方 SAML IdP 的断言。
async fn saml_acs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CallbackTenant>,
    Form(form): Form<SamlAcsForm>,
) -> AppResult<Response> {
    let tenant_id =
        resolve_tenant(&state, form.tenant.as_deref().or(query.tenant.as_deref())).await?;
    let provider_code = form
        .provider
        .clone()
        .or_else(|| form.relay_state.clone())
        .ok_or_else(|| AppError::bad_request("缺少 provider 标识"))?;
    let provider = state.federation_provider(tenant_id, &provider_code).await?;
    if provider.kind != "saml" {
        return Err(AppError::bad_request("提供商不是 SAML 类型"));
    }
    let identity = state
        .saml_consume_sp_response(
            &provider,
            form.saml_response.as_bytes(),
            form.relay_state.as_deref(),
        )
        .await?;
    let meta = request_meta(&state, &headers);
    let external = crate::protocol::federation::ExternalProfile::from_saml(
        identity.name_id().value.clone(),
        identity
            .attributes()
            .iter()
            .find(|attribute| attribute.name == "email")
            .and_then(|attribute| attribute.values.first())
            .cloned(),
        identity
            .attributes()
            .iter()
            .find(|attribute| attribute.name == "displayName")
            .and_then(|attribute| attribute.values.first())
            .cloned(),
        json!({ "saml_name_id": identity.name_id().value }),
    );
    let (resolved, _) = state
        .federation_resolve_identity(&provider, &external, &meta)
        .await?;
    let tokens = state
        .complete_login(
            &resolved,
            crate::application::session::DEFAULT_CLIENT_ID,
            "openid profile email offline_access",
            vec!["federated".to_string(), "saml".to_string()],
            crate::application::session::ACR_PWD,
            None,
            &crate::application::session::LoginContext {
                tenant_id,
                client_id: Some(crate::application::session::DEFAULT_CLIENT_ID.to_string()),
                device_id: None,
                device_name: None,
                ip: meta.ip,
                user_agent: meta.user_agent,
                trace_id: meta.trace_id,
            },
        )
        .await?;
    Ok(token_response(&state, tokens))
}
