//! OAuth 2.0 / OIDC 端点。

use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::AppState;
use crate::domain::AuthContext;
use crate::middleware::auth::OptionalAuth;
use crate::protocol::oauth::{AuthorizeOutcome, AuthorizeParams, TokenRequest};
use crate::shared::response::ok;
use crate::shared::{AppError, AppResult};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/oauth2/authorize", get(authorize))
        .route("/oauth2/authorize/consent", post(submit_consent))
        .route("/oauth2/token", post(token))
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
        .route("/oauth2/userinfo", get(userinfo).post(userinfo))
        .route("/oauth2/jwks", get(jwks))
        .route("/oauth2/logout", get(end_session).post(end_session))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/oauth2/.well-known/openid-configuration", get(discovery))
        .route("/oauth2/.well-known/jwks.json", get(jwks))
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    auth: OptionalAuth,
    Query(params): Query<AuthorizeParams>,
) -> AppResult<Response> {
    let Some(ctx) = auth.0 else {
        return Err(AppError::unauthorized("请先登录后再进行授权"));
    };
    match state.authorize(&ctx, params).await? {
        AuthorizeOutcome::Redirect { location } => Ok(Redirect::to(&location).into_response()),
        AuthorizeOutcome::ConsentRequired {
            request_id,
            client_id,
            client_name,
            scopes,
            redirect_uri,
            state: oauth_state,
            csrf_token,
        } => Ok(ok(json!({
            "consent_required": true,
            "request_id": request_id,
            "client_id": client_id,
            "client_name": client_name,
            "scopes": scopes,
            "redirect_uri": redirect_uri,
            "state": oauth_state,
            "csrf_token": csrf_token,
        }))
        .into_response()),
    }
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    request_id: String,
    csrf_token: String,
    #[serde(default = "default_true")]
    approve: bool,
}

fn default_true() -> bool {
    true
}

async fn submit_consent(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<ConsentRequest>,
) -> AppResult<Response> {
    let location = state
        .submit_consent(&ctx, &body.request_id, &body.csrf_token, body.approve)
        .await?;
    Ok(ok(json!({ "redirect_to": location })).into_response())
}

async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> AppResult<Response> {
    let basic = crate::protocol::oauth::parse_basic_auth(&headers);
    match state.exchange_token(request, basic).await {
        Ok(value) => Ok(Json(value).into_response()),
        Err(error) => Ok(crate::protocol::oauth::oauth_error_response(&error)),
    }
}

#[derive(Debug, Deserialize)]
struct IntrospectForm {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
}

async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> AppResult<Response> {
    let basic = crate::protocol::oauth::parse_basic_auth(&headers);
    let value = state
        .introspect(&form.token, form.token_type_hint.as_deref(), basic)
        .await?;
    Ok(Json(value).into_response())
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: String,
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> AppResult<Response> {
    let basic = crate::protocol::oauth::parse_basic_auth(&headers);
    state.revoke_token(&form.token, basic).await?;
    Ok(Json(json!({})).into_response())
}

async fn userinfo(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let value = state.userinfo(&ctx).await?;
    Ok(Json(value).into_response())
}

async fn jwks(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    let value = state.keys.jwks().await?;
    Ok(Json(value).into_response())
}

async fn discovery(State(state): State<Arc<AppState>>) -> Response {
    Json(state.discovery_document()).into_response()
}

#[derive(Debug, Deserialize)]
struct EndSessionQuery {
    #[serde(default)]
    id_token_hint: Option<String>,
    #[serde(default)]
    post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

async fn end_session(
    State(state): State<Arc<AppState>>,
    auth: OptionalAuth,
    Query(query): Query<EndSessionQuery>,
) -> AppResult<Response> {
    let redirect = state
        .end_session(
            query.id_token_hint.as_deref(),
            query.post_logout_redirect_uri.as_deref(),
            query.state.as_deref(),
            auth.0.as_ref(),
        )
        .await?;
    let mut response = match redirect {
        Some(location) => Redirect::to(&location).into_response(),
        None => ok(json!({ "logged_out": true })).into_response(),
    };
    super::clear_auth_cookies(&state, response.headers_mut());
    Ok(response)
}
