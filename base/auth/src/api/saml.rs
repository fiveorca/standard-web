//! SAML 2.0 IdP 端点。

use std::sync::Arc;

use axum::extract::{Form, Query, RawQuery, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::bootstrap::AppState;
use crate::domain::AuthContext;
use crate::protocol::saml::{SamlDispatch, SamlForm};
use crate::shared::response::ok;
use crate::shared::{AppError, AppResult};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/saml/metadata", get(metadata))
        .route("/saml/sso", get(sso_redirect).post(sso_post))
        .route("/saml/slo", get(slo_redirect).post(slo_post))
}

#[derive(Debug, Deserialize)]
struct MetadataQuery {
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    sign: Option<bool>,
}

async fn metadata(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MetadataQuery>,
) -> AppResult<Response> {
    let tenant_id = super::resolve_tenant(&state, query.tenant.as_deref()).await?;
    let xml = state
        .saml_metadata(tenant_id, query.sign.unwrap_or(true))
        .await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )],
        xml,
    )
        .into_response())
}

async fn sso_redirect(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    RawQuery(raw): RawQuery,
    Query(form): Query<SamlForm>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let wire = raw.unwrap_or_else(|| {
        form.saml_request
            .as_deref()
            .map(|value| format!("SAMLRequest={}", value))
            .unwrap_or_default()
    });
    let dispatch = state
        .saml_handle_sso(
            ctx.tenant_id,
            saml::Binding::HttpRedirect,
            wire.as_bytes(),
            form.relay_state.as_deref(),
            &identity,
        )
        .await?;
    Ok(render_dispatch(dispatch))
}

async fn sso_post(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Form(form): Form<SamlForm>,
) -> AppResult<Response> {
    let identity = state.get_identity(ctx.identity_id).await?;
    let wire = form
        .saml_request
        .clone()
        .ok_or_else(|| AppError::bad_request("缺少 SAMLRequest"))?;
    let dispatch = state
        .saml_handle_sso(
            ctx.tenant_id,
            saml::Binding::HttpPost,
            wire.as_bytes(),
            form.relay_state.as_deref(),
            &identity,
        )
        .await?;
    Ok(render_dispatch(dispatch))
}

async fn slo_redirect(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    RawQuery(raw): RawQuery,
    Query(form): Query<SamlForm>,
) -> AppResult<Response> {
    let wire = raw.unwrap_or_else(|| {
        form.saml_request
            .as_deref()
            .map(|value| format!("SAMLRequest={}", value))
            .unwrap_or_default()
    });
    let dispatch = state
        .saml_handle_slo(ctx.tenant_id, saml::Binding::HttpRedirect, wire.as_bytes())
        .await?;
    let mut response = render_dispatch(dispatch);
    super::clear_auth_cookies(&state, response.headers_mut());
    Ok(response)
}

async fn slo_post(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Form(form): Form<SamlForm>,
) -> AppResult<Response> {
    let wire = form
        .saml_request
        .or(form.saml_response)
        .ok_or_else(|| AppError::bad_request("缺少 SAML 注销请求"))?;
    let dispatch = state
        .saml_handle_slo(ctx.tenant_id, saml::Binding::HttpPost, wire.as_bytes())
        .await?;
    let mut response = render_dispatch(dispatch);
    super::clear_auth_cookies(&state, response.headers_mut());
    Ok(response)
}

fn render_dispatch(dispatch: SamlDispatch) -> Response {
    match dispatch {
        SamlDispatch::Redirect { url } => Redirect::to(&url).into_response(),
        SamlDispatch::Post {
            action,
            saml_request,
            saml_response,
            relay_state,
        } => {
            let field = if let Some(value) = saml_response {
                ("SAMLResponse", value)
            } else {
                ("SAMLRequest", saml_request.unwrap_or_default())
            };
            let html = format!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>SAML</title></head>\
                 <body onload=\"document.forms[0].submit()\">\
                 <form method=\"post\" action=\"{action}\">\
                 <input type=\"hidden\" name=\"{}\" value=\"{}\"/>\
                 {}\
                 <noscript><button type=\"submit\">Continue</button></noscript>\
                 </form></body></html>",
                escape(&field.0),
                escape(&field.1),
                relay_state
                    .map(|value| format!(
                        "<input type=\"hidden\" name=\"RelayState\" value=\"{}\"/>",
                        escape(&value)
                    ))
                    .unwrap_or_default(),
                action = escape(&action),
            );
            ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
        }
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// 便于调试的手工触发端点（需要登录）。
pub async fn _noop() -> impl IntoResponse {
    ok(serde_json::json!({}))
}
