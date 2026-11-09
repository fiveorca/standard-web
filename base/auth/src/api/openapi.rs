//! OpenAPI 3.1 文档与 Swagger UI。

use axum::response::{Html, Json};
use serde_json::{json, Value};

pub async fn document() -> Json<Value> {
    Json(openapi())
}

pub async fn swagger_ui() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <title>Auth Center API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      persistAuthorization: true
    });
  </script>
</body>
</html>"#,
    )
}

fn openapi() -> Value {
    serde_json::from_str(OPENAPI_JSON).unwrap_or_else(|_| json!({ "openapi": "3.1.0" }))
}

const OPENAPI_JSON: &str = r#"{
      "openapi": "3.1.0",
      "info": {
        "title": "认证授权中心 API",
        "version": "1.0.0",
        "description": "OAuth2/OIDC、SAML2、MFA、RBAC/ABAC/ReBAC 与身份联邦。"
      },
      "servers": [
        { "url": "/", "description": "当前服务" }
      ],
      "tags": [
        { "name": "auth", "description": "终端用户认证" },
        { "name": "oauth", "description": "OAuth2 / OIDC" },
        { "name": "authz", "description": "授权决策" },
        { "name": "admin", "description": "管理端" },
        { "name": "saml", "description": "SAML2 IdP" },
        { "name": "internal", "description": "内部服务" }
      ],
      "components": {
        "securitySchemes": {
          "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" },
          "cookieAuth": { "type": "apiKey", "in": "cookie", "name": "auth_session" },
          "internalToken": { "type": "apiKey", "in": "header", "name": "x-internal-token" }
        },
        "schemas": {
          "Error": {
            "type": "object",
            "properties": {
              "code": { "type": "string" },
              "message": { "type": "string" },
              "details": {}
            }
          }
        }
      },
      "paths": {
        "/api/v1/auth/register": { "post": { "tags": ["auth"], "summary": "注册身份", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/login": { "post": { "tags": ["auth"], "summary": "密码登录（可能返回 MFA 挑战）", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/login/otp/request": { "post": { "tags": ["auth"], "summary": "发送登录验证码", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/login/otp": { "post": { "tags": ["auth"], "summary": "验证码登录", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/refresh": { "post": { "tags": ["auth"], "summary": "刷新令牌（轮换）", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/logout": { "post": { "tags": ["auth"], "summary": "退出登录", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/me": { "get": { "tags": ["auth"], "summary": "当前身份与授权", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/password/forgot": { "post": { "tags": ["auth"], "summary": "发起密码找回", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/password/reset": { "post": { "tags": ["auth"], "summary": "重置密码", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/mfa/verify": { "post": { "tags": ["auth"], "summary": "完成 MFA 登录", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/mfa/totp/start": { "post": { "tags": ["auth"], "summary": "开始 TOTP 绑定", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/auth/sessions": { "get": { "tags": ["auth"], "summary": "列出会话", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } }, "delete": { "tags": ["auth"], "summary": "撤销其他会话", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/check": { "post": { "tags": ["authz"], "summary": "单次授权决策", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/batch-check": { "post": { "tags": ["authz"], "summary": "批量授权决策", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/me": { "get": { "tags": ["authz"], "summary": "我的角色与权限", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/me/menus": { "get": { "tags": ["authz"], "summary": "我的菜单", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/me/buttons": { "get": { "tags": ["authz"], "summary": "我的按钮权限", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/authz/me/apis": { "get": { "tags": ["authz"], "summary": "我的 API 权限", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/oauth2/authorize": { "get": { "tags": ["oauth"], "summary": "授权端点（Authorization Code + PKCE）", "responses": { "302": { "description": "重定向" } } } },
        "/oauth2/authorize/consent": { "post": { "tags": ["oauth"], "summary": "提交授权同意", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/oauth2/token": { "post": { "tags": ["oauth"], "summary": "令牌端点", "responses": { "200": { "description": "成功" } } } },
        "/oauth2/introspect": { "post": { "tags": ["oauth"], "summary": "令牌自省", "responses": { "200": { "description": "成功" } } } },
        "/oauth2/revoke": { "post": { "tags": ["oauth"], "summary": "令牌撤销", "responses": { "200": { "description": "成功" } } } },
        "/oauth2/userinfo": { "get": { "tags": ["oauth"], "summary": "用户信息", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/oauth2/jwks": { "get": { "tags": ["oauth"], "summary": "JWKS", "responses": { "200": { "description": "成功" } } } },
        "/.well-known/openid-configuration": { "get": { "tags": ["oauth"], "summary": "OIDC Discovery", "responses": { "200": { "description": "成功" } } } },
        "/saml/metadata": { "get": { "tags": ["saml"], "summary": "SAML IdP Metadata", "responses": { "200": { "description": "XML" } } } },
        "/saml/sso": { "get": { "tags": ["saml"], "summary": "SAML SSO（Redirect Binding）", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["saml"], "summary": "SAML SSO（POST Binding）", "security": [{ "bearerAuth": [] }, { "cookieAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/saml/slo": { "get": { "tags": ["saml"], "summary": "SAML 单点登出", "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["saml"], "summary": "SAML 单点登出（POST）", "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/roles": { "get": { "tags": ["admin"], "summary": "角色列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["admin"], "summary": "创建角色", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/permissions": { "get": { "tags": ["admin"], "summary": "权限列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["admin"], "summary": "创建权限", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/identities": { "get": { "tags": ["admin"], "summary": "身份列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["admin"], "summary": "创建身份", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/audit-logs": { "get": { "tags": ["admin"], "summary": "审计日志", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/saml/sps": { "get": { "tags": ["admin"], "summary": "SAML SP 列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["admin"], "summary": "注册/更新 SAML SP", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/admin/identity-providers": { "get": { "tags": ["admin"], "summary": "身份提供商列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }, "post": { "tags": ["admin"], "summary": "创建/更新身份提供商", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/internal/identities": { "post": { "tags": ["internal"], "summary": "内部创建身份", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } },
        "/api/v1/internal/events": { "post": { "tags": ["internal"], "summary": "接收领域事件", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } }
      }
    }"#;
