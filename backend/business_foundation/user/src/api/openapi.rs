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
  <title>User Center API</title>
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
    "title": "用户中心 API",
    "version": "1.0.0",
    "description": "用户资料、联系人、属性、分组、组织部门与注册审核。鉴权由认证中心完成，用户中心离线校验 JWT。"
  },
  "servers": [
    { "url": "/", "description": "当前服务" }
  ],
  "tags": [
    { "name": "self", "description": "终端用户自助" },
    { "name": "admin", "description": "管理端" },
    { "name": "registration", "description": "注册" },
    { "name": "internal", "description": "内部服务" }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" },
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
    "/api/v1/users/me": {
      "get": { "tags": ["self"], "summary": "当前用户", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "patch": { "tags": ["self"], "summary": "更新当前用户基础信息", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/users/me/profile": {
      "get": { "tags": ["self"], "summary": "读取资料", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["self"], "summary": "更新资料", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/users/me/avatar": { "put": { "tags": ["self"], "summary": "更新头像", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/nickname": { "put": { "tags": ["self"], "summary": "更新昵称", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/contacts": { "get": { "tags": ["self"], "summary": "我的联系方式（脱敏）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/contacts/request": { "post": { "tags": ["self"], "summary": "发起联系方式换绑（由认证中心发码）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/contacts/confirm": { "post": { "tags": ["self"], "summary": "确认联系方式换绑", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/contacts/{kind}": { "delete": { "tags": ["self"], "summary": "解绑联系方式", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/attributes": {
      "get": { "tags": ["self"], "summary": "我的自定义属性", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["self"], "summary": "更新自定义属性", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/users/me/groups": { "get": { "tags": ["self"], "summary": "我的分组", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/organizations": { "get": { "tags": ["self"], "summary": "我的组织/部门", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/history": { "get": { "tags": ["self"], "summary": "我的组织变动历史", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/links": { "get": { "tags": ["self"], "summary": "我的第三方账号绑定", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/links/{provider}": { "delete": { "tags": ["self"], "summary": "解绑第三方账号", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/users/me/registration": { "get": { "tags": ["self"], "summary": "我的注册记录", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/registrations": { "post": { "tags": ["registration"], "summary": "自助注册", "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users": {
      "get": { "tags": ["admin"], "summary": "用户列表（筛选/分页）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "创建用户（密码透传认证中心）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/batch": {
      "post": { "tags": ["admin"], "summary": "批量创建", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "patch": { "tags": ["admin"], "summary": "批量更新", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/import": { "post": { "tags": ["admin"], "summary": "CSV 导入", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/export": { "get": { "tags": ["admin"], "summary": "CSV 导出", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "CSV" } } } },
    "/api/v1/admin/users/{id}": {
      "get": { "tags": ["admin"], "summary": "用户详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "patch": { "tags": ["admin"], "summary": "更新用户", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "删除用户（软删）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/{id}/status": { "put": { "tags": ["admin"], "summary": "变更状态", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/restore": { "post": { "tags": ["admin"], "summary": "恢复用户", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/tags": {
      "get": { "tags": ["admin"], "summary": "用户标签", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "设置标签", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/{id}/contacts": { "get": { "tags": ["admin"], "summary": "用户联系方式（脱敏）", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/contacts/{kind}": { "delete": { "tags": ["admin"], "summary": "解绑联系方式", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/attributes": {
      "get": { "tags": ["admin"], "summary": "用户属性值", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "设置用户属性值", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/{id}/groups": { "get": { "tags": ["admin"], "summary": "用户所属分组", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/memberships": { "get": { "tags": ["admin"], "summary": "用户组织归属", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/history": { "get": { "tags": ["admin"], "summary": "组织变动历史", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/status-history": { "get": { "tags": ["admin"], "summary": "状态历史", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/registration": { "get": { "tags": ["admin"], "summary": "注册记录", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/links": {
      "get": { "tags": ["admin"], "summary": "第三方绑定列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "添加第三方绑定", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/users/{id}/links/{provider}": { "delete": { "tags": ["admin"], "summary": "解绑第三方账号", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/users/{id}/transfer": { "post": { "tags": ["admin"], "summary": "组织调动", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/attributes": {
      "get": { "tags": ["admin"], "summary": "属性定义列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "创建属性定义", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/attributes/{id}": {
      "get": { "tags": ["admin"], "summary": "属性定义详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "更新属性定义", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "删除属性定义", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/groups": {
      "get": { "tags": ["admin"], "summary": "分组列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "创建分组", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/groups/tree": { "get": { "tags": ["admin"], "summary": "分组树", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/groups/{id}": {
      "get": { "tags": ["admin"], "summary": "分组详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "更新分组", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "删除分组", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/groups/{id}/members": {
      "get": { "tags": ["admin"], "summary": "分组成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "添加成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "移除成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/organizations": {
      "get": { "tags": ["admin"], "summary": "组织列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "创建组织", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/organizations/tree": { "get": { "tags": ["admin"], "summary": "组织树", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/organizations/{id}": {
      "get": { "tags": ["admin"], "summary": "组织详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "更新组织", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "删除组织", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/organizations/{id}/leader": { "put": { "tags": ["admin"], "summary": "设置组织负责人", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/organizations/{id}/members": {
      "get": { "tags": ["admin"], "summary": "组织成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "添加成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/organizations/{id}/members/{user_id}": { "delete": { "tags": ["admin"], "summary": "移除成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/departments": {
      "get": { "tags": ["admin"], "summary": "部门列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "创建部门", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/departments/tree": { "get": { "tags": ["admin"], "summary": "部门树", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/departments/{id}": {
      "get": { "tags": ["admin"], "summary": "部门详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "put": { "tags": ["admin"], "summary": "更新部门", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "delete": { "tags": ["admin"], "summary": "删除部门", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/departments/{id}/leader": { "put": { "tags": ["admin"], "summary": "设置部门负责人", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/departments/{id}/members": {
      "get": { "tags": ["admin"], "summary": "部门成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } },
      "post": { "tags": ["admin"], "summary": "添加成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/admin/departments/{id}/members/{user_id}": { "delete": { "tags": ["admin"], "summary": "移除成员", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/registrations": { "get": { "tags": ["admin"], "summary": "注册申请列表", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/registrations/{id}": { "get": { "tags": ["admin"], "summary": "注册申请详情", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/registrations/{id}/review": { "post": { "tags": ["admin"], "summary": "审核注册申请", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/admin/audit-logs": { "get": { "tags": ["admin"], "summary": "审计日志", "security": [{ "bearerAuth": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/internal/users/ensure": { "post": { "tags": ["internal"], "summary": "确保用户本地投影存在", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/internal/users/{id}": {
      "get": { "tags": ["internal"], "summary": "读取用户投影", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } },
      "patch": { "tags": ["internal"], "summary": "更新用户资料投影", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } }
    },
    "/api/v1/internal/users/{id}/status": { "post": { "tags": ["internal"], "summary": "同步用户状态", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/internal/users/{id}/contacts": { "post": { "tags": ["internal"], "summary": "同步已验证联系方式", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } },
    "/api/v1/internal/events": { "post": { "tags": ["internal"], "summary": "接收领域事件", "security": [{ "internalToken": [] }], "responses": { "200": { "description": "成功" } } } }
  }
}"#;
