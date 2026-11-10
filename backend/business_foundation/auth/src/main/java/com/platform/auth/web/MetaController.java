package com.platform.auth.web;

import com.platform.auth.config.AppProps;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OpenAPI 3.1 描述与 Swagger UI 页面。
 */
@RestController
public class MetaController {
    private final AppProps props;

    public MetaController(AppProps props) {
        this.props = props;
    }

    @GetMapping(value = "/openapi.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> openapi() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("openapi", "3.1.0");
        doc.put("info", Map.of(
                "title", "Auth Center API",
                "description", "通用身份认证与授权中心（OAuth 2.0 / OIDC / SAML 2.0）",
                "version", "1.0.0"));
        doc.put("servers", List.of(Map.of("url", props.getBaseUrl())));
        doc.put("tags", List.of(
                tag("Auth", "身份注册、登录、会话与凭证"),
                tag("MFA", "多因素认证"),
                tag("Federation", "第三方身份联邦"),
                tag("Authz", "统一授权决策"),
                tag("Admin", "管理后台"),
                tag("OAuth", "OAuth 2.0 / OpenID Connect"),
                tag("SAML", "SAML 2.0"),
                tag("Internal", "内部服务接口"),
                tag("Meta", "健康检查与文档")));
        doc.put("components", Map.of(
                "securitySchemes", Map.of(
                        "bearerAuth", Map.of("type", "http", "scheme", "bearer", "bearerFormat", "JWT"),
                        "internalToken", Map.of("type", "apiKey", "in", "header", "name", "x-internal-token")),
                "schemas", Map.of(
                        "Envelope", Map.of("type", "object", "properties", Map.of(
                                "code", Map.of("type", "string", "example", "ok"),
                                "data", Map.of())),
                        "Error", Map.of("type", "object", "properties", Map.of(
                                "code", Map.of("type", "string", "example", "bad_request"),
                                "message", Map.of("type", "string"),
                                "details", Map.of())))));
        doc.put("paths", paths());
        return doc;
    }

    @GetMapping(value = "/docs", produces = MediaType.TEXT_HTML_VALUE)
    public String docs() {
        return """
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                  <meta charset="utf-8"/>
                  <meta name="viewport" content="width=device-width, initial-scale=1"/>
                  <title>Auth Center API</title>
                  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
                  <style>body{margin:0;background:#fafafa}#swagger-ui{max-width:1200px;margin:0 auto}</style>
                </head>
                <body>
                  <div id="swagger-ui"></div>
                  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
                  <script>
                    window.ui = SwaggerUIBundle({
                      url: '/openapi.json',
                      dom_id: '#swagger-ui',
                      deepLinking: true,
                      displayRequestDuration: true,
                      persistAuthorization: true
                    });
                  </script>
                </body>
                </html>
                """;
    }

    private Map<String, Object> tag(String name, String description) {
        return Map.of("name", name, "description", description);
    }

    private Map<String, Object> paths() {
        Map<String, Object> paths = new LinkedHashMap<>();

        List<Route> routes = new ArrayList<>();
        String auth = "/api/v1/auth";
        routes.add(new Route("post", auth + "/register", "Auth", "注册身份"));
        routes.add(new Route("post", auth + "/login", "Auth", "密码登录"));
        routes.add(new Route("post", auth + "/login/otp", "Auth", "验证码登录"));
        routes.add(new Route("post", auth + "/login/otp/request", "Auth", "请求登录验证码"));
        routes.add(new Route("post", auth + "/logout", "Auth", "登出当前会话"));
        routes.add(new Route("post", auth + "/refresh", "Auth", "刷新令牌"));
        routes.add(new Route("get", auth + "/me", "Auth", "当前身份"));
        routes.add(new Route("patch", auth + "/me", "Auth", "更新当前身份资料"));
        routes.add(new Route("post", auth + "/password/change", "Auth", "修改密码"));
        routes.add(new Route("post", auth + "/password/forgot", "Auth", "发起忘记密码"));
        routes.add(new Route("post", auth + "/password/reset", "Auth", "重置密码"));
        routes.add(new Route("post", auth + "/email/verify", "Auth", "确认邮箱验证码"));
        routes.add(new Route("post", auth + "/email/verify/request", "Auth", "请求邮箱验证码"));
        routes.add(new Route("post", auth + "/phone/verify", "Auth", "确认手机验证码"));
        routes.add(new Route("post", auth + "/phone/verify/request", "Auth", "请求手机验证码"));
        routes.add(new Route("post", auth + "/contact/change", "Auth", "确认联系方式变更"));
        routes.add(new Route("post", auth + "/contact/change/request", "Auth", "请求联系方式变更"));
        routes.add(new Route("get", auth + "/login-history", "Auth", "登录历史"));
        routes.add(new Route("get", auth + "/login-anomalies", "Auth", "异常登录检测"));
        routes.add(new Route("get", auth + "/consents", "Auth", "授权记录"));
        routes.add(new Route("delete", auth + "/consents/{clientId}", "Auth", "撤销授权"));
        routes.add(new Route("get", auth + "/sessions", "Auth", "会话与设备列表"));
        routes.add(new Route("delete", auth + "/sessions/{id}", "Auth", "撤销指定会话"));
        routes.add(new Route("put", auth + "/sessions/{id}/device", "Auth", "重命名设备"));
        routes.add(new Route("delete", auth + "/sessions/devices/{deviceId}", "Auth", "撤销指定设备"));
        routes.add(new Route("get", auth + "/mfa", "MFA", "MFA 状态"));
        routes.add(new Route("delete", auth + "/mfa/factors/{id}", "MFA", "解绑 MFA 因子"));
        routes.add(new Route("post", auth + "/mfa/recovery-codes", "MFA", "重新生成恢复码"));
        routes.add(new Route("post", auth + "/mfa/totp/start", "MFA", "开始绑定 TOTP"));
        routes.add(new Route("post", auth + "/mfa/totp/confirm", "MFA", "确认绑定 TOTP"));
        routes.add(new Route("post", auth + "/mfa/verify", "MFA", "MFA 二次验证"));
        routes.add(new Route("post", auth + "/mfa/webauthn/register/start", "MFA", "开始注册 WebAuthn"));
        routes.add(new Route("post", auth + "/mfa/webauthn/register/finish", "MFA", "完成注册 WebAuthn"));
        routes.add(new Route("post", auth + "/mfa/webauthn/verify/start", "MFA", "开始 WebAuthn 断言"));
        routes.add(new Route("post", auth + "/mfa/webauthn/verify/finish", "MFA", "完成 WebAuthn 断言"));
        routes.add(new Route("get", auth + "/federated/links", "Federation", "第三方账号绑定列表"));
        routes.add(new Route("delete", auth + "/federated/links/{provider}", "Federation", "解绑第三方账号"));
        routes.add(new Route("get", auth + "/federated/{provider}/start", "Federation", "发起第三方登录"));
        routes.add(new Route("get", auth + "/federated/{provider}/callback", "Federation", "第三方回调（GET）"));
        routes.add(new Route("post", auth + "/federated/{provider}/callback", "Federation", "第三方回调（POST）"));

        String authz = "/api/v1/authz";
        routes.add(new Route("get", authz + "/me", "Authz", "当前身份授权信息"));
        routes.add(new Route("get", authz + "/me/permissions", "Authz", "当前身份权限"));
        routes.add(new Route("get", authz + "/me/menus", "Authz", "当前身份菜单树"));
        routes.add(new Route("get", authz + "/me/buttons", "Authz", "当前身份按钮权限"));
        routes.add(new Route("get", authz + "/me/apis", "Authz", "当前身份 API 权限"));
        routes.add(new Route("get", authz + "/me/data-scope", "Authz", "当前身份数据范围"));
        routes.add(new Route("post", authz + "/check", "Authz", "单次授权检查"));
        routes.add(new Route("post", authz + "/batch-check", "Authz", "批量授权检查"));

        String admin = "/api/v1/admin";
        routes.add(new Route("get", admin + "/identities", "Admin", "身份列表"));
        routes.add(new Route("post", admin + "/identities", "Admin", "创建身份"));
        routes.add(new Route("get", admin + "/identities/{id}", "Admin", "身份详情"));
        routes.add(new Route("patch", admin + "/identities/{id}", "Admin", "更新身份"));
        routes.add(new Route("put", admin + "/identities/{id}/status", "Admin", "变更身份状态"));
        routes.add(new Route("get", admin + "/identities/{id}/roles", "Admin", "身份角色"));
        routes.add(new Route("post", admin + "/identities/{id}/roles", "Admin", "授予身份角色"));
        routes.add(new Route("delete", admin + "/identities/{id}/roles/{roleId}", "Admin", "回收身份角色"));
        routes.add(new Route("get", admin + "/identities/{id}/permissions", "Admin", "身份直接授权"));
        routes.add(new Route("post", admin + "/identities/{id}/permissions", "Admin", "新增身份直接授权"));
        routes.add(new Route("delete", admin + "/identities/{id}/permissions/{permissionId}", "Admin", "回收身份直接授权"));
        routes.add(new Route("post", admin + "/identities/{id}/mfa/reset", "Admin", "重置身份 MFA"));
        routes.add(new Route("get", admin + "/roles", "Admin", "角色列表"));
        routes.add(new Route("post", admin + "/roles", "Admin", "创建角色"));
        routes.add(new Route("get", admin + "/roles/{id}", "Admin", "角色详情"));
        routes.add(new Route("patch", admin + "/roles/{id}", "Admin", "更新角色"));
        routes.add(new Route("delete", admin + "/roles/{id}", "Admin", "删除角色"));
        routes.add(new Route("put", admin + "/roles/{id}/permissions", "Admin", "设置角色权限"));
        routes.add(new Route("post", admin + "/roles/{id}/assign", "Admin", "批量分配角色"));
        routes.add(new Route("get", admin + "/roles/{id}/members", "Admin", "角色成员"));
        routes.add(new Route("get", admin + "/permissions", "Admin", "权限列表"));
        routes.add(new Route("get", admin + "/permissions/tree", "Admin", "权限树"));
        routes.add(new Route("post", admin + "/permissions", "Admin", "创建权限"));
        routes.add(new Route("get", admin + "/permissions/{id}", "Admin", "权限详情"));
        routes.add(new Route("patch", admin + "/permissions/{id}", "Admin", "更新权限"));
        routes.add(new Route("delete", admin + "/permissions/{id}", "Admin", "删除权限"));
        routes.add(new Route("get", admin + "/policies", "Admin", "授权策略列表"));
        routes.add(new Route("post", admin + "/policies", "Admin", "创建授权策略"));
        routes.add(new Route("get", admin + "/policies/{id}", "Admin", "授权策略详情"));
        routes.add(new Route("patch", admin + "/policies/{id}", "Admin", "更新授权策略"));
        routes.add(new Route("delete", admin + "/policies/{id}", "Admin", "删除授权策略"));
        routes.add(new Route("get", admin + "/resource-relations", "Admin", "资源关系列表"));
        routes.add(new Route("post", admin + "/resource-relations", "Admin", "创建资源关系"));
        routes.add(new Route("delete", admin + "/resource-relations/{id}", "Admin", "删除资源关系"));
        routes.add(new Route("get", admin + "/menus", "Admin", "菜单列表"));
        routes.add(new Route("post", admin + "/menus", "Admin", "创建菜单"));
        routes.add(new Route("patch", admin + "/menus/{id}", "Admin", "更新菜单"));
        routes.add(new Route("delete", admin + "/menus/{id}", "Admin", "删除菜单"));
        routes.add(new Route("get", admin + "/buttons", "Admin", "按钮列表"));
        routes.add(new Route("post", admin + "/buttons", "Admin", "创建按钮"));
        routes.add(new Route("patch", admin + "/buttons/{id}", "Admin", "更新按钮"));
        routes.add(new Route("delete", admin + "/buttons/{id}", "Admin", "删除按钮"));
        routes.add(new Route("get", admin + "/api-resources", "Admin", "API 资源列表"));
        routes.add(new Route("post", admin + "/api-resources", "Admin", "创建 API 资源"));
        routes.add(new Route("patch", admin + "/api-resources/{id}", "Admin", "更新 API 资源"));
        routes.add(new Route("delete", admin + "/api-resources/{id}", "Admin", "删除 API 资源"));
        routes.add(new Route("get", admin + "/data-permissions", "Admin", "数据权限列表"));
        routes.add(new Route("post", admin + "/data-permissions", "Admin", "创建数据权限"));
        routes.add(new Route("patch", admin + "/data-permissions/{id}", "Admin", "更新数据权限"));
        routes.add(new Route("delete", admin + "/data-permissions/{id}", "Admin", "删除数据权限"));
        routes.add(new Route("get", admin + "/tenants", "Admin", "租户列表"));
        routes.add(new Route("post", admin + "/tenants", "Admin", "创建租户"));
        routes.add(new Route("put", admin + "/tenants/{id}/status", "Admin", "变更租户状态"));
        routes.add(new Route("get", admin + "/audit-logs", "Admin", "安全审计日志"));
        routes.add(new Route("get", admin + "/signing-keys", "Admin", "签名密钥列表"));
        routes.add(new Route("post", admin + "/signing-keys/rotate", "Admin", "轮换签名密钥"));
        routes.add(new Route("get", admin + "/oauth/clients", "Admin", "OAuth 客户端列表"));
        routes.add(new Route("post", admin + "/oauth/clients", "Admin", "创建 OAuth 客户端"));
        routes.add(new Route("get", admin + "/oauth/clients/{clientId}", "Admin", "OAuth 客户端详情"));
        routes.add(new Route("patch", admin + "/oauth/clients/{clientId}", "Admin", "更新 OAuth 客户端"));
        routes.add(new Route("delete", admin + "/oauth/clients/{clientId}", "Admin", "删除 OAuth 客户端"));
        routes.add(new Route("post", admin + "/oauth/clients/{clientId}/secret", "Admin", "轮换客户端密钥"));
        routes.add(new Route("put", admin + "/oauth/clients/{clientId}/status", "Admin", "变更客户端状态"));
        routes.add(new Route("get", admin + "/oauth/scopes", "Admin", "Scope 列表"));
        routes.add(new Route("post", admin + "/oauth/scopes", "Admin", "创建 Scope"));
        routes.add(new Route("delete", admin + "/oauth/scopes/{name}", "Admin", "删除 Scope"));
        routes.add(new Route("get", admin + "/identity-providers", "Admin", "身份提供商列表"));
        routes.add(new Route("post", admin + "/identity-providers", "Admin", "创建身份提供商"));
        routes.add(new Route("get", admin + "/identity-providers/{code}", "Admin", "身份提供商详情"));
        routes.add(new Route("patch", admin + "/identity-providers/{code}", "Admin", "更新身份提供商"));
        routes.add(new Route("delete", admin + "/identity-providers/{code}", "Admin", "删除身份提供商"));
        routes.add(new Route("get", admin + "/saml/idp", "Admin", "SAML IdP 配置"));
        routes.add(new Route("put", admin + "/saml/idp", "Admin", "更新 SAML IdP 配置"));
        routes.add(new Route("post", admin + "/saml/idp/rotate-certificate", "Admin", "轮换 SAML 签名证书"));
        routes.add(new Route("get", admin + "/saml/sps", "Admin", "SAML SP 列表"));
        routes.add(new Route("post", admin + "/saml/sps", "Admin", "注册 SAML SP"));
        routes.add(new Route("delete", admin + "/saml/sps/{code}", "Admin", "删除 SAML SP"));

        routes.add(new Route("get", "/oauth2/authorize", "OAuth", "授权端点"));
        routes.add(new Route("post", "/oauth2/authorize/consent", "OAuth", "提交授权同意"));
        routes.add(new Route("post", "/oauth2/token", "OAuth", "令牌端点"));
        routes.add(new Route("get", "/oauth2/jwks", "OAuth", "JWKS"));
        routes.add(new Route("get", "/oauth2/.well-known/jwks.json", "OAuth", "JWKS（兼容路径）"));
        routes.add(new Route("get", "/oauth2/userinfo", "OAuth", "UserInfo 端点"));
        routes.add(new Route("post", "/oauth2/introspect", "OAuth", "令牌内省"));
        routes.add(new Route("post", "/oauth2/revoke", "OAuth", "令牌撤销"));
        routes.add(new Route("get", "/oauth2/logout", "OAuth", "End Session 端点"));
        routes.add(new Route("post", "/oauth2/logout", "OAuth", "End Session 端点（POST）"));
        routes.add(new Route("get", "/oauth2/.well-known/openid-configuration", "OAuth", "OIDC Discovery"));
        routes.add(new Route("get", "/oauth2/.well-known/oauth-authorization-server", "OAuth", "OAuth AS Metadata"));

        routes.add(new Route("get", "/saml/metadata", "SAML", "IdP Metadata"));
        routes.add(new Route("get", "/saml/sso", "SAML", "SAML SSO 端点"));
        routes.add(new Route("get", "/saml/slo", "SAML", "SAML SLO 端点"));
        routes.add(new Route("post", "/saml/slo", "SAML", "SAML SLO 端点（POST）"));
        routes.add(new Route("post", "/api/v1/auth/federated/saml/acs", "SAML", "SAML ACS 端点"));

        String internal = "/api/v1/internal";
        routes.add(new Route("get", internal + "/identities", "Internal", "内部身份查询"));
        routes.add(new Route("post", internal + "/identities", "Internal", "内部创建身份"));
        routes.add(new Route("get", internal + "/identities/{id}", "Internal", "内部身份详情"));
        routes.add(new Route("put", internal + "/identities/{id}/status", "Internal", "内部变更身份状态"));
        routes.add(new Route("post", internal + "/identities/{id}/sessions/revoke", "Internal", "撤销身份全部会话"));
        routes.add(new Route("post", internal + "/identities/{id}/contacts/request", "Internal", "请求联系方式验证"));
        routes.add(new Route("post", internal + "/identities/{id}/contacts/confirm", "Internal", "确认联系方式验证"));
        routes.add(new Route("get", internal + "/identities/{id}/contacts", "Internal", "身份联系方式"));
        routes.add(new Route("delete", internal + "/identities/{id}/contacts/{kind}", "Internal", "移除身份联系方式"));
        routes.add(new Route("post", internal + "/authz/check", "Internal", "内部授权检查"));
        routes.add(new Route("post", internal + "/events", "Internal", "接收领域事件"));

        routes.add(new Route("get", "/health", "Meta", "健康检查"));
        routes.add(new Route("get", "/health/live", "Meta", "存活检查"));
        routes.add(new Route("get", "/live", "Meta", "存活检查"));
        routes.add(new Route("get", "/ready", "Meta", "就绪检查"));
        routes.add(new Route("get", "/health/ready", "Meta", "就绪检查"));
        routes.add(new Route("get", "/readiness", "Meta", "就绪检查"));
        routes.add(new Route("get", "/openapi.json", "Meta", "OpenAPI 描述"));
        routes.add(new Route("get", "/docs", "Meta", "Swagger UI"));

        for (Route route : routes) {
            @SuppressWarnings("unchecked")
            Map<String, Object> operations = (Map<String, Object>) paths.computeIfAbsent(route.path(), k -> new LinkedHashMap<>());
            Map<String, Object> operation = new LinkedHashMap<>();
            operation.put("tags", List.of(route.tag()));
            operation.put("summary", route.summary());
            operation.put("operationId", route.operationId());
            operation.put("responses", Map.of(
                    "200", Map.of("description", "成功"),
                    "400", Map.of("description", "请求不合法"),
                    "401", Map.of("description", "未认证"),
                    "403", Map.of("description", "无权限")));
            if (route.path().startsWith("/api/v1/admin")) {
                operation.put("security", List.of(Map.of("bearerAuth", List.of())));
            } else if (route.path().startsWith("/api/v1/internal")) {
                operation.put("security", List.of(Map.of("internalToken", List.of())));
            }
            operations.put(route.method(), operation);
        }
        return paths;
    }

    private record Route(String method, String path, String tag, String summary) {
        String operationId() {
            return method + path.replaceAll("[^A-Za-z0-9]+", "_");
        }
    }
}
