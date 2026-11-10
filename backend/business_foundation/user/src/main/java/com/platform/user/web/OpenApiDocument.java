package com.platform.user.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class OpenApiDocument {
    private OpenApiDocument() {
    }

    public static Map<String, Object> build() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("openapi", "3.0.3");
        root.put("info", Map.of(
                "title", "User Center API",
                "version", "1.0.0",
                "description", "平台用户中心：用户自助、管理端、扩展属性、分组、组织/部门、注册审核、审计与内部接口。"));
        root.put("servers", List.of(Map.of("url", "/", "description", "当前服务")));

        Map<String, Object> paths = new LinkedHashMap<>();
        // 公共
        op(paths, "/health", "get", "健康检查");
        op(paths, "/live", "get", "存活检查");
        op(paths, "/ready", "get", "就绪检查（数据库）");
        op(paths, "/readyz", "get", "就绪检查别名");
        op(paths, "/openapi.json", "get", "OpenAPI 文档");
        op(paths, "/docs", "get", "Swagger UI");

        // 用户自助
        op(paths, "/api/v1/users/me", "get", "获取当前用户详情");
        op(paths, "/api/v1/users/me", "patch", "更新当前用户基础资料");
        op(paths, "/api/v1/users/me/profile", "get", "获取当前用户资料");
        op(paths, "/api/v1/users/me/profile", "patch", "更新当前用户资料");
        op(paths, "/api/v1/users/me/avatar", "post", "更新头像");
        op(paths, "/api/v1/users/me/nickname", "put", "更新昵称");
        op(paths, "/api/v1/users/me/contacts", "get", "列出联系方式");
        op(paths, "/api/v1/users/me/contacts", "post", "发起联系方式变更");
        op(paths, "/api/v1/users/me/contacts", "delete", "解绑全部联系方式");
        op(paths, "/api/v1/users/me/contacts/request", "post", "请求联系方式验证码");
        op(paths, "/api/v1/users/me/contacts/confirm", "post", "确认联系方式验证码");
        op(paths, "/api/v1/users/me/contacts/{kind}", "delete", "解绑指定联系方式");
        op(paths, "/api/v1/users/me/attributes", "get", "列出当前用户属性值");
        op(paths, "/api/v1/users/me/attributes", "put", "全量替换当前用户属性值");
        op(paths, "/api/v1/users/me/groups", "get", "当前用户所属分组");
        op(paths, "/api/v1/users/me/organizations", "get", "当前用户组织/部门关系");
        op(paths, "/api/v1/users/me/history", "get", "当前用户组织变更历史");
        op(paths, "/api/v1/users/me/links", "get", "当前用户第三方绑定");
        op(paths, "/api/v1/users/me/links/{provider}", "delete", "解绑第三方账号");
        op(paths, "/api/v1/users/me/registration", "get", "当前用户注册记录");
        op(paths, "/api/v1/registrations", "post", "匿名提交注册申请");

        // 管理端用户
        op(paths, "/api/v1/admin/users", "get", "分页查询用户");
        op(paths, "/api/v1/admin/users", "post", "创建用户");
        op(paths, "/api/v1/admin/users/batch", "post", "批量创建用户");
        op(paths, "/api/v1/admin/users/batch", "patch", "批量操作用户");
        op(paths, "/api/v1/admin/users/import", "post", "导入用户（JSON/CSV）");
        op(paths, "/api/v1/admin/users/export", "get", "导出用户（JSON/CSV）");
        op(paths, "/api/v1/admin/users/{id}", "get", "获取用户详情");
        op(paths, "/api/v1/admin/users/{id}", "patch", "更新用户");
        op(paths, "/api/v1/admin/users/{id}", "delete", "软删除用户");
        op(paths, "/api/v1/admin/users/{id}/profile", "get", "获取用户资料");
        op(paths, "/api/v1/admin/users/{id}/profile", "patch", "更新用户资料");
        op(paths, "/api/v1/admin/users/{id}/restore", "post", "恢复用户");
        op(paths, "/api/v1/admin/users/{id}/status", "put", "变更用户状态");
        op(paths, "/api/v1/admin/users/{id}/tags", "get", "列出用户标签");
        op(paths, "/api/v1/admin/users/{id}/tags", "put", "替换用户标签");
        op(paths, "/api/v1/admin/users/{id}/tags", "delete", "清空用户标签");
        op(paths, "/api/v1/admin/users/{id}/contacts", "get", "列出用户联系方式");
        op(paths, "/api/v1/admin/users/{id}/contacts", "post", "新增用户联系方式");
        op(paths, "/api/v1/admin/users/{id}/contacts/{kind}", "post", "设置用户联系方式");
        op(paths, "/api/v1/admin/users/{id}/contacts/{kind}", "delete", "删除用户联系方式");
        op(paths, "/api/v1/admin/users/{id}/attributes", "get", "列出用户属性值");
        op(paths, "/api/v1/admin/users/{id}/attributes", "put", "替换用户属性值");
        op(paths, "/api/v1/admin/users/{id}/groups", "get", "用户所属分组");
        op(paths, "/api/v1/admin/users/{id}/memberships", "get", "用户组织/部门关系");
        op(paths, "/api/v1/admin/users/{id}/history", "get", "用户组织变更历史");
        op(paths, "/api/v1/admin/users/{id}/status-history", "get", "用户状态历史");
        op(paths, "/api/v1/admin/users/{id}/registration", "get", "用户注册记录");
        op(paths, "/api/v1/admin/users/{id}/links", "get", "用户第三方绑定");
        op(paths, "/api/v1/admin/users/{id}/links/{provider}", "post", "新增用户第三方绑定");
        op(paths, "/api/v1/admin/users/{id}/links/{provider}", "delete", "删除用户第三方绑定");
        op(paths, "/api/v1/admin/users/{id}/transfer", "post", "调动用户组织/部门");

        // 扩展属性
        op(paths, "/api/v1/admin/attributes", "get", "分页查询属性定义");
        op(paths, "/api/v1/admin/attributes", "post", "创建属性定义");
        op(paths, "/api/v1/admin/attributes/{id}", "get", "获取属性定义");
        op(paths, "/api/v1/admin/attributes/{id}", "patch", "更新属性定义");
        op(paths, "/api/v1/admin/attributes/{id}", "delete", "删除属性定义");

        // 分组
        op(paths, "/api/v1/admin/groups", "get", "分页查询分组");
        op(paths, "/api/v1/admin/groups", "post", "创建分组");
        op(paths, "/api/v1/admin/groups/tree", "get", "分组树");
        op(paths, "/api/v1/admin/groups/{id}", "get", "获取分组");
        op(paths, "/api/v1/admin/groups/{id}", "patch", "更新分组");
        op(paths, "/api/v1/admin/groups/{id}", "delete", "删除分组");
        op(paths, "/api/v1/admin/groups/{id}/members", "get", "分组及成员");
        op(paths, "/api/v1/admin/groups/{id}/members", "post", "添加分组成员");
        op(paths, "/api/v1/admin/groups/{id}/members/{user_id}", "delete", "移除分组成员");

        // 组织
        op(paths, "/api/v1/admin/organizations", "get", "分页查询组织");
        op(paths, "/api/v1/admin/organizations", "post", "创建组织");
        op(paths, "/api/v1/admin/organizations/tree", "get", "组织树");
        op(paths, "/api/v1/admin/organizations/{id}", "get", "获取组织");
        op(paths, "/api/v1/admin/organizations/{id}", "patch", "更新组织");
        op(paths, "/api/v1/admin/organizations/{id}", "delete", "删除组织");
        op(paths, "/api/v1/admin/organizations/{id}/leader", "put", "设置组织负责人");
        op(paths, "/api/v1/admin/organizations/{id}/members", "get", "组织成员");
        op(paths, "/api/v1/admin/organizations/{id}/members", "post", "添加组织成员");
        op(paths, "/api/v1/admin/organizations/{id}/members/{user_id}", "delete", "移除组织成员");

        // 部门
        op(paths, "/api/v1/admin/departments", "get", "分页查询部门");
        op(paths, "/api/v1/admin/departments", "post", "创建部门");
        op(paths, "/api/v1/admin/departments/tree", "get", "部门树");
        op(paths, "/api/v1/admin/departments/{id}", "get", "获取部门");
        op(paths, "/api/v1/admin/departments/{id}", "patch", "更新部门");
        op(paths, "/api/v1/admin/departments/{id}", "delete", "删除部门");
        op(paths, "/api/v1/admin/departments/{id}/leader", "put", "设置部门负责人");
        op(paths, "/api/v1/admin/departments/{id}/members", "get", "部门成员");
        op(paths, "/api/v1/admin/departments/{id}/members", "post", "添加部门成员");
        op(paths, "/api/v1/admin/departments/{id}/members/{user_id}", "delete", "移除部门成员");

        // 注册审核
        op(paths, "/api/v1/admin/registrations", "get", "分页查询注册申请");
        op(paths, "/api/v1/admin/registrations/{id}", "get", "获取注册申请");
        op(paths, "/api/v1/admin/registrations/{id}/review", "post", "审核注册申请");

        // 审计
        op(paths, "/api/v1/admin/audit-logs", "get", "查询审计日志");

        // 内部
        op(paths, "/api/v1/internal/users/ensure", "post", "按 identity_id 幂等创建用户");
        op(paths, "/api/v1/internal/users/{id}", "get", "内部获取用户");
        op(paths, "/api/v1/internal/users/{id}/status", "put", "内部更新用户状态");
        op(paths, "/api/v1/internal/users/{id}/contacts", "get", "内部获取用户联系方式");
        op(paths, "/api/v1/internal/events", "post", "接收认证中心事件（inbox 幂等）");

        root.put("paths", paths);
        root.put("components", Map.of(
                "securitySchemes", Map.of(
                        "bearerAuth", Map.of("type", "http", "scheme", "bearer", "bearerFormat", "JWT"),
                        "internalToken", Map.of("type", "apiKey", "in", "header", "name", "x-internal-token"))));
        return root;
    }

    private static void op(Map<String, Object> paths, String path, String method, String summary) {
        @SuppressWarnings("unchecked")
        Map<String, Object> item = (Map<String, Object>) paths.computeIfAbsent(path, key -> new LinkedHashMap<>());
        Map<String, Object> operation = new LinkedHashMap<>();
        operation.put("summary", summary);
        operation.put("operationId", method + path.replace("/", "_").replace("{", "").replace("}", ""));
        operation.put("responses", Map.of("200", Map.of("description", "成功")));
        item.put(method, operation);
    }
}
