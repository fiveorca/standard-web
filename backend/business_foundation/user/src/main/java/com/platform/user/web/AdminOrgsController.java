package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.OrgService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminOrgsController {
    private final OrgService orgs;
    private final AuthClient authClient;
    private final RequestContext ctx;

    public AdminOrgsController(OrgService orgs, AuthClient authClient, RequestContext ctx) {
        this.orgs = orgs;
        this.authClient = authClient;
        this.ctx = ctx;
    }

    // ───────── 组织 ─────────

    @GetMapping("/organizations")
    public Map<String, Object> listOrganizations(@CurrentUser AuthContext auth,
                                                  @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(orgs.listOrganizations(auth.tenantId(), query));
    }

    @PostMapping("/organizations")
    public Map<String, Object> createOrganization(@CurrentUser AuthContext auth,
                                                   @RequestBody(required = false) Map<String, Object> body,
                                                   HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.createOrganization(auth.tenantId(), Body.of(body), auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/organizations/tree")
    public Map<String, Object> organizationTree(@CurrentUser AuthContext auth) {
        require(auth);
        return Api.ok(Map.of("items", orgs.organizationTree(auth.tenantId())));
    }

    @GetMapping("/organizations/{id}")
    public Map<String, Object> getOrganization(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(orgs.getOrganization(auth.tenantId(), ctx.id(id, "id")));
    }

    @PatchMapping("/organizations/{id}")
    public Map<String, Object> updateOrganization(@CurrentUser AuthContext auth, @PathVariable String id,
                                                   @RequestBody(required = false) Map<String, Object> body,
                                                   HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.updateOrganization(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/organizations/{id}")
    public Map<String, Object> deleteOrganization(@CurrentUser AuthContext auth, @PathVariable String id,
                                                   HttpServletRequest request) {
        require(auth);
        orgs.deleteOrganization(auth.tenantId(), ctx.id(id, "id"), auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("id", id));
    }

    @PutMapping("/organizations/{id}/leader")
    public Map<String, Object> setOrganizationLeader(@CurrentUser AuthContext auth, @PathVariable String id,
                                                      @RequestBody(required = false) Map<String, Object> body,
                                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.setOrganizationLeader(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/organizations/{id}/members")
    public Map<String, Object> organizationMembers(@CurrentUser AuthContext auth, @PathVariable String id,
                                                    @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(orgs.organizationMembers(auth.tenantId(), ctx.id(id, "id"), query));
    }

    @PostMapping("/organizations/{id}/members")
    public Map<String, Object> addOrganizationMember(@CurrentUser AuthContext auth, @PathVariable String id,
                                                      @RequestBody(required = false) Map<String, Object> body,
                                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.addOrganizationMember(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/organizations/{id}/members/{user_id}")
    public Map<String, Object> removeOrganizationMember(@CurrentUser AuthContext auth, @PathVariable String id,
                                                         @PathVariable String user_id,
                                                         HttpServletRequest request) {
        require(auth);
        orgs.removeOrganizationMember(auth.tenantId(), ctx.id(id, "id"), ctx.id(user_id, "user_id"),
                auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("organization_id", id, "user_id", user_id));
    }

    // ───────── 部门 ─────────

    @GetMapping("/departments")
    public Map<String, Object> listDepartments(@CurrentUser AuthContext auth,
                                                @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(orgs.listDepartments(auth.tenantId(), query));
    }

    @PostMapping("/departments")
    public Map<String, Object> createDepartment(@CurrentUser AuthContext auth,
                                                 @RequestBody(required = false) Map<String, Object> body,
                                                 HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.createDepartment(auth.tenantId(), Body.of(body), auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/departments/tree")
    public Map<String, Object> departmentTree(@CurrentUser AuthContext auth,
                                               @RequestParam Map<String, String> query) {
        require(auth);
        String orgId = query.get("organization_id");
        return Api.ok(Map.of("items", orgs.departmentTree(auth.tenantId(),
                orgId == null || orgId.isBlank() ? null : ctx.id(orgId, "organization_id"))));
    }

    @GetMapping("/departments/{id}")
    public Map<String, Object> getDepartment(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(orgs.getDepartment(auth.tenantId(), ctx.id(id, "id")));
    }

    @PatchMapping("/departments/{id}")
    public Map<String, Object> updateDepartment(@CurrentUser AuthContext auth, @PathVariable String id,
                                                 @RequestBody(required = false) Map<String, Object> body,
                                                 HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.updateDepartment(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/departments/{id}")
    public Map<String, Object> deleteDepartment(@CurrentUser AuthContext auth, @PathVariable String id,
                                                 HttpServletRequest request) {
        require(auth);
        orgs.deleteDepartment(auth.tenantId(), ctx.id(id, "id"), auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("id", id));
    }

    @PutMapping("/departments/{id}/leader")
    public Map<String, Object> setDepartmentLeader(@CurrentUser AuthContext auth, @PathVariable String id,
                                                    @RequestBody(required = false) Map<String, Object> body,
                                                    HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.setDepartmentLeader(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/departments/{id}/members")
    public Map<String, Object> departmentMembers(@CurrentUser AuthContext auth, @PathVariable String id,
                                                  @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(orgs.departmentMembers(auth.tenantId(), ctx.id(id, "id"), query));
    }

    @PostMapping("/departments/{id}/members")
    public Map<String, Object> addDepartmentMember(@CurrentUser AuthContext auth, @PathVariable String id,
                                                    @RequestBody(required = false) Map<String, Object> body,
                                                    HttpServletRequest request) {
        require(auth);
        return Api.ok(orgs.addDepartmentMember(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/departments/{id}/members/{user_id}")
    public Map<String, Object> removeDepartmentMember(@CurrentUser AuthContext auth, @PathVariable String id,
                                                       @PathVariable String user_id,
                                                       HttpServletRequest request) {
        require(auth);
        orgs.removeDepartmentMember(auth.tenantId(), ctx.id(id, "id"), ctx.id(user_id, "user_id"),
                auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("department_id", id, "user_id", user_id));
    }

    private void require(AuthContext auth) {
        authClient.requirePermission(auth, "identity:manage");
    }
}
