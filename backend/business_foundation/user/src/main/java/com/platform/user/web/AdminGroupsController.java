package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.GroupService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/groups")
public class AdminGroupsController {
    private final GroupService groups;
    private final AuthClient authClient;
    private final RequestContext ctx;

    public AdminGroupsController(GroupService groups, AuthClient authClient, RequestContext ctx) {
        this.groups = groups;
        this.authClient = authClient;
        this.ctx = ctx;
    }

    @GetMapping
    public Map<String, Object> list(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(groups.list(auth.tenantId(), query));
    }

    @PostMapping
    public Map<String, Object> create(@CurrentUser AuthContext auth,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(groups.create(auth.tenantId(), Body.of(body), auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/tree")
    public Map<String, Object> tree(@CurrentUser AuthContext auth) {
        require(auth);
        return Api.ok(Map.of("items", groups.tree(auth.tenantId())));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(groups.get(auth.tenantId(), ctx.id(id, "id")));
    }

    @PatchMapping("/{id}")
    public Map<String, Object> update(@CurrentUser AuthContext auth, @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(groups.update(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}")
    public Map<String, Object> delete(@CurrentUser AuthContext auth, @PathVariable String id,
                                      HttpServletRequest request) {
        require(auth);
        groups.delete(auth.tenantId(), ctx.id(id, "id"), auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("id", id));
    }

    @GetMapping("/{id}/members")
    public Map<String, Object> members(@CurrentUser AuthContext auth, @PathVariable String id,
                                       @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(groups.members(auth.tenantId(), ctx.id(id, "id"), query));
    }

    @PostMapping("/{id}/members")
    public Map<String, Object> addMembers(@CurrentUser AuthContext auth, @PathVariable String id,
                                          @RequestBody(required = false) Map<String, Object> body,
                                          HttpServletRequest request) {
        require(auth);
        return Api.ok(groups.addMembers(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}/members/{user_id}")
    public Map<String, Object> removeMember(@CurrentUser AuthContext auth, @PathVariable String id,
                                            @PathVariable String user_id, HttpServletRequest request) {
        require(auth);
        groups.removeMember(auth.tenantId(), ctx.id(id, "id"), ctx.id(user_id, "user_id"),
                auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("group_id", id, "user_id", user_id));
    }

    @DeleteMapping("/{id}/members")
    public Map<String, Object> removeMembers(@CurrentUser AuthContext auth, @PathVariable String id,
                                             @RequestBody(required = false) Map<String, Object> body,
                                             HttpServletRequest request) {
        require(auth);
        groups.removeMembers(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("group_id", id));
    }

    private void require(AuthContext auth) {
        authClient.requirePermission(auth, "identity:manage");
    }
}
