package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.Csv;
import com.platform.user.common.CurrentUser;
import com.platform.user.common.Json;
import com.platform.user.service.AttributeService;
import com.platform.user.service.ContactService;
import com.platform.user.service.GroupService;
import com.platform.user.service.OrgService;
import com.platform.user.service.RegistrationService;
import com.platform.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/users")
public class AdminUsersController {
    private static final String PERMISSION = "identity:manage";

    private final UserService users;
    private final ContactService contacts;
    private final AttributeService attributes;
    private final GroupService groups;
    private final OrgService orgs;
    private final RegistrationService registrations;
    private final AuthClient authClient;
    private final RequestContext ctx;

    public AdminUsersController(UserService users, ContactService contacts, AttributeService attributes,
                                GroupService groups, OrgService orgs, RegistrationService registrations,
                                AuthClient authClient, RequestContext ctx) {
        this.users = users;
        this.contacts = contacts;
        this.attributes = attributes;
        this.groups = groups;
        this.orgs = orgs;
        this.registrations = registrations;
        this.authClient = authClient;
        this.ctx = ctx;
    }

    @GetMapping
    public Map<String, Object> list(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(users.list(auth.tenantId(), query));
    }

    @PostMapping
    public Map<String, Object> create(@CurrentUser AuthContext auth,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(users.create(auth.tenantId(), Body.of(body), auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/batch")
    public Map<String, Object> batchCreate(@CurrentUser AuthContext auth,
                                           @RequestBody(required = false) Object body,
                                           HttpServletRequest request) {
        require(auth);
        List<Object> items = items(body);
        return Api.ok(users.batchCreate(auth.tenantId(), items, auth.identityId(), ctx.meta(request)));
    }

    @PatchMapping("/batch")
    public Map<String, Object> batchUpdate(@CurrentUser AuthContext auth,
                                           @RequestBody(required = false) Object body,
                                           HttpServletRequest request) {
        require(auth);
        Object normalized = body instanceof List<?> list ? Map.of("items", list) : body;
        return Api.ok(users.batchUpdate(auth.tenantId(), normalized, auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/import")
    public Map<String, Object> importUsers(@CurrentUser AuthContext auth,
                                           @RequestBody(required = false) Map<String, Object> body,
                                           HttpServletRequest request) {
        require(auth);
        return Api.ok(users.importUsers(auth.tenantId(), Body.of(body), auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/export")
    public ResponseEntity<Object> export(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        require(auth);
        String format = query.getOrDefault("format", "csv").toLowerCase();
        List<Map<String, Object>> rows = users.exportUsers(auth.tenantId(), query);
        if ("json".equals(format)) {
            return RequestContext.jsonText(rows);
        }
        List<String> columns = List.of("id", "tenant_id", "username", "email", "email_verified", "phone",
                "phone_verified", "display_name", "avatar_url", "status", "source", "remark",
                "registered_at", "last_login_at", "created_at", "updated_at", "tags");
        StringBuilder out = new StringBuilder();
        out.append(Csv.line(new ArrayList<>(columns))).append('\n');
        for (Map<String, Object> row : rows) {
            List<Object> values = new ArrayList<>();
            for (String column : columns) {
                Object value = row.get(column);
                if ("tags".equals(column) && value instanceof List<?> list) {
                    values.add(String.join(";", list.stream().map(String::valueOf).toList()));
                } else {
                    values.add(value == null ? "" : value);
                }
            }
            out.append(Csv.line(values)).append('\n');
        }
        return RequestContext.csv(out.toString(), "users.csv");
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(users.detail(auth.tenantId(), ctx.id(id, "id"), false));
    }

    @PatchMapping("/{id}")
    @PutMapping("/{id}")
    public Map<String, Object> update(@CurrentUser AuthContext auth, @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      @RequestHeader(value = "If-Match", required = false) String ifMatch,
                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(users.update(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                ctx.version(ifMatch, body), auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}")
    public Map<String, Object> delete(@CurrentUser AuthContext auth, @PathVariable String id,
                                      HttpServletRequest request) {
        require(auth);
        UUID userId = ctx.id(id, "id");
        users.delete(auth.tenantId(), userId, auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("id", userId.toString(), "status", "deleted"));
    }

    @GetMapping("/{id}/profile")
    public Map<String, Object> profile(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(users.profile(auth.tenantId(), ctx.id(id, "id")));
    }

    @PatchMapping("/{id}/profile")
    @PutMapping("/{id}/profile")
    public Map<String, Object> updateProfile(@CurrentUser AuthContext auth, @PathVariable String id,
                                             @RequestBody(required = false) Map<String, Object> body,
                                             HttpServletRequest request) {
        require(auth);
        return Api.ok(users.updateProfile(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/{id}/restore")
    public Map<String, Object> restore(@CurrentUser AuthContext auth, @PathVariable String id,
                                       HttpServletRequest request) {
        require(auth);
        return Api.ok(users.restore(auth.tenantId(), ctx.id(id, "id"), auth.identityId(), ctx.meta(request)));
    }

    @PutMapping("/{id}/status")
    @PostMapping("/{id}/status")
    public Map<String, Object> status(@CurrentUser AuthContext auth, @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        require(auth);
        return Api.ok(users.changeStatus(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/{id}/tags")
    public Map<String, Object> tags(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", users.tags(auth.tenantId(), ctx.id(id, "id"))));
    }

    @PutMapping("/{id}/tags")
    @PostMapping("/{id}/tags")
    public Map<String, Object> setTags(@CurrentUser AuthContext auth, @PathVariable String id,
                                       @RequestBody(required = false) Map<String, Object> body,
                                       HttpServletRequest request) {
        require(auth);
        Body input = Body.of(body);
        List<String> values = input.has("tags") ? input.strings("tags")
                : input.has("items") ? input.strings("items") : List.of();
        return Api.ok(Map.of("items", users.setTags(auth.tenantId(), ctx.id(id, "id"),
                Body.of(Map.of("tags", values)), auth.identityId(), ctx.meta(request))));
    }

    @DeleteMapping("/{id}/tags")
    public Map<String, Object> clearTags(@CurrentUser AuthContext auth, @PathVariable String id,
                                         HttpServletRequest request) {
        require(auth);
        return Api.ok(Map.of("items", users.setTags(auth.tenantId(), ctx.id(id, "id"),
                Body.of(Map.of("tags", List.of())), auth.identityId(), ctx.meta(request))));
    }

    @GetMapping("/{id}/contacts")
    public Map<String, Object> listContacts(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", contacts.list(auth.tenantId(), ctx.id(id, "id"), false)));
    }

    @PostMapping("/{id}/contacts")
    public Map<String, Object> addContact(@CurrentUser AuthContext auth, @PathVariable String id,
                                          @RequestBody(required = false) Map<String, Object> body,
                                          HttpServletRequest request) {
        require(auth);
        Body input = Body.of(body);
        String kind = input.required("kind", "联系方式类型");
        return Api.ok(contacts.adminSet(auth.tenantId(), ctx.id(id, "id"), kind, input,
                auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/{id}/contacts/{kind}")
    @PutMapping("/{id}/contacts/{kind}")
    public Map<String, Object> setContact(@CurrentUser AuthContext auth, @PathVariable String id,
                                          @PathVariable String kind,
                                          @RequestBody(required = false) Map<String, Object> body,
                                          HttpServletRequest request) {
        require(auth);
        return Api.ok(contacts.adminSet(auth.tenantId(), ctx.id(id, "id"), kind, Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}/contacts/{kind}")
    public Map<String, Object> removeContact(@CurrentUser AuthContext auth, @PathVariable String id,
                                             @PathVariable String kind, HttpServletRequest request) {
        require(auth);
        UUID userId = ctx.id(id, "id");
        contacts.adminRemove(auth.tenantId(), userId, kind, auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("items", contacts.list(auth.tenantId(), userId, false)));
    }

    @GetMapping("/{id}/attributes")
    public Map<String, Object> attributes(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", attributes.listValues(auth.tenantId(), ctx.id(id, "id"))));
    }

    @PutMapping("/{id}/attributes")
    public Map<String, Object> setAttributes(@CurrentUser AuthContext auth, @PathVariable String id,
                                             @RequestBody(required = false) Map<String, Object> body,
                                             HttpServletRequest request) {
        require(auth);
        Body input = Body.of(body);
        Map<String, Object> values = input.has("values") ? input.map("values") : input.map();
        return Api.ok(Map.of("items", attributes.setValues(auth.tenantId(), ctx.id(id, "id"), values,
                auth.identityId(), ctx.meta(request))));
    }

    @GetMapping("/{id}/groups")
    public Map<String, Object> groups(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", groups.userGroups(auth.tenantId(), ctx.id(id, "id"))));
    }

    @GetMapping("/{id}/memberships")
    public Map<String, Object> memberships(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", orgs.memberships(auth.tenantId(), ctx.id(id, "id"))));
    }

    @GetMapping("/{id}/history")
    public Map<String, Object> history(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", users.history(auth.tenantId(), ctx.id(id, "id"))));
    }

    @GetMapping("/{id}/status-history")
    public Map<String, Object> statusHistory(@CurrentUser AuthContext auth, @PathVariable String id,
                                             @RequestParam Map<String, String> query) {
        require(auth);
        return Api.ok(users.statusHistory(auth.tenantId(), ctx.id(id, "id"), query));
    }

    @GetMapping("/{id}/registration")
    public Map<String, Object> registration(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(registrations.userRegistration(auth.tenantId(), ctx.id(id, "id")));
    }

    @GetMapping("/{id}/links")
    public Map<String, Object> links(@CurrentUser AuthContext auth, @PathVariable String id) {
        require(auth);
        return Api.ok(Map.of("items", users.links(auth.tenantId(), ctx.id(id, "id"))));
    }

    @PostMapping("/{id}/links")
    public Map<String, Object> addLink(@CurrentUser AuthContext auth, @PathVariable String id,
                                       @RequestBody(required = false) Map<String, Object> body,
                                       HttpServletRequest request) {
        require(auth);
        Body input = Body.of(body);
        return Api.ok(users.addLink(auth.tenantId(), ctx.id(id, "id"), input.required("provider", "服务商"),
                input, auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/{id}/links/{provider}")
    public Map<String, Object> addLinkProvider(@CurrentUser AuthContext auth, @PathVariable String id,
                                               @PathVariable String provider,
                                               @RequestBody(required = false) Map<String, Object> body,
                                               HttpServletRequest request) {
        require(auth);
        return Api.ok(users.addLink(auth.tenantId(), ctx.id(id, "id"), provider, Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}/links/{provider}")
    public Map<String, Object> removeLink(@CurrentUser AuthContext auth, @PathVariable String id,
                                          @PathVariable String provider, HttpServletRequest request) {
        require(auth);
        UUID userId = ctx.id(id, "id");
        users.removeLink(auth.tenantId(), userId, provider, auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("items", users.links(auth.tenantId(), userId)));
    }

    @PostMapping("/{id}/transfer")
    public Map<String, Object> transfer(@CurrentUser AuthContext auth, @PathVariable String id,
                                        @RequestBody(required = false) Map<String, Object> body,
                                        HttpServletRequest request) {
        require(auth);
        Map<String, Object> input = body == null ? new LinkedHashMap<>() : new LinkedHashMap<>(body);
        input.put("user_id", ctx.id(id, "id"));
        return Api.ok(orgs.transfer(auth.tenantId(), Body.of(input), auth.identityId(), ctx.meta(request)));
    }

    private void require(AuthContext auth) {
        authClient.requirePermission(auth, PERMISSION);
    }

    @SuppressWarnings("unchecked")
    private List<Object> items(Object body) {
        if (body instanceof List<?> list) {
            return new ArrayList<>((List<Object>) list);
        }
        Body input = Body.of(body);
        if (input.has("items")) {
            return input.list("items");
        }
        if (input.has("users")) {
            return input.list("users");
        }
        throw com.platform.user.common.ApiException.validation("items", "请提供用户数组");
    }
}
