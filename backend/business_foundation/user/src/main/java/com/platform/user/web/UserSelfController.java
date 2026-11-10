package com.platform.user.web;

import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.AttributeService;
import com.platform.user.service.ContactService;
import com.platform.user.service.GroupService;
import com.platform.user.service.OrgService;
import com.platform.user.service.RegistrationService;
import com.platform.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/users/me")
public class UserSelfController {
    private final UserService users;
    private final ContactService contacts;
    private final GroupService groups;
    private final OrgService orgs;
    private final AttributeService attributes;
    private final RegistrationService registrations;
    private final RequestContext ctx;

    public UserSelfController(UserService users, ContactService contacts, GroupService groups,
                              OrgService orgs, AttributeService attributes,
                              RegistrationService registrations, RequestContext ctx) {
        this.users = users;
        this.contacts = contacts;
        this.groups = groups;
        this.orgs = orgs;
        this.attributes = attributes;
        this.registrations = registrations;
        this.ctx = ctx;
    }

    @GetMapping
    public Map<String, Object> me(@CurrentUser AuthContext auth, HttpServletRequest request) {
        return Api.ok(users.ensureFromContext(auth, ctx.meta(request)));
    }

    @PatchMapping
    public Map<String, Object> updateMe(@CurrentUser AuthContext auth,
                                        @RequestBody(required = false) Map<String, Object> body,
                                        @RequestHeader(value = "If-Match", required = false) String ifMatch,
                                        HttpServletRequest request) {
        return Api.ok(users.update(auth.tenantId(), auth.identityId(), Body.of(body),
                ctx.version(ifMatch, body), auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/profile")
    public Map<String, Object> profile(@CurrentUser AuthContext auth) {
        return Api.ok(users.profile(auth.tenantId(), auth.identityId()));
    }

    @PatchMapping("/profile")
    @PutMapping("/profile")
    public Map<String, Object> updateProfile(@CurrentUser AuthContext auth,
                                              @RequestBody(required = false) Map<String, Object> body,
                                              HttpServletRequest request) {
        return Api.ok(users.updateProfile(auth.tenantId(), auth.identityId(), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @PostMapping("/avatar")
    public Map<String, Object> avatar(@CurrentUser AuthContext auth,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        Map<String, Object> patch = new LinkedHashMap<>();
        Body input = Body.of(body);
        patch.put("avatar_url", input.str("avatar_url") != null ? input.str("avatar_url") : input.required("url", "头像地址"));
        return Api.ok(users.update(auth.tenantId(), auth.identityId(), Body.of(patch),
                null, auth.identityId(), ctx.meta(request)));
    }

    @PutMapping("/nickname")
    public Map<String, Object> nickname(@CurrentUser AuthContext auth,
                                        @RequestBody(required = false) Map<String, Object> body,
                                        HttpServletRequest request) {
        Body input = Body.of(body);
        Map<String, Object> patch = new LinkedHashMap<>();
        String value = input.str("nickname") != null ? input.str("nickname") : input.required("display_name", "昵称");
        patch.put("display_name", value);
        return Api.ok(users.update(auth.tenantId(), auth.identityId(), Body.of(patch),
                null, auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/contacts")
    public Map<String, Object> listContacts(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", contacts.list(auth.tenantId(), auth.identityId(), true)));
    }

    @PostMapping("/contacts")
    public Map<String, Object> addContact(@CurrentUser AuthContext auth,
                                          @RequestBody(required = false) Map<String, Object> body,
                                          HttpServletRequest request) {
        return Api.ok(contacts.requestChange(auth.tenantId(), auth.identityId(), Body.of(body), ctx.meta(request)));
    }

    @DeleteMapping("/contacts")
    public Map<String, Object> removeAllContacts(@CurrentUser AuthContext auth, HttpServletRequest request) {
        List<Map<String, Object>> current = contacts.list(auth.tenantId(), auth.identityId(), true);
        Set<String> kinds = new LinkedHashSet<>();
        for (Map<String, Object> item : current) {
            kinds.add(String.valueOf(item.get("kind")));
        }
        List<Map<String, Object>> result = current;
        for (String kind : kinds) {
            result = contacts.unbind(auth.tenantId(), auth.identityId(), kind, ctx.meta(request));
        }
        return Api.ok(Map.of("items", result));
    }

    @PostMapping("/contacts/request")
    public Map<String, Object> requestContact(@CurrentUser AuthContext auth,
                                              @RequestBody(required = false) Map<String, Object> body,
                                              HttpServletRequest request) {
        return Api.ok(contacts.requestChange(auth.tenantId(), auth.identityId(), Body.of(body), ctx.meta(request)));
    }

    @PostMapping("/contacts/confirm")
    public Map<String, Object> confirmContact(@CurrentUser AuthContext auth,
                                              @RequestBody(required = false) Map<String, Object> body,
                                              HttpServletRequest request) {
        return Api.ok(Map.of("items",
                contacts.confirmChange(auth.tenantId(), auth.identityId(), Body.of(body), ctx.meta(request))));
    }

    @DeleteMapping("/contacts/{kind}")
    public Map<String, Object> removeContact(@CurrentUser AuthContext auth, @PathVariable String kind,
                                             HttpServletRequest request) {
        return Api.ok(Map.of("items",
                contacts.unbind(auth.tenantId(), auth.identityId(), kind, ctx.meta(request))));
    }

    @GetMapping("/attributes")
    public Map<String, Object> attributes(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", attributes.listValues(auth.tenantId(), auth.identityId())));
    }

    @PutMapping("/attributes")
    public Map<String, Object> setAttributes(@CurrentUser AuthContext auth,
                                             @RequestBody(required = false) Map<String, Object> body,
                                             HttpServletRequest request) {
        Body input = Body.of(body);
        Map<String, Object> values = input.has("values") ? input.map("values") : input.map();
        return Api.ok(Map.of("items", attributes.setValues(auth.tenantId(), auth.identityId(), values,
                auth.identityId(), ctx.meta(request))));
    }

    @GetMapping("/groups")
    public Map<String, Object> groups(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", groups.userGroups(auth.tenantId(), auth.identityId())));
    }

    @GetMapping("/organizations")
    public Map<String, Object> organizations(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", orgs.memberships(auth.tenantId(), auth.identityId())));
    }

    @GetMapping("/history")
    public Map<String, Object> history(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", users.history(auth.tenantId(), auth.identityId())));
    }

    @GetMapping("/links")
    public Map<String, Object> links(@CurrentUser AuthContext auth) {
        return Api.ok(Map.of("items", users.links(auth.tenantId(), auth.identityId())));
    }

    @DeleteMapping("/links/{provider}")
    public Map<String, Object> removeLink(@CurrentUser AuthContext auth, @PathVariable String provider,
                                          HttpServletRequest request) {
        users.removeLink(auth.tenantId(), auth.identityId(), provider, auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("items", users.links(auth.tenantId(), auth.identityId())));
    }

    @GetMapping("/registration")
    public Map<String, Object> registration(@CurrentUser AuthContext auth) {
        return Api.ok(registrations.userRegistration(auth.tenantId(), auth.identityId()));
    }
}
