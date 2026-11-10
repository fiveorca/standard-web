package com.platform.user.web;

import com.platform.user.common.Access;
import com.platform.user.common.Api;
import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.config.AppProperties;
import com.platform.user.service.InternalService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/internal")
public class InternalController {
    private final InternalService internal;
    private final AppProperties props;
    private final RequestContext ctx;

    public InternalController(InternalService internal, AppProperties props, RequestContext ctx) {
        this.internal = internal;
        this.props = props;
        this.ctx = ctx;
    }

    @PostMapping("/users/ensure")
    public Map<String, Object> ensure(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        requireInternal(token);
        Body input = Body.of(body);
        UUID tenantId = input.requiredUuid("tenant_id", "tenant_id");
        return Api.ok(internal.ensure(tenantId, input, ctx.meta(request)));
    }

    @GetMapping("/users/{id}")
    public Map<String, Object> user(@RequestHeader(value = "x-internal-token", required = false) String token,
                                    @PathVariable String id,
                                    @RequestParam Map<String, String> query) {
        requireInternal(token);
        return Api.ok(internal.user(optionalUuid(query.get("tenant_id")), ctx.id(id, "id")));
    }

    @PutMapping("/users/{id}/status")
    @PostMapping("/users/{id}/status")
    public Map<String, Object> status(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        requireInternal(token);
        return Api.ok(internal.updateStatus(optionalUuid(Body.of(body).str("tenant_id")),
                ctx.id(id, "id"), Body.of(body), ctx.meta(request)));
    }

    @GetMapping("/users/{id}/contacts")
    public Map<String, Object> contacts(@RequestHeader(value = "x-internal-token", required = false) String token,
                                        @PathVariable String id,
                                        @RequestParam Map<String, String> query) {
        requireInternal(token);
        return Api.ok(Map.of("items", internal.contactsInternal(optionalUuid(query.get("tenant_id")),
                ctx.id(id, "id"))));
    }

    @PostMapping("/events")
    public Map<String, Object> events(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @RequestBody(required = false) Map<String, Object> body) {
        requireInternal(token);
        Map<String, Object> envelope = Body.of(body).has("event")
                ? Body.of(body).map("event") : Json.readMap(body);
        return Api.ok(internal.receiveEvent(envelope));
    }

    private void requireInternal(String token) {
        Access.requireInternal(token, props.getInternalToken());
    }

    private static UUID optionalUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        UUID id = Ids.parse(value);
        if (id == null) {
            throw ApiException.validation("tenant_id", "ID 格式不合法");
        }
        return id;
    }
}
