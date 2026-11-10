package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.ApiException;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.common.NotificationService;
import com.platform.auth.config.AppProps;
import com.platform.auth.service.IdentityService;
import com.platform.auth.service.RbacService;
import com.platform.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/internal")
public class InternalController {
    private final Db db;
    private final AppProps props;
    private final IdentityService identities;
    private final SessionService sessions;
    private final RbacService rbac;
    private final NotificationService notifications;

    public InternalController(Db db, AppProps props, IdentityService identities, SessionService sessions,
                              RbacService rbac, NotificationService notifications) {
        this.db = db;
        this.props = props;
        this.identities = identities;
        this.sessions = sessions;
        this.rbac = rbac;
        this.notifications = notifications;
    }

    private void authorize(String token) {
        if (!Ids.constantEquals(props.getInternalToken(), token)) {
            throw ApiException.unauthorized("内部令牌无效");
        }
    }

    @GetMapping("/identities")
    public Map<String, Object> list(@RequestHeader(value = "x-internal-token", required = false) String token,
                                    @RequestParam(defaultValue = "1") int page,
                                    @RequestParam(defaultValue = "20") int page_size,
                                    @RequestParam(required = false) String status,
                                    @RequestParam(required = false) String keyword) {
        authorize(token);
        return Api.ok(identities.adminList(Math.max(1, page), Math.min(200, Math.max(1, page_size)), status, keyword));
    }

    @PostMapping("/identities")
    public ResponseEntity<Map<String, Object>> create(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @RequestBody Map<String, Object> body) {
        authorize(token);
        String tenant = body.get("tenant_id") == null
                ? IdentityService.DEFAULT_TENANT : String.valueOf(body.get("tenant_id"));
        String status = body.get("status") == null ? "active" : String.valueOf(body.get("status"));
        Map<String, Object> created = identities.create(body, tenant, status, null, "internal");
        return Api.created(created);
    }

    @GetMapping("/identities/{id}")
    public Map<String, Object> get(@RequestHeader(value = "x-internal-token", required = false) String token,
                                   @PathVariable String id) {
        authorize(token);
        return Api.ok(identities.get(id));
    }

    @PutMapping("/identities/{id}/status")
    public Map<String, Object> status(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @PathVariable String id, @RequestBody Map<String, Object> body) {
        authorize(token);
        return Api.ok(identities.setStatus(id, body, null, null));
    }

    @PostMapping("/identities/{id}/sessions/revoke")
    public Map<String, Object> revokeSessions(@RequestHeader(value = "x-internal-token", required = false) String token,
                                              @PathVariable String id) {
        authorize(token);
        sessions.logoutAll(id);
        return Api.ok(Map.of("revoked", true));
    }

    @PostMapping("/identities/{id}/contacts/request")
    public Map<String, Object> requestContact(@RequestHeader(value = "x-internal-token", required = false) String token,
                                              @PathVariable String id, @RequestBody Map<String, Object> body) {
        authorize(token);
        return Api.ok(identities.requestContactChange(id, body, null));
    }

    @PostMapping("/identities/{id}/contacts/confirm")
    public Map<String, Object> confirmContact(@RequestHeader(value = "x-internal-token", required = false) String token,
                                              @PathVariable String id, @RequestBody Map<String, Object> body) {
        authorize(token);
        return Api.ok(identities.confirmContactChange(id, body, null));
    }

    @GetMapping("/identities/{id}/contacts")
    public Map<String, Object> contacts(@RequestHeader(value = "x-internal-token", required = false) String token,
                                        @PathVariable String id) {
        authorize(token);
        return Api.ok(Map.of("items", db.list("""
                SELECT kind, value, verified_at, is_primary FROM identity_identifiers
                WHERE identity_id = :id ORDER BY kind
                """, Db.params("id", id))));
    }

    @DeleteMapping("/identities/{id}/contacts/{kind}")
    public Map<String, Object> clearContact(@RequestHeader(value = "x-internal-token", required = false) String token,
                                            @PathVariable String id, @PathVariable String kind) {
        authorize(token);
        Map<String, Object> identity = identities.get(id);
        if (!"email".equals(kind) && !"phone".equals(kind)) {
            throw ApiException.badRequest("不支持的联系方式类型");
        }
        db.inTx(() -> {
            db.update("UPDATE identities SET " + kind + " = NULL, " + kind + "_verified = FALSE WHERE id = :id",
                    Db.params("id", id));
            db.update("DELETE FROM identity_identifiers WHERE identity_id = :id AND kind = :kind",
                    Db.params("id", id, "kind", kind));
        });
        return Api.ok(Map.of("cleared", true, "identity_id", identity.get("id")));
    }

    @PostMapping("/authz/check")
    public Map<String, Object> authzCheck(@RequestHeader(value = "x-internal-token", required = false) String token,
                                          @RequestBody Map<String, Object> body) {
        authorize(token);
        String identityId = String.valueOf(body.get("identity_id"));
        String tenant = body.get("tenant_id") == null ? IdentityService.DEFAULT_TENANT : String.valueOf(body.get("tenant_id"));
        return Api.ok(rbac.check(identityId, tenant, String.valueOf(body.get("permission")),
                body.get("resource_type") == null ? null : String.valueOf(body.get("resource_type")),
                body.get("resource_id") == null ? null : String.valueOf(body.get("resource_id")),
                body.get("context") instanceof Map<?, ?> map ? Json.readMap(map) : Map.of()));
    }

    @PostMapping("/events")
    public Map<String, Object> events(@RequestHeader(value = "x-internal-token", required = false) String token,
                                      @RequestBody Map<String, Object> body, HttpServletRequest request) {
        authorize(token);
        String eventId = body.get("event_id") == null ? Ids.uuidStr() : String.valueOf(body.get("event_id"));
        String eventType = String.valueOf(body.get("event_type"));
        Map<String, Object> payload = Json.readMap(body.getOrDefault("payload", Map.of()));
        int inserted = db.update("""
                INSERT INTO inbox_events (event_id, consumer, event_type, payload, status)
                VALUES (:id, 'auth-center', :type, :payload, 'received')
                ON CONFLICT (event_id, consumer) DO NOTHING
                """, Db.params("id", eventId, "type", eventType, "payload", Json.jsonb(payload)));
        if (inserted == 0) {
            return Api.ok(Map.of("duplicate", true, "event_id", eventId));
        }
        try {
            String identityId = payload.get("identity_id") == null ? null : String.valueOf(payload.get("identity_id"));
            if ("user.deleted".equals(eventType) && identityId != null) {
                db.update("UPDATE identities SET status = 'deleted', deleted_at = now() WHERE id = :id",
                        Db.params("id", identityId));
                sessions.logoutAll(identityId);
            }
            String targetStatus = payload.get("to") == null ? null : String.valueOf(payload.get("to"));
            if ("user.status_changed".equals(eventType) && identityId != null && targetStatus != null) {
                db.update("UPDATE identities SET status = :status, updated_at = now() WHERE id = :id",
                        Db.params("status", targetStatus, "id", identityId));
                if (!"active".equals(targetStatus)) {
                    sessions.logoutAll(identityId);
                }
            }
            db.update("UPDATE inbox_events SET status = 'processed', processed_at = now() WHERE event_id = :id AND consumer = 'auth-center'",
                    Db.params("id", eventId));
        } catch (Exception e) {
            db.update("UPDATE inbox_events SET status = 'failed', attempts = attempts + 1, last_error = :err WHERE event_id = :id AND consumer = 'auth-center'",
                    Db.params("err", e.getMessage(), "id", eventId));
        }
        return Api.ok(Map.of("received", true, "event_id", eventId));
    }
}
