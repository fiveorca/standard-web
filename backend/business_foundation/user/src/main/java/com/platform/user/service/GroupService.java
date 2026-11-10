package com.platform.user.service;

import com.platform.user.bootstrap.OutboxService;
import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.PageQuery;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.Text;
import com.platform.user.common.Tree;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class GroupService {
    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;
    private final TransactionTemplate tx;

    public GroupService(Db db, AuditService audit, OutboxService outbox, TransactionTemplate tx) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
        this.tx = tx;
    }

    public Map<String, Object> list(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        StringBuilder where = new StringBuilder(" WHERE g.tenant_id = :tenant AND g.deleted_at IS NULL");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND g.status = :status");
            params.put("status", status);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (g.name ILIKE :kw ESCAPE '\\' OR g.code ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        String parent = blank(query.get("parent_id"));
        if ("root".equals(parent)) {
            where.append(" AND g.parent_id IS NULL");
        } else if (parent != null) {
            params.put("parent", Ids.parse(parent));
            where.append(" AND g.parent_id = :parent");
        }
        long total = db.count("SELECT count(*) FROM user_groups g" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT g.*, (SELECT count(*) FROM user_group_members m WHERE m.group_id = g.id) AS member_count
                FROM user_groups g
                """ + where + " ORDER BY g.sort_order, g.created_at LIMIT :limit OFFSET :offset", pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public List<Map<String, Object>> tree(UUID tenantId) {
        List<Map<String, Object>> rows = db.list("""
                SELECT g.*, (SELECT count(*) FROM user_group_members m WHERE m.group_id = g.id) AS member_count
                FROM user_groups g WHERE g.tenant_id = :tenant AND g.deleted_at IS NULL
                ORDER BY g.sort_order, g.created_at
                """, Db.params("tenant", tenantId));
        return Tree.build(rows, "id", "parent_id");
    }

    public Map<String, Object> get(UUID tenantId, UUID id) {
        return db.one("""
                SELECT g.*, (SELECT count(*) FROM user_group_members m WHERE m.group_id = g.id) AS member_count
                FROM user_groups g
                WHERE g.tenant_id = :tenant AND g.id = :id AND g.deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
    }

    public Map<String, Object> create(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        String code = input.required("code", "编码");
        String name = input.required("name", "名称");
        UUID parentId = input.uuid("parent_id");
        Map<String, Object> parent = parentId == null ? null : get(tenantId, parentId);
        if (db.count("""
                SELECT count(*) FROM user_groups
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code)) > 0) {
            throw ApiException.conflict("分组编码已存在");
        }
        UUID id = Ids.uuidValue();
        String path = parent == null ? "/" + id : parent.get("path") + "/" + id;
        int level = parent == null ? 0 : ((Number) parent.get("level")).intValue() + 1;
        db.update("""
                INSERT INTO user_groups
                    (id, tenant_id, parent_id, code, name, description, path, level, status, tags, extra, sort_order)
                VALUES
                    (:id, :tenant, :parent, :code, :name, :description, :path, :level, :status, :tags, :extra, :sort)
                """, Db.params("id", id, "tenant", tenantId, "parent", parentId, "code", code, "name", name,
                "description", input.trimmed("description"), "path", path, "level", level,
                "status", validStatus(input.str("status", "active")), "tags", Json.jsonb(input.list("tags")),
                "extra", Json.jsonb(input.map("extra")), "sort", input.integer("sort_order", 0)));
        audit.success(tenantId, actorId, "group.create", "group", id.toString(), meta, Map.of("code", code));
        return get(tenantId, id);
    }

    public Map<String, Object> update(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = get(tenantId, id);
        UUID oldParent = Ids.parse(String.valueOf(current.get("parent_id")));
        UUID newParent = input.has("parent_id") ? input.uuid("parent_id") : oldParent;
        Map<String, Object> parent = newParent == null ? null : get(tenantId, newParent);
        if (newParent != null && newParent.equals(id)) {
            throw ApiException.validation("parent_id", "分组不能作为自己的父级");
        }
        String oldPath = String.valueOf(current.get("path"));
        int oldLevel = ((Number) current.get("level")).intValue();
        String newPath;
        int newLevel;
        if (newParent == null) {
            newPath = "/" + id;
            newLevel = 0;
        } else {
            String parentPath = String.valueOf(parent.get("path"));
            if (parentPath.equals(oldPath) || parentPath.startsWith(oldPath + "/")) {
                throw ApiException.validation("parent_id", "不能移动到自己的子孙节点下");
            }
            newPath = parentPath + "/" + id;
            newLevel = ((Number) parent.get("level")).intValue() + 1;
        }
        String code = input.has("code") ? input.required("code", "编码") : String.valueOf(current.get("code"));
        if (db.count("""
                SELECT count(*) FROM user_groups
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND id <> :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code, "id", id)) > 0) {
            throw ApiException.conflict("分组编码已存在");
        }
        String name = input.has("name") ? input.required("name", "名称") : String.valueOf(current.get("name"));
        String status = input.has("status") ? validStatus(input.str("status", "active")) : String.valueOf(current.get("status"));
        boolean moved = !newPath.equals(oldPath) || !java.util.Objects.equals(newParent, oldParent);
        tx.executeWithoutResult(txStatus -> {
            db.update("""
                    UPDATE user_groups
                    SET parent_id = :parent, code = :code, name = :name, description = :description,
                        path = :path, level = :level, status = :status, tags = :tags, extra = :extra,
                        sort_order = :sort, updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("parent", newParent, "code", code, "name", name,
                    "description", input.has("description") ? input.trimmed("description") : current.get("description"),
                    "path", newPath, "level", newLevel, "status", status,
                    "tags", input.has("tags") ? Json.jsonb(input.list("tags")) : Json.jsonb(current.get("tags")),
                    "extra", input.has("extra") ? Json.jsonb(input.map("extra")) : Json.jsonb(current.get("extra")),
                    "sort", input.has("sort_order") ? input.integer("sort_order", 0)
                            : ((Number) current.getOrDefault("sort_order", 0)).intValue(),
                    "tenant", tenantId, "id", id));
            if (moved) {
                relocate(tenantId, id, oldPath, newPath, newLevel - oldLevel);
            }
        });
        audit.success(tenantId, actorId, "group.update", "group", id.toString(), meta, Map.of("moved", moved));
        return get(tenantId, id);
    }

    public void delete(UUID tenantId, UUID id, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = get(tenantId, id);
        UUID parentId = Ids.parse(String.valueOf(current.get("parent_id")));
        Map<String, Object> parent = parentId == null ? null : get(tenantId, parentId);
        String oldPath = String.valueOf(current.get("path"));
        List<Map<String, Object>> children = db.list("""
                SELECT * FROM user_groups WHERE tenant_id = :tenant AND parent_id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
        tx.executeWithoutResult(status -> {
            for (Map<String, Object> child : children) {
                UUID childId = Ids.parse(String.valueOf(child.get("id")));
                String childOldPath = String.valueOf(child.get("path"));
                int childOldLevel = ((Number) child.get("level")).intValue();
                String childNewPath = parent == null ? "/" + childId : parent.get("path") + "/" + childId;
                int childNewLevel = parent == null ? 0 : ((Number) parent.get("level")).intValue() + 1;
                db.update("""
                        UPDATE user_groups SET parent_id = :parent, path = :path, level = :level, updated_at = now()
                        WHERE tenant_id = :tenant AND id = :id
                        """, Db.params("parent", parentId, "path", childNewPath, "level", childNewLevel,
                        "tenant", tenantId, "id", childId));
                relocate(tenantId, childId, childOldPath, childNewPath, childNewLevel - childOldLevel);
            }
            db.update("""
                    UPDATE user_groups SET deleted_at = now(), updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("tenant", tenantId, "id", id));
            db.update("DELETE FROM user_group_members WHERE group_id = :id", Db.params("id", id));
        });
        audit.success(tenantId, actorId, "group.delete", "group", id.toString(), meta,
                Map.of("old_path", oldPath));
    }

    private void relocate(UUID tenantId, UUID nodeId, String oldPath, String newPath, int delta) {
        db.update("""
                UPDATE user_groups
                SET path = :newPath || substring(path from :cut), level = level + :delta, updated_at = now()
                WHERE tenant_id = :tenant AND path LIKE :prefix ESCAPE '\\'
                """, Db.params("newPath", newPath, "cut", oldPath.length() + 1, "delta", delta,
                "tenant", tenantId, "prefix", escapeLike(oldPath) + "/%"));
    }

    public Map<String, Object> members(UUID tenantId, UUID groupId, Map<String, String> query) {
        get(tenantId, groupId);
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        Map<String, Object> params = Db.params("tenant", tenantId, "group", groupId);
        long total = db.count("""
                SELECT count(*) FROM user_group_members m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.group_id = :group AND u.deleted_at IS NULL
                """, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT u.id, u.username, u.display_name, u.email, u.phone, u.status, m.joined_at
                FROM user_group_members m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.group_id = :group AND u.deleted_at IS NULL
                ORDER BY m.joined_at DESC LIMIT :limit OFFSET :offset
                """, pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public Map<String, Object> addMembers(UUID tenantId, UUID groupId, Body input, UUID actorId, RequestMeta meta) {
        get(tenantId, groupId);
        List<UUID> userIds = input.uuids("user_ids");
        if (userIds.isEmpty() && input.uuid("user_id") != null) {
            userIds = List.of(input.uuid("user_id"));
        }
        if (userIds.isEmpty()) {
            throw ApiException.validation("user_ids", "至少需要一个用户");
        }
        final List<UUID> targets = userIds;
        int added = tx.execute(status -> {
            int count = 0;
            for (UUID userId : targets) {
                if (db.count("""
                        SELECT count(*) FROM users WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                        """, Db.params("tenant", tenantId, "id", userId)) == 0) {
                    throw ApiException.notFound("用户不存在: " + userId);
                }
                int rows = db.update("""
                        INSERT INTO user_group_members (group_id, user_id, tenant_id)
                        VALUES (:group, :user, :tenant) ON CONFLICT DO NOTHING
                        """, Db.params("group", groupId, "user", userId, "tenant", tenantId));
                if (rows > 0) {
                    count++;
                    audit.orgHistory(tenantId, userId, null, null, "join", actorId,
                            Map.of("group_id", groupId.toString(), "type", "group"));
                }
            }
            return count;
        });
        audit.success(tenantId, actorId, "group.member_add", "group", groupId.toString(), meta,
                Map.of("user_ids", targets.stream().map(UUID::toString).toList(), "added", added));
        for (UUID userId : targets) {
            outbox.publish("user.updated", "user", userId.toString(),
                    Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "groups", List.of(groupId.toString())));
        }
        return Map.of("added", added, "user_ids", targets.stream().map(UUID::toString).toList());
    }

    public void removeMember(UUID tenantId, UUID groupId, UUID userId, UUID actorId, RequestMeta meta) {
        get(tenantId, groupId);
        int rows = db.update("""
                DELETE FROM user_group_members WHERE tenant_id = :tenant AND group_id = :group AND user_id = :user
                """, Db.params("tenant", tenantId, "group", groupId, "user", userId));
        if (rows == 0) {
            throw ApiException.notFound("用户不在该分组中");
        }
        audit.orgHistory(tenantId, userId, null, null, "leave", actorId,
                Map.of("group_id", groupId.toString(), "type", "group"));
        audit.success(tenantId, actorId, "group.member_remove", "group", groupId.toString(), meta,
                Map.of("user_id", userId.toString()));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "groups", List.of(groupId.toString())));
    }

    public void removeMembers(UUID tenantId, UUID groupId, Body input, UUID actorId, RequestMeta meta) {
        List<UUID> userIds = input.uuids("user_ids");
        for (UUID userId : userIds) {
            try {
                removeMember(tenantId, groupId, userId, actorId, meta);
            } catch (ApiException ignored) {
                // 逐项删除，忽略不存在的成员
            }
        }
    }

    public List<Map<String, Object>> userGroups(UUID tenantId, UUID userId) {
        return db.list("""
                SELECT g.* FROM user_group_members m
                JOIN user_groups g ON g.id = m.group_id
                WHERE m.tenant_id = :tenant AND m.user_id = :user AND g.deleted_at IS NULL
                ORDER BY g.sort_order, g.name
                """, Db.params("tenant", tenantId, "user", userId));
    }

    private static String validStatus(String status) {
        if (!List.of("active", "disabled").contains(status)) {
            throw ApiException.validation("status", "状态值不合法");
        }
        return status;
    }

    private static String escapeLike(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
