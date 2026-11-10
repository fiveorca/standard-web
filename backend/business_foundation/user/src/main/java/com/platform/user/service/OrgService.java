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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class OrgService {
    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;
    private final TransactionTemplate tx;

    public OrgService(Db db, AuditService audit, OutboxService outbox, TransactionTemplate tx) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
        this.tx = tx;
    }

    // ───────────────────────── 组织 ─────────────────────────

    public Map<String, Object> listOrganizations(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        StringBuilder where = new StringBuilder(" WHERE o.tenant_id = :tenant AND o.deleted_at IS NULL");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND o.status = :status");
            params.put("status", status);
        }
        String kind = blank(query.get("kind"));
        if (kind != null) {
            where.append(" AND o.kind = :kind");
            params.put("kind", kind);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (o.name ILIKE :kw ESCAPE '\\' OR o.code ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        String parent = blank(query.get("parent_id"));
        if ("root".equals(parent)) {
            where.append(" AND o.parent_id IS NULL");
        } else if (parent != null) {
            params.put("parent", Ids.parse(parent));
            where.append(" AND o.parent_id = :parent");
        }
        long total = db.count("SELECT count(*) FROM organizations o" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT o.*, (SELECT count(*) FROM organization_members m WHERE m.organization_id = o.id) AS member_count,
                       (SELECT count(*) FROM departments d WHERE d.organization_id = o.id AND d.deleted_at IS NULL) AS department_count
                FROM organizations o
                """ + where + " ORDER BY o.sort_order, o.created_at LIMIT :limit OFFSET :offset", pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public List<Map<String, Object>> organizationTree(UUID tenantId) {
        List<Map<String, Object>> rows = db.list("""
                SELECT o.*, (SELECT count(*) FROM organization_members m WHERE m.organization_id = o.id) AS member_count
                FROM organizations o WHERE o.tenant_id = :tenant AND o.deleted_at IS NULL
                ORDER BY o.sort_order, o.created_at
                """, Db.params("tenant", tenantId));
        return Tree.build(rows, "id", "parent_id");
    }

    public Map<String, Object> getOrganization(UUID tenantId, UUID id) {
        return db.one("""
                SELECT o.*, (SELECT count(*) FROM organization_members m WHERE m.organization_id = o.id) AS member_count
                FROM organizations o
                WHERE o.tenant_id = :tenant AND o.id = :id AND o.deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
    }

    public Map<String, Object> createOrganization(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        String code = input.required("code", "编码");
        String name = input.required("name", "名称");
        String kind = input.str("kind", "company");
        if (!List.of("company", "department", "team", "other").contains(kind)) {
            throw ApiException.validation("kind", "组织类型不合法");
        }
        UUID parentId = input.uuid("parent_id");
        Map<String, Object> parent = parentId == null ? null : getOrganization(tenantId, parentId);
        UUID leaderId = input.uuid("leader_id");
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        if (db.count("""
                SELECT count(*) FROM organizations
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code)) > 0) {
            throw ApiException.conflict("组织编码已存在");
        }
        UUID id = Ids.uuidValue();
        String path = parent == null ? "/" + id : parent.get("path") + "/" + id;
        int level = parent == null ? 0 : ((Number) parent.get("level")).intValue() + 1;
        db.update("""
                INSERT INTO organizations
                    (id, tenant_id, parent_id, kind, code, name, description, path, level, leader_id,
                     status, extra, sort_order)
                VALUES
                    (:id, :tenant, :parent, :kind, :code, :name, :description, :path, :level, :leader,
                     :status, :extra, :sort)
                """, Db.params("id", id, "tenant", tenantId, "parent", parentId, "kind", kind, "code", code,
                "name", name, "description", input.trimmed("description"), "path", path, "level", level,
                "leader", leaderId, "status", validStatus(input.str("status", "active")),
                "extra", Json.jsonb(input.map("extra")), "sort", input.integer("sort_order", 0)));
        audit.success(tenantId, actorId, "organization.create", "organization", id.toString(), meta, Map.of("code", code));
        return getOrganization(tenantId, id);
    }

    public Map<String, Object> updateOrganization(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = getOrganization(tenantId, id);
        UUID oldParent = Ids.parse(String.valueOf(current.get("parent_id")));
        UUID newParent = input.has("parent_id") ? input.uuid("parent_id") : oldParent;
        Map<String, Object> parent = newParent == null ? null : getOrganization(tenantId, newParent);
        if (newParent != null && newParent.equals(id)) {
            throw ApiException.validation("parent_id", "组织不能作为自己的父级");
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
                SELECT count(*) FROM organizations
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND id <> :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code, "id", id)) > 0) {
            throw ApiException.conflict("组织编码已存在");
        }
        UUID leaderId = input.has("leader_id") ? input.uuid("leader_id") : Ids.parse(String.valueOf(current.get("leader_id")));
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        String kind = input.has("kind") ? input.str("kind", "company") : String.valueOf(current.get("kind"));
        if (!List.of("company", "department", "team", "other").contains(kind)) {
            throw ApiException.validation("kind", "组织类型不合法");
        }
        String name = input.has("name") ? input.required("name", "名称") : String.valueOf(current.get("name"));
        String status = input.has("status") ? validStatus(input.str("status", "active")) : String.valueOf(current.get("status"));
        boolean moved = !newPath.equals(oldPath);
        tx.executeWithoutResult(txStatus -> {
            db.update("""
                    UPDATE organizations
                    SET parent_id = :parent, kind = :kind, code = :code, name = :name, description = :description,
                        path = :path, level = :level, leader_id = :leader, status = :status, extra = :extra,
                        sort_order = :sort, updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("parent", newParent, "kind", kind, "code", code, "name", name,
                    "description", input.has("description") ? input.trimmed("description") : current.get("description"),
                    "path", newPath, "level", newLevel, "leader", leaderId, "status", status,
                    "extra", input.has("extra") ? Json.jsonb(input.map("extra")) : Json.jsonb(current.get("extra")),
                    "sort", input.has("sort_order") ? input.integer("sort_order", 0)
                            : ((Number) current.getOrDefault("sort_order", 0)).intValue(),
                    "tenant", tenantId, "id", id));
            if (moved) {
                db.update("""
                        UPDATE organizations
                        SET path = :newPath || substring(path from :cut), level = level + :delta, updated_at = now()
                        WHERE tenant_id = :tenant AND path LIKE :prefix ESCAPE '\\'
                        """, Db.params("newPath", newPath, "cut", oldPath.length() + 1,
                        "delta", newLevel - oldLevel, "tenant", tenantId,
                        "prefix", escapeLike(oldPath) + "/%"));
            }
        });
        audit.success(tenantId, actorId, "organization.update", "organization", id.toString(), meta, Map.of("moved", moved));
        return getOrganization(tenantId, id);
    }

    public void deleteOrganization(UUID tenantId, UUID id, UUID actorId, RequestMeta meta) {
        getOrganization(tenantId, id);
        tx.executeWithoutResult(status -> {
            db.update("""
                    UPDATE departments SET deleted_at = now(), updated_at = now()
                    WHERE tenant_id = :tenant AND organization_id = :id AND deleted_at IS NULL
                    """, Db.params("tenant", tenantId, "id", id));
            db.update("DELETE FROM department_members WHERE department_id IN (SELECT id FROM departments WHERE organization_id = :id)",
                    Db.params("id", id));
            db.update("DELETE FROM organization_members WHERE organization_id = :id", Db.params("id", id));
            db.update("""
                    UPDATE organizations SET deleted_at = now(), updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("tenant", tenantId, "id", id));
        });
        audit.success(tenantId, actorId, "organization.delete", "organization", id.toString(), meta, Map.of());
    }

    public Map<String, Object> setOrganizationLeader(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        getOrganization(tenantId, id);
        UUID leaderId = input.uuid("leader_id");
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        db.update("""
                UPDATE organizations SET leader_id = :leader, updated_at = now()
                WHERE tenant_id = :tenant AND id = :id
                """, Db.params("leader", leaderId, "tenant", tenantId, "id", id));
        audit.success(tenantId, actorId, "organization.leader_set", "organization", id.toString(), meta,
                Map.of("leader_id", leaderId == null ? "" : leaderId.toString()));
        return getOrganization(tenantId, id);
    }

    public Map<String, Object> organizationMembers(UUID tenantId, UUID orgId, Map<String, String> query) {
        getOrganization(tenantId, orgId);
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        Map<String, Object> params = Db.params("tenant", tenantId, "org", orgId);
        long total = db.count("""
                SELECT count(*) FROM organization_members m JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.organization_id = :org AND u.deleted_at IS NULL
                """, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT u.id, u.username, u.display_name, u.email, u.phone, u.status,
                       m.title, m.is_primary, m.joined_at
                FROM organization_members m JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.organization_id = :org AND u.deleted_at IS NULL
                ORDER BY m.is_primary DESC, m.joined_at DESC LIMIT :limit OFFSET :offset
                """, pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public Map<String, Object> addOrganizationMember(UUID tenantId, UUID orgId, Body input, UUID actorId, RequestMeta meta) {
        getOrganization(tenantId, orgId);
        List<UUID> userIds = targetUsers(input);
        String title = input.trimmed("title");
        boolean primary = input.bool("is_primary", true);
        int added = tx.execute(status -> {
            int count = 0;
            for (UUID userId : userIds) {
                requireUser(tenantId, userId);
                if (primary) {
                    db.update("""
                            UPDATE organization_members SET is_primary = FALSE
                            WHERE tenant_id = :tenant AND user_id = :user
                            """, Db.params("tenant", tenantId, "user", userId));
                }
                count += db.update("""
                        INSERT INTO organization_members (organization_id, user_id, tenant_id, title, is_primary)
                        VALUES (:org, :user, :tenant, :title, :primary)
                        ON CONFLICT (organization_id, user_id) DO UPDATE
                        SET title = EXCLUDED.title, is_primary = EXCLUDED.is_primary, left_at = NULL
                        """, Db.params("org", orgId, "user", userId, "tenant", tenantId,
                        "title", title, "primary", primary));
                audit.orgHistory(tenantId, userId, orgId, null, "join", actorId,
                        Map.of("title", title == null ? "" : title));
            }
            return count;
        });
        audit.success(tenantId, actorId, "organization.member_add", "organization", orgId.toString(), meta,
                Map.of("user_ids", userIds.stream().map(UUID::toString).toList(), "added", added));
        publishOrganizationChanged(tenantId, userIds);
        return Map.of("added", added, "user_ids", userIds.stream().map(UUID::toString).toList());
    }

    public void removeOrganizationMember(UUID tenantId, UUID orgId, UUID userId, UUID actorId, RequestMeta meta) {
        getOrganization(tenantId, orgId);
        int rows = db.update("""
                DELETE FROM organization_members
                WHERE tenant_id = :tenant AND organization_id = :org AND user_id = :user
                """, Db.params("tenant", tenantId, "org", orgId, "user", userId));
        if (rows == 0) {
            throw ApiException.notFound("用户不在该组织中");
        }
        audit.orgHistory(tenantId, userId, orgId, null, "leave", actorId, Map.of());
        audit.success(tenantId, actorId, "organization.member_remove", "organization", orgId.toString(), meta,
                Map.of("user_id", userId.toString()));
        publishOrganizationChanged(tenantId, List.of(userId));
    }

    // ───────────────────────── 部门 ─────────────────────────

    public Map<String, Object> listDepartments(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        StringBuilder where = new StringBuilder(" WHERE d.tenant_id = :tenant AND d.deleted_at IS NULL");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String org = blank(query.get("organization_id"));
        if (org != null) {
            params.put("org", Ids.parse(org));
            where.append(" AND d.organization_id = :org");
        }
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND d.status = :status");
            params.put("status", status);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (d.name ILIKE :kw ESCAPE '\\' OR d.code ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        long total = db.count("SELECT count(*) FROM departments d" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT d.*, o.name AS organization_name,
                       (SELECT count(*) FROM department_members m WHERE m.department_id = d.id) AS member_count
                FROM departments d LEFT JOIN organizations o ON o.id = d.organization_id
                """ + where + " ORDER BY d.sort_order, d.created_at LIMIT :limit OFFSET :offset", pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public List<Map<String, Object>> departmentTree(UUID tenantId, UUID organizationId) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        StringBuilder where = new StringBuilder(" WHERE d.tenant_id = :tenant AND d.deleted_at IS NULL");
        if (organizationId != null) {
            where.append(" AND d.organization_id = :org");
            params.put("org", organizationId);
        }
        List<Map<String, Object>> rows = db.list("""
                SELECT d.*, o.name AS organization_name,
                       (SELECT count(*) FROM department_members m WHERE m.department_id = d.id) AS member_count
                FROM departments d LEFT JOIN organizations o ON o.id = d.organization_id
                """ + where + " ORDER BY d.sort_order, d.created_at", params);
        return Tree.build(rows, "id", "parent_id");
    }

    public Map<String, Object> getDepartment(UUID tenantId, UUID id) {
        return db.one("""
                SELECT d.*, o.name AS organization_name,
                       (SELECT count(*) FROM department_members m WHERE m.department_id = d.id) AS member_count
                FROM departments d LEFT JOIN organizations o ON o.id = d.organization_id
                WHERE d.tenant_id = :tenant AND d.id = :id AND d.deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
    }

    public Map<String, Object> createDepartment(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        UUID orgId = input.requiredUuid("organization_id", "组织");
        getOrganization(tenantId, orgId);
        String code = input.required("code", "编码");
        String name = input.required("name", "名称");
        UUID parentId = input.uuid("parent_id");
        Map<String, Object> parent = parentId == null ? null : getDepartment(tenantId, parentId);
        if (parent != null && !orgId.toString().equals(String.valueOf(parent.get("organization_id")))) {
            throw ApiException.validation("parent_id", "父部门必须属于同一组织");
        }
        UUID leaderId = input.uuid("leader_id");
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        if (db.count("""
                SELECT count(*) FROM departments
                WHERE organization_id = :org AND lower(code) = lower(:code) AND deleted_at IS NULL
                """, Db.params("org", orgId, "code", code)) > 0) {
            throw ApiException.conflict("部门编码已存在");
        }
        UUID id = Ids.uuidValue();
        String path = parent == null ? "/" + id : parent.get("path") + "/" + id;
        int level = parent == null ? 0 : ((Number) parent.get("level")).intValue() + 1;
        db.update("""
                INSERT INTO departments
                    (id, tenant_id, organization_id, parent_id, code, name, description, path, level,
                     leader_id, status, extra, sort_order)
                VALUES
                    (:id, :tenant, :org, :parent, :code, :name, :description, :path, :level,
                     :leader, :status, :extra, :sort)
                """, Db.params("id", id, "tenant", tenantId, "org", orgId, "parent", parentId, "code", code,
                "name", name, "description", input.trimmed("description"), "path", path, "level", level,
                "leader", leaderId, "status", validStatus(input.str("status", "active")),
                "extra", Json.jsonb(input.map("extra")), "sort", input.integer("sort_order", 0)));
        audit.success(tenantId, actorId, "department.create", "department", id.toString(), meta, Map.of("code", code));
        return getDepartment(tenantId, id);
    }

    public Map<String, Object> updateDepartment(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = getDepartment(tenantId, id);
        UUID orgId = Ids.parse(String.valueOf(current.get("organization_id")));
        if (input.has("organization_id")) {
            UUID requested = input.uuid("organization_id");
            if (requested != null && !requested.equals(orgId)) {
                throw ApiException.validation("organization_id", "暂不支持跨组织移动部门");
            }
        }
        UUID oldParent = Ids.parse(String.valueOf(current.get("parent_id")));
        UUID newParent = input.has("parent_id") ? input.uuid("parent_id") : oldParent;
        Map<String, Object> parent = newParent == null ? null : getDepartment(tenantId, newParent);
        if (newParent != null && newParent.equals(id)) {
            throw ApiException.validation("parent_id", "部门不能作为自己的父级");
        }
        if (parent != null && !orgId.toString().equals(String.valueOf(parent.get("organization_id")))) {
            throw ApiException.validation("parent_id", "父部门必须属于同一组织");
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
                SELECT count(*) FROM departments
                WHERE organization_id = :org AND lower(code) = lower(:code) AND id <> :id AND deleted_at IS NULL
                """, Db.params("org", orgId, "code", code, "id", id)) > 0) {
            throw ApiException.conflict("部门编码已存在");
        }
        UUID leaderId = input.has("leader_id") ? input.uuid("leader_id") : Ids.parse(String.valueOf(current.get("leader_id")));
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        String name = input.has("name") ? input.required("name", "名称") : String.valueOf(current.get("name"));
        String status = input.has("status") ? validStatus(input.str("status", "active")) : String.valueOf(current.get("status"));
        boolean moved = !newPath.equals(oldPath);
        tx.executeWithoutResult(txStatus -> {
            db.update("""
                    UPDATE departments
                    SET parent_id = :parent, code = :code, name = :name, description = :description,
                        path = :path, level = :level, leader_id = :leader, status = :status, extra = :extra,
                        sort_order = :sort, updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("parent", newParent, "code", code, "name", name,
                    "description", input.has("description") ? input.trimmed("description") : current.get("description"),
                    "path", newPath, "level", newLevel, "leader", leaderId, "status", status,
                    "extra", input.has("extra") ? Json.jsonb(input.map("extra")) : Json.jsonb(current.get("extra")),
                    "sort", input.has("sort_order") ? input.integer("sort_order", 0)
                            : ((Number) current.getOrDefault("sort_order", 0)).intValue(),
                    "tenant", tenantId, "id", id));
            if (moved) {
                db.update("""
                        UPDATE departments
                        SET path = :newPath || substring(path from :cut), level = level + :delta, updated_at = now()
                        WHERE tenant_id = :tenant AND path LIKE :prefix ESCAPE '\\'
                        """, Db.params("newPath", newPath, "cut", oldPath.length() + 1,
                        "delta", newLevel - oldLevel, "tenant", tenantId,
                        "prefix", escapeLike(oldPath) + "/%"));
            }
        });
        audit.success(tenantId, actorId, "department.update", "department", id.toString(), meta, Map.of("moved", moved));
        return getDepartment(tenantId, id);
    }

    public void deleteDepartment(UUID tenantId, UUID id, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = getDepartment(tenantId, id);
        UUID orgId = Ids.parse(String.valueOf(current.get("organization_id")));
        UUID parentId = Ids.parse(String.valueOf(current.get("parent_id")));
        Map<String, Object> parent = parentId == null ? null : getDepartment(tenantId, parentId);
        List<Map<String, Object>> children = db.list("""
                SELECT * FROM departments WHERE tenant_id = :tenant AND parent_id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
        tx.executeWithoutResult(status -> {
            for (Map<String, Object> child : children) {
                UUID childId = Ids.parse(String.valueOf(child.get("id")));
                String childOldPath = String.valueOf(child.get("path"));
                int childOldLevel = ((Number) child.get("level")).intValue();
                String childNewPath = parent == null ? "/" + childId : parent.get("path") + "/" + childId;
                int childNewLevel = parent == null ? 0 : ((Number) parent.get("level")).intValue() + 1;
                db.update("""
                        UPDATE departments SET parent_id = :parent, path = :path, level = :level, updated_at = now()
                        WHERE tenant_id = :tenant AND id = :id
                        """, Db.params("parent", parentId, "path", childNewPath, "level", childNewLevel,
                        "tenant", tenantId, "id", childId));
                db.update("""
                        UPDATE departments
                        SET path = :newPath || substring(path from :cut), level = level + :delta, updated_at = now()
                        WHERE tenant_id = :tenant AND path LIKE :prefix ESCAPE '\\'
                        """, Db.params("newPath", childNewPath, "cut", childOldPath.length() + 1,
                        "delta", childNewLevel - childOldLevel, "tenant", tenantId,
                        "prefix", escapeLike(childOldPath) + "/%"));
            }
            db.update("DELETE FROM department_members WHERE department_id = :id", Db.params("id", id));
            db.update("""
                    UPDATE departments SET deleted_at = now(), updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("tenant", tenantId, "id", id));
        });
        audit.success(tenantId, actorId, "department.delete", "department", id.toString(), meta,
                Map.of("organization_id", orgId.toString()));
    }

    public Map<String, Object> setDepartmentLeader(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        getDepartment(tenantId, id);
        UUID leaderId = input.uuid("leader_id");
        if (leaderId != null) {
            requireUser(tenantId, leaderId);
        }
        db.update("""
                UPDATE departments SET leader_id = :leader, updated_at = now()
                WHERE tenant_id = :tenant AND id = :id
                """, Db.params("leader", leaderId, "tenant", tenantId, "id", id));
        audit.success(tenantId, actorId, "department.leader_set", "department", id.toString(), meta,
                Map.of("leader_id", leaderId == null ? "" : leaderId.toString()));
        return getDepartment(tenantId, id);
    }

    public Map<String, Object> departmentMembers(UUID tenantId, UUID deptId, Map<String, String> query) {
        getDepartment(tenantId, deptId);
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        Map<String, Object> params = Db.params("tenant", tenantId, "dept", deptId);
        long total = db.count("""
                SELECT count(*) FROM department_members m JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.department_id = :dept AND u.deleted_at IS NULL
                """, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT u.id, u.username, u.display_name, u.email, u.phone, u.status,
                       m.title, m.is_primary, m.joined_at
                FROM department_members m JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = :tenant AND m.department_id = :dept AND u.deleted_at IS NULL
                ORDER BY m.is_primary DESC, m.joined_at DESC LIMIT :limit OFFSET :offset
                """, pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public Map<String, Object> addDepartmentMember(UUID tenantId, UUID deptId, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> department = getDepartment(tenantId, deptId);
        UUID orgId = Ids.parse(String.valueOf(department.get("organization_id")));
        List<UUID> userIds = targetUsers(input);
        String title = input.trimmed("title");
        boolean primary = input.bool("is_primary", false);
        int added = tx.execute(status -> {
            int count = 0;
            for (UUID userId : userIds) {
                requireUser(tenantId, userId);
                if (primary) {
                    db.update("""
                            UPDATE department_members SET is_primary = FALSE
                            WHERE tenant_id = :tenant AND user_id = :user
                            """, Db.params("tenant", tenantId, "user", userId));
                }
                count += db.update("""
                        INSERT INTO department_members (department_id, user_id, tenant_id, title, is_primary)
                        VALUES (:dept, :user, :tenant, :title, :primary)
                        ON CONFLICT (department_id, user_id) DO UPDATE
                        SET title = EXCLUDED.title, is_primary = EXCLUDED.is_primary, left_at = NULL
                        """, Db.params("dept", deptId, "user", userId, "tenant", tenantId,
                        "title", title, "primary", primary));
                audit.orgHistory(tenantId, userId, orgId, deptId, "join", actorId,
                        Map.of("title", title == null ? "" : title));
            }
            return count;
        });
        audit.success(tenantId, actorId, "department.member_add", "department", deptId.toString(), meta,
                Map.of("user_ids", userIds.stream().map(UUID::toString).toList(), "added", added));
        publishOrganizationChanged(tenantId, userIds);
        return Map.of("added", added, "user_ids", userIds.stream().map(UUID::toString).toList());
    }

    public void removeDepartmentMember(UUID tenantId, UUID deptId, UUID userId, UUID actorId, RequestMeta meta) {
        Map<String, Object> department = getDepartment(tenantId, deptId);
        UUID orgId = Ids.parse(String.valueOf(department.get("organization_id")));
        int rows = db.update("""
                DELETE FROM department_members
                WHERE tenant_id = :tenant AND department_id = :dept AND user_id = :user
                """, Db.params("tenant", tenantId, "dept", deptId, "user", userId));
        if (rows == 0) {
            throw ApiException.notFound("用户不在该部门中");
        }
        audit.orgHistory(tenantId, userId, orgId, deptId, "leave", actorId, Map.of());
        audit.success(tenantId, actorId, "department.member_remove", "department", deptId.toString(), meta,
                Map.of("user_id", userId.toString()));
        publishOrganizationChanged(tenantId, List.of(userId));
    }

    // ───────────────────────── 调动/成员关系 ─────────────────────────

    public Map<String, Object> transfer(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        UUID userId = input.requiredUuid("user_id", "用户");
        UUID orgId = input.requiredUuid("organization_id", "组织");
        UUID deptId = input.uuid("department_id");
        requireUser(tenantId, userId);
        getOrganization(tenantId, orgId);
        if (deptId != null) {
            Map<String, Object> department = getDepartment(tenantId, deptId);
            if (!orgId.toString().equals(String.valueOf(department.get("organization_id")))) {
                throw ApiException.validation("department_id", "部门不属于目标组织");
            }
        }
        Map<String, Object> before = db.find("""
                SELECT organization_id FROM organization_members
                WHERE tenant_id = :tenant AND user_id = :user AND is_primary = TRUE
                """, Db.params("tenant", tenantId, "user", userId)).orElse(null);
        String title = input.trimmed("title");
        boolean primary = input.bool("is_primary", true);
        String reason = input.trimmed("reason");
        tx.executeWithoutResult(status -> {
            db.update("DELETE FROM organization_members WHERE tenant_id = :tenant AND user_id = :user",
                    Db.params("tenant", tenantId, "user", userId));
            db.update("DELETE FROM department_members WHERE tenant_id = :tenant AND user_id = :user",
                    Db.params("tenant", tenantId, "user", userId));
            db.update("""
                    INSERT INTO organization_members (organization_id, user_id, tenant_id, title, is_primary)
                    VALUES (:org, :user, :tenant, :title, :primary)
                    """, Db.params("org", orgId, "user", userId, "tenant", tenantId, "title", title, "primary", primary));
            if (deptId != null) {
                db.update("""
                        INSERT INTO department_members (department_id, user_id, tenant_id, title, is_primary)
                        VALUES (:dept, :user, :tenant, :title, :primary)
                        """, Db.params("dept", deptId, "user", userId, "tenant", tenantId, "title", title, "primary", primary));
            }
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("from_organization_id", before == null ? "" : String.valueOf(before.get("organization_id")));
            detail.put("to_organization_id", orgId.toString());
            detail.put("to_department_id", deptId == null ? "" : deptId.toString());
            detail.put("reason", reason == null ? "" : reason);
            audit.orgHistory(tenantId, userId, orgId, deptId, "transfer", actorId, detail);
        });
        audit.success(tenantId, actorId, "user.transfer", "user", userId.toString(), meta,
                Map.of("organization_id", orgId.toString(), "department_id", deptId == null ? "" : deptId.toString()));
        outbox.publish("user.organization_changed", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "organization_id", orgId.toString(),
                "department_id", deptId == null ? "" : deptId.toString(),
                "reason", reason == null ? "" : reason));
        return Map.of("user_id", userId.toString(), "organization_id", orgId.toString(),
                "department_id", deptId == null ? "" : deptId.toString());
    }

    public List<Map<String, Object>> memberships(UUID tenantId, UUID userId) {
        return db.list("""
                SELECT 'organization' AS type, om.organization_id AS organization_id, o.name AS organization_name,
                       NULL::uuid AS department_id, NULL::text AS department_name,
                       om.title, om.is_primary, om.joined_at
                FROM organization_members om
                LEFT JOIN organizations o ON o.id = om.organization_id
                WHERE om.tenant_id = :tenant AND om.user_id = :user
                UNION ALL
                SELECT 'department' AS type, d.organization_id, o.name,
                       d.id, d.name, dm.title, dm.is_primary, dm.joined_at
                FROM department_members dm
                JOIN departments d ON d.id = dm.department_id
                LEFT JOIN organizations o ON o.id = d.organization_id
                WHERE dm.tenant_id = :tenant AND dm.user_id = :user
                ORDER BY joined_at DESC
                """, Db.params("tenant", tenantId, "user", userId));
    }

    private List<UUID> targetUsers(Body input) {
        List<UUID> userIds = input.uuids("user_ids");
        if (userIds.isEmpty()) {
            UUID single = input.uuid("user_id");
            if (single != null) {
                userIds = List.of(single);
            }
        }
        if (userIds.isEmpty()) {
            throw ApiException.validation("user_ids", "至少需要一个用户");
        }
        return userIds;
    }

    private void publishOrganizationChanged(UUID tenantId, List<UUID> userIds) {
        for (UUID userId : userIds) {
            outbox.publish("user.organization_changed", "user", userId.toString(), Map.of(
                    "identity_id", userId.toString(),
                    "tenant_id", tenantId.toString(),
                    "memberships", memberships(tenantId, userId)));
        }
    }

    private void requireUser(UUID tenantId, UUID userId) {
        if (db.count("""
                SELECT count(*) FROM users WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", userId)) == 0) {
            throw ApiException.notFound("用户不存在: " + userId);
        }
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
