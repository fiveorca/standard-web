package com.platform.file.application;

import com.platform.file.application.command.FileSourceCommand;
import com.platform.file.domain.model.FileSource;
import com.platform.file.domain.repository.FileSourceRepository;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Db;
import com.platform.file.shared.Ids;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class FileSourceService {
    private final FileSourceRepository repository;
    private final Db db;

    public FileSourceService(FileSourceRepository repository, Db db) {
        this.repository = repository;
        this.db = db;
    }

    public List<Map<String, Object>> list(boolean includeDisabled) {
        return repository.findAll(includeDisabled).stream().map(FileSourceService::view).toList();
    }

    public Map<String, Object> detail(UUID id) {
        return view(repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("文件来源类型不存在")));
    }

    public Map<String, Object> create(FileSourceCommand command) {
        String code = normalizeCode(command.code());
        String name = requireName(command.name());
        if (repository.findByCode(code).isPresent()) {
            throw ApiException.conflict("文件来源类型编码已存在: " + code);
        }
        FileSource source = new FileSource(Ids.uuidV7(), code, name,
                command.description(), command.enabled() == null || command.enabled(), null, null);
        repository.insert(source);
        return detail(source.id());
    }

    public Map<String, Object> update(UUID id, FileSourceCommand command) {
        FileSource existing = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("文件来源类型不存在"));
        String code = command.code() == null || command.code().isBlank()
                ? existing.code() : normalizeCode(command.code());
        if (!code.equals(existing.code())) {
            repository.findByCode(code).ifPresent(other -> {
                if (!other.id().equals(id)) {
                    throw ApiException.conflict("文件来源类型编码已存在: " + code);
                }
            });
            long references = db.count("SELECT count(*) FROM file_record WHERE source_type = :code",
                    Db.params("code", existing.code()));
            if (references > 0) {
                throw ApiException.conflict("该来源类型已被 " + references + " 条文件记录引用，不能修改编码");
            }
        }
        FileSource updated = new FileSource(id, code,
                command.name() == null || command.name().isBlank() ? existing.name() : command.name().trim(),
                command.description() == null ? existing.description() : command.description(),
                command.enabled() == null ? existing.enabled() : command.enabled(),
                existing.createdAt(), existing.updatedAt());
        repository.update(updated);
        return detail(id);
    }

    public Map<String, Object> setEnabled(UUID id, boolean enabled) {
        FileSource existing = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("文件来源类型不存在"));
        FileSource updated = new FileSource(existing.id(), existing.code(), existing.name(),
                existing.description(), enabled, existing.createdAt(), existing.updatedAt());
        repository.update(updated);
        return detail(id);
    }

    public void delete(UUID id) {
        FileSource existing = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("文件来源类型不存在"));
        long references = db.count("SELECT count(*) FROM file_record WHERE source_type = :code AND deleted_at IS NULL",
                Db.params("code", existing.code()));
        if (references > 0) {
            throw ApiException.conflict("该来源类型已被 " + references + " 条文件记录引用，不能删除");
        }
        repository.delete(id);
    }

    public void ensure(String code, String name, String description) {
        if (repository.findByCode(code).isPresent()) {
            return;
        }
        repository.insert(new FileSource(Ids.uuidV7(), code, name, description, true, null, null));
    }

    private static Map<String, Object> view(FileSource source) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", source.id().toString());
        out.put("code", source.code());
        out.put("name", source.name());
        out.put("description", source.description());
        out.put("enabled", source.enabled());
        out.put("created_at", source.createdAt() == null ? null : source.createdAt().toString());
        out.put("updated_at", source.updatedAt() == null ? null : source.updatedAt().toString());
        return out;
    }

    private static String normalizeCode(String code) {
        if (code == null || code.isBlank()) {
            throw ApiException.validation("code", "来源类型编码不能为空");
        }
        String value = code.trim();
        if (!value.matches("[A-Za-z0-9_.-]{1,64}")) {
            throw ApiException.validation("code", "来源类型编码只允许字母、数字、下划线、点和短横线，长度 1-64");
        }
        return value;
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw ApiException.validation("name", "来源类型名称不能为空");
        }
        return name.trim();
    }
}
