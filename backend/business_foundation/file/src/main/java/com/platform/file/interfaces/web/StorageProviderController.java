package com.platform.file.interfaces.web;

import com.platform.file.application.StorageProviderService;
import com.platform.file.application.command.StorageProviderCommand;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.interfaces.dto.Requests;
import com.platform.file.shared.Api;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/storage-providers")
public class StorageProviderController {
    private final StorageProviderService service;

    public StorageProviderController(StorageProviderService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody Requests.StorageProvider request) {
        Map<String, Object> created = service.create(command(request));
        return ResponseEntity.created(URI.create("/api/v1/storage-providers/" + created.get("id")))
                .body(Api.ok(created));
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(defaultValue = "true") boolean include_disabled) {
        return Api.ok(service.list(include_disabled));
    }

    @GetMapping("/{id}")
    public Map<String, Object> detail(@PathVariable String id) {
        return Api.ok(service.detail(Ids.required(id, "id")));
    }

    @PatchMapping("/{id}")
    public Map<String, Object> update(@PathVariable String id,
                                      @RequestBody Requests.StorageProvider request) {
        return Api.ok(service.update(Ids.required(id, "id"), command(request)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        service.delete(Ids.required(id, "id"));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/test")
    public Map<String, Object> test(@PathVariable String id) {
        return Api.ok(service.test(Ids.required(id, "id")));
    }

    @PostMapping("/{id}/default")
    public Map<String, Object> setDefault(@PathVariable String id) {
        service.setDefault(Ids.required(id, "id"));
        return Api.ok(service.detail(Ids.required(id, "id")));
    }

    @PostMapping("/{id}/enabled")
    public Map<String, Object> setEnabled(@PathVariable String id, @RequestBody Requests.Enabled request) {
        if (request == null || request.enabled() == null) {
            throw ApiException.validation("enabled", "enabled 不能为空");
        }
        var providerId = Ids.required(id, "id");
        service.setEnabled(providerId, request.enabled());
        return Api.ok(service.detail(providerId));
    }

    private static StorageProviderCommand command(Requests.StorageProvider request) {
        if (request == null) {
            throw ApiException.validation("body", "请求体不能为空");
        }
        return new StorageProviderCommand(
                request.code(),
                request.name(),
                StorageType.parse(request.type()),
                request.endpoint(),
                request.region(),
                request.bucket(),
                request.root_path(),
                request.access_key(),
                request.secret_key(),
                request.access_key_env(),
                request.secret_key_env(),
                request.enabled(),
                request.default_provider(),
                request.allow_upload(),
                request.allow_download(),
                request.allow_delete(),
                request.options());
    }
}
