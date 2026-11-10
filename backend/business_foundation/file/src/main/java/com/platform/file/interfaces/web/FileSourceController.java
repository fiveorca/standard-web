package com.platform.file.interfaces.web;

import com.platform.file.application.FileSourceService;
import com.platform.file.application.command.FileSourceCommand;
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
@RequestMapping("/api/v1/file-sources")
public class FileSourceController {
    private final FileSourceService sources;

    public FileSourceController(FileSourceService sources) {
        this.sources = sources;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(defaultValue = "true") boolean include_disabled) {
        return Api.ok(sources.list(include_disabled));
    }

    @GetMapping("/{id}")
    public Map<String, Object> detail(@PathVariable String id) {
        return Api.ok(sources.detail(Ids.required(id, "id")));
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody Requests.FileSource request) {
        Map<String, Object> created = sources.create(command(request));
        return ResponseEntity.created(URI.create("/api/v1/file-sources/" + created.get("id")))
                .body(Api.ok(created));
    }

    @PatchMapping("/{id}")
    public Map<String, Object> update(@PathVariable String id, @RequestBody Requests.FileSource request) {
        return Api.ok(sources.update(Ids.required(id, "id"), command(request)));
    }

    @PostMapping("/{id}/enabled")
    public Map<String, Object> setEnabled(@PathVariable String id, @RequestBody Requests.Enabled request) {
        if (request == null || request.enabled() == null) {
            throw ApiException.validation("enabled", "enabled 不能为空");
        }
        return Api.ok(sources.setEnabled(Ids.required(id, "id"), request.enabled()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        sources.delete(Ids.required(id, "id"));
        return ResponseEntity.noContent().build();
    }

    private static FileSourceCommand command(Requests.FileSource request) {
        if (request == null) {
            throw ApiException.validation("body", "请求体不能为空");
        }
        return new FileSourceCommand(request.code(), request.name(), request.description(),
                request.enabled());
    }
}
