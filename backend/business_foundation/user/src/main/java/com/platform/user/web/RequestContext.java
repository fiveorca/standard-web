package com.platform.user.web;

import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Ids;
import com.platform.user.common.RequestMeta;
import com.platform.user.config.AppProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@Component
public class RequestContext {
    private final AppProperties props;

    public RequestContext(AppProperties props) {
        this.props = props;
    }

    public RequestMeta meta(HttpServletRequest request) {
        return RequestMeta.from(request, props.isTrustProxy());
    }

    public UUID id(String raw, String field) {
        UUID id = Ids.parse(raw);
        if (id == null) {
            throw ApiException.validation(field, "ID 格式不合法");
        }
        return id;
    }

    public Integer version(String ifMatch, Map<String, Object> body) {
        if (ifMatch != null && !ifMatch.isBlank() && !"*".equals(ifMatch.trim())) {
            String value = ifMatch.trim();
            if (value.startsWith("W/")) {
                value = value.substring(2);
            }
            value = value.replace("\"", "");
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw ApiException.validation("If-Match", "版本号格式不合法");
            }
        }
        return Body.of(body).integer("version");
    }

    public static ResponseEntity<Object> csv(String content, String filename) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(bytes);
    }

    public static ResponseEntity<Object> jsonText(Object data) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8")
                .body(com.platform.user.common.Json.write(data));
    }
}
