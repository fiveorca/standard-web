package com.platform.file.application;

import java.util.List;
import java.util.Map;

public record DirectAuthorization(
        Map<String, Object> upload,
        Map<String, Object> authorization,
        List<Map<String, Object>> partUrls) {
}
