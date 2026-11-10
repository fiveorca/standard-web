package com.platform.file.domain.storage;

import java.util.List;

public record ObjectPage(List<ObjectMetadata> items, String nextCursor) {
    public boolean hasMore() {
        return nextCursor != null;
    }
}
