package com.platform.user.common;

public record PageQuery(int page, int pageSize) {
    public static final int DEFAULT_PAGE = 1;
    public static final int DEFAULT_SIZE = 20;
    public static final int MAX_SIZE = 200;

    public static PageQuery of(Integer page, Integer size) {
        int p = page == null || page < 1 ? DEFAULT_PAGE : page;
        int s = size == null || size < 1 ? DEFAULT_SIZE : Math.min(size, MAX_SIZE);
        return new PageQuery(p, s);
    }

    public static PageQuery parse(String page, String size) {
        Integer p = null;
        Integer s = null;
        if (page != null && !page.isBlank()) {
            try {
                p = Integer.parseInt(page.trim());
            } catch (NumberFormatException e) {
                throw ApiException.validation("page", "必须为整数");
            }
        }
        if (size != null && !size.isBlank()) {
            try {
                s = Integer.parseInt(size.trim());
            } catch (NumberFormatException e) {
                throw ApiException.validation("page_size", "必须为整数");
            }
        }
        return of(p, s);
    }

    public static PageQuery of(java.util.Map<String, String> query) {
        return parse(query.get("page"), query.get("page_size"));
    }

    public long offset() {
        return (long) (page - 1) * pageSize;
    }

    public long limit() {
        return pageSize;
    }
}
