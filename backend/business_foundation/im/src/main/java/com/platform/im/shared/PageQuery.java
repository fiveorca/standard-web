package com.platform.im.shared;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PageQuery(int page, int size) {
    public static final int MAX_SIZE = 200;

    public static PageQuery of(Integer page, Integer size) {
        int p = page == null || page < 1 ? 1 : page;
        int s = size == null || size < 1 ? 20 : Math.min(size, MAX_SIZE);
        return new PageQuery(p, s);
    }

    public Pageable pageable(Sort sort) {
        return PageRequest.of(page - 1, size, sort);
    }

    public Pageable pageable() {
        return PageRequest.of(page - 1, size);
    }
}
