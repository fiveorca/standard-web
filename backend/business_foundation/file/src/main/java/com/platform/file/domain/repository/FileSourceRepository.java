package com.platform.file.domain.repository;

import com.platform.file.domain.model.FileSource;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FileSourceRepository {
    List<FileSource> findAll(boolean includeDisabled);

    Optional<FileSource> findById(UUID id);

    Optional<FileSource> findByCode(String code);

    void insert(FileSource source);

    void update(FileSource source);

    void delete(UUID id);
}
