package com.platform.file.domain.repository;

import com.platform.file.domain.model.StorageProviderRow;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface StorageProviderRepository {
    List<StorageProviderRow> findAll(boolean includeDisabled);

    Optional<StorageProviderRow> findById(UUID id);

    Optional<StorageProviderRow> findByCode(String code);

    Optional<StorageProviderRow> findDefault();

    void insert(StorageProviderRow row);

    void update(StorageProviderRow row);

    void delete(UUID id);

    void clearDefault(UUID exceptId);

    void setDefault(UUID id);

    void setEnabled(UUID id, boolean enabled);

    void updateHealth(UUID id, String status, String message);

    long countFileObjects(UUID providerId);
}
