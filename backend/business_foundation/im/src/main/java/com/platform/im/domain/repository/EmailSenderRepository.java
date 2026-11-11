package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailSender;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailSenderRepository extends JpaRepository<EmailSender, UUID> {
    Optional<EmailSender> findByIdAndDeletedFalse(UUID id);

    Optional<EmailSender> findByCodeIgnoreCaseAndDeletedFalse(String code);

    boolean existsByCodeIgnoreCaseAndDeletedFalse(String code);

    Optional<EmailSender> findFirstByDefaultSenderTrueAndDeletedFalse();

    Optional<EmailSender> findFirstByTenantIdAndDefaultSenderTrueAndDeletedFalse(UUID tenantId);

    Page<EmailSender> findByDeletedFalse(Pageable pageable);

    Page<EmailSender> findByTenantIdAndDeletedFalse(UUID tenantId, Pageable pageable);

    Page<EmailSender> findByCodeContainingIgnoreCaseAndDeletedFalse(String code, Pageable pageable);

    List<EmailSender> findByDeletedFalseOrderByNameAsc();

    long countByDefaultSenderTrueAndDeletedFalse();
}
