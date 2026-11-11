package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailSenderConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface EmailSenderConfigRepository extends JpaRepository<EmailSenderConfig, UUID> {
    Optional<EmailSenderConfig> findBySenderId(UUID senderId);

    void deleteBySenderId(UUID senderId);
}
