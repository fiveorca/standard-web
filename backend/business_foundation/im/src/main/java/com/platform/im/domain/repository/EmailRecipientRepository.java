package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailRecipient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface EmailRecipientRepository extends JpaRepository<EmailRecipient, UUID> {
    List<EmailRecipient> findByTaskIdOrderByCreatedAtAsc(UUID taskId);
}
