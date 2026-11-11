package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailAttachment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface EmailAttachmentRepository extends JpaRepository<EmailAttachment, UUID> {
    List<EmailAttachment> findByTaskIdOrderByCreatedAtAsc(UUID taskId);

    void deleteByTaskId(UUID taskId);
}
