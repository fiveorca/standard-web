package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "email_attachment")
public class EmailAttachment extends BaseEntity {
    @Column(name = "task_id", nullable = false)
    public UUID taskId;

    @Column(name = "filename", nullable = false)
    public String filename;

    @Column(name = "content_type")
    public String contentType;

    @Column(name = "file_size", nullable = false)
    public long fileSize;

    @Column(name = "storage_path", nullable = false)
    public String storagePath;

    @Column(name = "sha256", nullable = false)
    public String sha256;
}
