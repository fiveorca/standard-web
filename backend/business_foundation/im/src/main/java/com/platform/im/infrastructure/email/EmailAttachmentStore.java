package com.platform.im.infrastructure.email;

import com.platform.im.config.AppProperties;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.CryptoService;
import com.platform.im.shared.Ids;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 邮件附件落盘存储。文件名做安全清洗，限制扩展名与大小。
 */
@Component
public class EmailAttachmentStore {
    private final AppProperties props;
    private final Set<String> allowedExtensions;
    private final Path root;

    public EmailAttachmentStore(AppProperties props) {
        this.props = props;
        this.allowedExtensions = Arrays.stream(props.email.allowedAttachmentExtensions.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        this.root = Paths.get(props.email.attachmentDir).toAbsolutePath().normalize();
    }

    public StoredAttachment store(UUID taskId, String filename, String contentType, byte[] content) {
        if (content == null || content.length == 0) {
            throw ApiException.validation("attachments", "附件内容不能为空");
        }
        if (content.length > props.email.maxAttachmentBytes) {
            throw ApiException.payloadTooLarge("单个附件超过大小限制 " + props.email.maxAttachmentBytes + " 字节");
        }
        String safeName = sanitize(filename);
        String extension = extension(safeName);
        if (!allowedExtensions.isEmpty() && !allowedExtensions.contains(extension)) {
            throw ApiException.validation("attachments", "不允许的附件类型: " + extension);
        }
        try {
            Path dir = root.resolve(taskId.toString());
            Files.createDirectories(dir);
            Path target = dir.resolve(Ids.uuid() + "-" + safeName);
            Files.write(target, content, StandardOpenOption.CREATE_NEW);
            return new StoredAttachment(target.toString(), safeName,
                    contentType == null || contentType.isBlank() ? "application/octet-stream" : contentType,
                    content.length, CryptoService.sha256Base64(content));
        } catch (IOException e) {
            throw ApiException.internal("附件保存失败: " + e.getMessage());
        }
    }

    public byte[] read(String storagePath) {
        try {
            return Files.readAllBytes(Paths.get(storagePath));
        } catch (IOException e) {
            throw ApiException.internal("附件读取失败: " + e.getMessage());
        }
    }

    public void delete(String storagePath) {
        try {
            Files.deleteIfExists(Paths.get(storagePath));
        } catch (IOException ignored) {
            // 附件清理失败不应影响主流程
        }
    }

    private static String sanitize(String filename) {
        String value = filename == null ? "" : filename.trim();
        value = value.replace('\\', '/');
        int slash = value.lastIndexOf('/');
        if (slash >= 0) {
            value = value.substring(slash + 1);
        }
        value = value.replaceAll("[\\p{Cntrl}]", "_").replaceAll("[\\s]+", "_");
        if (value.isBlank() || ".".equals(value) || "..".equals(value)) {
            value = "attachment.bin";
        }
        if (value.length() > 200) {
            value = value.substring(value.length() - 200);
        }
        return value;
    }

    private static String extension(String filename) {
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) {
            return "";
        }
        return filename.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    public record StoredAttachment(String storagePath, String filename, String contentType,
                                   long size, String sha256) {
    }
}
