package com.platform.file.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 文件服务配置。Spring Boot 4 的 @ConfigurationProperties 仅通过 JavaBean setter 绑定，
 * 因此每个可配置项都必须提供 setter（字段保持 public 以便调用方直接读取）。
 */
@ConfigurationProperties(prefix = "file")
public class AppProperties {
    public String publicBaseUrl = "http://localhost:8082";
    public String cors = "*";
    public boolean trustProxy = true;
    public Security security = new Security();
    public Storage storage = new Storage();
    public Upload upload = new Upload();
    public Download download = new Download();
    public Cleanup cleanup = new Cleanup();
    public Encryption encryption = new Encryption();
    public Seed seed = new Seed();

    public void setPublicBaseUrl(String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
    }

    public void setCors(String cors) {
        this.cors = cors;
    }

    public void setTrustProxy(boolean trustProxy) {
        this.trustProxy = trustProxy;
    }

    public void setSecurity(Security security) {
        this.security = security;
    }

    public void setStorage(Storage storage) {
        this.storage = storage;
    }

    public void setUpload(Upload upload) {
        this.upload = upload;
    }

    public void setDownload(Download download) {
        this.download = download;
    }

    public void setCleanup(Cleanup cleanup) {
        this.cleanup = cleanup;
    }

    public void setEncryption(Encryption encryption) {
        this.encryption = encryption;
    }

    public void setSeed(Seed seed) {
        this.seed = seed;
    }

    public static class Security {
        public String apiKey = "";
        public long maxFileSize = 5L * 1024 * 1024 * 1024;
        public String allowedExtensions = "";
        public String allowedMimeTypes = "";
        public boolean sniffContent = true;

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public void setMaxFileSize(long maxFileSize) {
            this.maxFileSize = maxFileSize;
        }

        public void setAllowedExtensions(String allowedExtensions) {
            this.allowedExtensions = allowedExtensions;
        }

        public void setAllowedMimeTypes(String allowedMimeTypes) {
            this.allowedMimeTypes = allowedMimeTypes;
        }

        public void setSniffContent(boolean sniffContent) {
            this.sniffContent = sniffContent;
        }
    }

    public static class Storage {
        public String localRoot = "./data/storage";
        public String tempPrefix = "temporary/";
        public String permanentPrefix = "permanent/";
        public String uploadWorkDir = "./data/upload-tmp";

        public void setLocalRoot(String localRoot) {
            this.localRoot = localRoot;
        }

        public void setTempPrefix(String tempPrefix) {
            this.tempPrefix = tempPrefix;
        }

        public void setPermanentPrefix(String permanentPrefix) {
            this.permanentPrefix = permanentPrefix;
        }

        public void setUploadWorkDir(String uploadWorkDir) {
            this.uploadWorkDir = uploadWorkDir;
        }
    }

    public static class Upload {
        public long expirySeconds = 3600;
        public long maxPartSize = 100L * 1024 * 1024;
        public long minPartSize = 5L * 1024 * 1024;
        public int maxParts = 1000;
        public long confirmTimeoutMinutes = 30;

        public void setExpirySeconds(long expirySeconds) {
            this.expirySeconds = expirySeconds;
        }

        public void setMaxPartSize(long maxPartSize) {
            this.maxPartSize = maxPartSize;
        }

        public void setMinPartSize(long minPartSize) {
            this.minPartSize = minPartSize;
        }

        public void setMaxParts(int maxParts) {
            this.maxParts = maxParts;
        }

        public void setConfirmTimeoutMinutes(long confirmTimeoutMinutes) {
            this.confirmTimeoutMinutes = confirmTimeoutMinutes;
        }
    }

    public static class Download {
        public long urlTtlSeconds = 300;
        public String tokenSecret = "";

        public void setUrlTtlSeconds(long urlTtlSeconds) {
            this.urlTtlSeconds = urlTtlSeconds;
        }

        public void setTokenSecret(String tokenSecret) {
            this.tokenSecret = tokenSecret;
        }
    }

    public static class Cleanup {
        public boolean enabled = true;
        public boolean dryRun = false;
        public long orphanSafetyMinutes = 1440;
        public long deleteGraceMinutes = 10;
        public int batchSize = 200;
        public int maxPerRun = 1000;
        public long lockSeconds = 900;
        public long expiryIntervalMs = 60000;
        public long deleteIntervalMs = 300000;
        public long scanIntervalMs = 3600000;
        public long consistencyIntervalMs = 3600000;

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setDryRun(boolean dryRun) {
            this.dryRun = dryRun;
        }

        public void setOrphanSafetyMinutes(long orphanSafetyMinutes) {
            this.orphanSafetyMinutes = orphanSafetyMinutes;
        }

        public void setDeleteGraceMinutes(long deleteGraceMinutes) {
            this.deleteGraceMinutes = deleteGraceMinutes;
        }

        public void setBatchSize(int batchSize) {
            this.batchSize = batchSize;
        }

        public void setMaxPerRun(int maxPerRun) {
            this.maxPerRun = maxPerRun;
        }

        public void setLockSeconds(long lockSeconds) {
            this.lockSeconds = lockSeconds;
        }

        public void setExpiryIntervalMs(long expiryIntervalMs) {
            this.expiryIntervalMs = expiryIntervalMs;
        }

        public void setDeleteIntervalMs(long deleteIntervalMs) {
            this.deleteIntervalMs = deleteIntervalMs;
        }

        public void setScanIntervalMs(long scanIntervalMs) {
            this.scanIntervalMs = scanIntervalMs;
        }

        public void setConsistencyIntervalMs(long consistencyIntervalMs) {
            this.consistencyIntervalMs = consistencyIntervalMs;
        }
    }

    public static class Encryption {
        public String key = "";

        public void setKey(String key) {
            this.key = key;
        }
    }

    public static class Seed {
        public boolean enabled = true;
        public String localProviderCode = "local-default";

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setLocalProviderCode(String localProviderCode) {
            this.localProviderCode = localProviderCode;
        }
    }
}
