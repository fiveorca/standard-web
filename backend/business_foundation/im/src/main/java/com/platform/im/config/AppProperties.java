package com.platform.im.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * IM 服务全部可配置项。Spring Boot 4 的宽松绑定要求提供 JavaBean setter。
 */
@ConfigurationProperties(prefix = "im")
public class AppProperties {
    public String cors = "*";
    public Security security = new Security();
    public Encryption encryption = new Encryption();
    public Mqtt mqtt = new Mqtt();
    public Email email = new Email();
    public Grpc grpc = new Grpc();
    public Seed seed = new Seed();
    public RateLimit rateLimit = new RateLimit();

    public void setCors(String cors) {
        this.cors = cors;
    }

    public void setSecurity(Security security) {
        this.security = security;
    }

    public void setEncryption(Encryption encryption) {
        this.encryption = encryption;
    }

    public void setMqtt(Mqtt mqtt) {
        this.mqtt = mqtt;
    }

    public void setEmail(Email email) {
        this.email = email;
    }

    public void setGrpc(Grpc grpc) {
        this.grpc = grpc;
    }

    public void setSeed(Seed seed) {
        this.seed = seed;
    }

    public void setRateLimit(RateLimit rateLimit) {
        this.rateLimit = rateLimit;
    }

    public static class Security {
        public boolean enabled = true;
        public Jwt jwt = new Jwt();
        public String adminApiKey = "";
        public String internalToken = "";
        public String deviceTokenPepper = "";
        public String adminRole = "IM_ADMIN";
        public String serviceRole = "IM_SERVICE";

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setJwt(Jwt jwt) {
            this.jwt = jwt;
        }

        public void setAdminApiKey(String adminApiKey) {
            this.adminApiKey = adminApiKey;
        }

        public void setInternalToken(String internalToken) {
            this.internalToken = internalToken;
        }

        public void setDeviceTokenPepper(String deviceTokenPepper) {
            this.deviceTokenPepper = deviceTokenPepper;
        }

        public void setAdminRole(String adminRole) {
            this.adminRole = adminRole;
        }

        public void setServiceRole(String serviceRole) {
            this.serviceRole = serviceRole;
        }
    }

    public static class Jwt {
        public String hmacSecret = "";
        public String jwksUrl = "";
        public String issuer = "";
        public String audience = "";
        public String rolesClaim = "roles";
        public String tenantClaim = "tenant_id";
        public long clockSkewSeconds = 30;

        public void setHmacSecret(String hmacSecret) {
            this.hmacSecret = hmacSecret;
        }

        public void setJwksUrl(String jwksUrl) {
            this.jwksUrl = jwksUrl;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public void setRolesClaim(String rolesClaim) {
            this.rolesClaim = rolesClaim;
        }

        public void setTenantClaim(String tenantClaim) {
            this.tenantClaim = tenantClaim;
        }

        public void setClockSkewSeconds(long clockSkewSeconds) {
            this.clockSkewSeconds = clockSkewSeconds;
        }
    }

    public static class Encryption {
        public String key = "";

        public void setKey(String key) {
            this.key = key;
        }
    }

    public static class Mqtt {
        public String clientIdPrefix = "im-service-publisher";
        public int connectTimeoutSeconds = 10;
        public int keepAliveSeconds = 60;
        public long sessionExpirySeconds = 0;
        public int maxInflight = 100;
        public int reconnectDelaySeconds = 5;
        public int publishTimeoutSeconds = 10;
        public long statusCheckIntervalMs = 30000;
        public int maxPayloadBytes = 262144;
        public int defaultQos = 1;
        public String serviceTopicPrefix = "tenants/";

        public void setClientIdPrefix(String clientIdPrefix) {
            this.clientIdPrefix = clientIdPrefix;
        }

        public void setConnectTimeoutSeconds(int connectTimeoutSeconds) {
            this.connectTimeoutSeconds = connectTimeoutSeconds;
        }

        public void setKeepAliveSeconds(int keepAliveSeconds) {
            this.keepAliveSeconds = keepAliveSeconds;
        }

        public void setSessionExpirySeconds(long sessionExpirySeconds) {
            this.sessionExpirySeconds = sessionExpirySeconds;
        }

        public void setMaxInflight(int maxInflight) {
            this.maxInflight = maxInflight;
        }

        public void setReconnectDelaySeconds(int reconnectDelaySeconds) {
            this.reconnectDelaySeconds = reconnectDelaySeconds;
        }

        public void setPublishTimeoutSeconds(int publishTimeoutSeconds) {
            this.publishTimeoutSeconds = publishTimeoutSeconds;
        }

        public void setStatusCheckIntervalMs(long statusCheckIntervalMs) {
            this.statusCheckIntervalMs = statusCheckIntervalMs;
        }

        public void setMaxPayloadBytes(int maxPayloadBytes) {
            this.maxPayloadBytes = maxPayloadBytes;
        }

        public void setDefaultQos(int defaultQos) {
            this.defaultQos = defaultQos;
        }

        public void setServiceTopicPrefix(String serviceTopicPrefix) {
            this.serviceTopicPrefix = serviceTopicPrefix;
        }
    }

    public static class Email {
        public boolean workerEnabled = true;
        public long pollIntervalMs = 2000;
        public int batchSize = 20;
        public int maxAttempts = 5;
        public long retryBaseSeconds = 60;
        public long retryMaxSeconds = 3600;
        public long lockTimeoutSeconds = 900;
        public String attachmentDir = "./data/email-attachments";
        public long maxAttachmentBytes = 10485760L;
        public long maxTotalAttachmentBytes = 26214400L;
        public String allowedAttachmentExtensions =
                "pdf,doc,docx,xls,xlsx,ppt,pptx,txt,csv,json,xml,zip,gz,png,jpg,jpeg,gif,webp";
        public int maxRecipients = 100;
        public boolean rateLimitEnabled = true;
        public String workerId = "";

        public void setWorkerEnabled(boolean workerEnabled) {
            this.workerEnabled = workerEnabled;
        }

        public void setPollIntervalMs(long pollIntervalMs) {
            this.pollIntervalMs = pollIntervalMs;
        }

        public void setBatchSize(int batchSize) {
            this.batchSize = batchSize;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public void setRetryBaseSeconds(long retryBaseSeconds) {
            this.retryBaseSeconds = retryBaseSeconds;
        }

        public void setRetryMaxSeconds(long retryMaxSeconds) {
            this.retryMaxSeconds = retryMaxSeconds;
        }

        public void setLockTimeoutSeconds(long lockTimeoutSeconds) {
            this.lockTimeoutSeconds = lockTimeoutSeconds;
        }

        public void setAttachmentDir(String attachmentDir) {
            this.attachmentDir = attachmentDir;
        }

        public void setMaxAttachmentBytes(long maxAttachmentBytes) {
            this.maxAttachmentBytes = maxAttachmentBytes;
        }

        public void setMaxTotalAttachmentBytes(long maxTotalAttachmentBytes) {
            this.maxTotalAttachmentBytes = maxTotalAttachmentBytes;
        }

        public void setAllowedAttachmentExtensions(String allowedAttachmentExtensions) {
            this.allowedAttachmentExtensions = allowedAttachmentExtensions;
        }

        public void setMaxRecipients(int maxRecipients) {
            this.maxRecipients = maxRecipients;
        }

        public void setRateLimitEnabled(boolean rateLimitEnabled) {
            this.rateLimitEnabled = rateLimitEnabled;
        }

        public void setWorkerId(String workerId) {
            this.workerId = workerId;
        }
    }

    public static class Grpc {
        public boolean enabled = true;
        public int port = 9091;
        public boolean authEnabled = true;
        public boolean tlsEnabled = false;
        public boolean requireClientAuth = false;
        public String certificateChainPath = "";
        public String privateKeyPath = "";
        public String trustCertificatePath = "";
        public int maxInboundMessageSize = 16777216;

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public void setAuthEnabled(boolean authEnabled) {
            this.authEnabled = authEnabled;
        }

        public void setTlsEnabled(boolean tlsEnabled) {
            this.tlsEnabled = tlsEnabled;
        }

        public void setRequireClientAuth(boolean requireClientAuth) {
            this.requireClientAuth = requireClientAuth;
        }

        public void setCertificateChainPath(String certificateChainPath) {
            this.certificateChainPath = certificateChainPath;
        }

        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }

        public void setTrustCertificatePath(String trustCertificatePath) {
            this.trustCertificatePath = trustCertificatePath;
        }

        public void setMaxInboundMessageSize(int maxInboundMessageSize) {
            this.maxInboundMessageSize = maxInboundMessageSize;
        }
    }

    public static class Seed {
        public boolean enabled = true;
        public String brokerCode = "emqx-default";
        public String brokerName = "EMQX Default";
        public String brokerHost = "localhost";
        public int brokerTcpPort = 1883;
        public int brokerTlsPort = 8883;
        public boolean brokerTlsEnabled = false;
        public String accessConfigCode = "default";
        public String tenantId = "";
        public String serviceTopicPrefix = "tenants/";

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setBrokerCode(String brokerCode) {
            this.brokerCode = brokerCode;
        }

        public void setBrokerName(String brokerName) {
            this.brokerName = brokerName;
        }

        public void setBrokerHost(String brokerHost) {
            this.brokerHost = brokerHost;
        }

        public void setBrokerTcpPort(int brokerTcpPort) {
            this.brokerTcpPort = brokerTcpPort;
        }

        public void setBrokerTlsPort(int brokerTlsPort) {
            this.brokerTlsPort = brokerTlsPort;
        }

        public void setBrokerTlsEnabled(boolean brokerTlsEnabled) {
            this.brokerTlsEnabled = brokerTlsEnabled;
        }

        public void setAccessConfigCode(String accessConfigCode) {
            this.accessConfigCode = accessConfigCode;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public void setServiceTopicPrefix(String serviceTopicPrefix) {
            this.serviceTopicPrefix = serviceTopicPrefix;
        }
    }

    public static class RateLimit {
        public boolean enabled = true;
        public int httpPerMinute = 600;
        public int grpcPerMinute = 6000;

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public void setHttpPerMinute(int httpPerMinute) {
            this.httpPerMinute = httpPerMinute;
        }

        public void setGrpcPerMinute(int grpcPerMinute) {
            this.grpcPerMinute = grpcPerMinute;
        }
    }
}
