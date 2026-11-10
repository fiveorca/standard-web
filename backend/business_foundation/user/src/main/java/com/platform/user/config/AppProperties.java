package com.platform.user.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "user")
public class AppProperties {
    private String internalToken = "";
    private String eventsTarget = "http://localhost:8080/api/v1/internal/events";
    private String cors = "";
    private boolean trustProxy = true;
    private final Auth auth = new Auth();
    private final Registration registration = new Registration();
    private final Batch batch = new Batch();

    public String getInternalToken() {
        return internalToken;
    }

    public void setInternalToken(String internalToken) {
        this.internalToken = internalToken;
    }

    public String getEventsTarget() {
        return eventsTarget;
    }

    public void setEventsTarget(String eventsTarget) {
        this.eventsTarget = eventsTarget;
    }

    public String getCors() {
        return cors;
    }

    public void setCors(String cors) {
        this.cors = cors;
    }

    public boolean isTrustProxy() {
        return trustProxy;
    }

    public void setTrustProxy(boolean trustProxy) {
        this.trustProxy = trustProxy;
    }

    public Auth getAuth() {
        return auth;
    }

    public Registration getRegistration() {
        return registration;
    }

    public Batch getBatch() {
        return batch;
    }

    public static class Auth {
        private String baseUrl = "http://localhost:8080";
        private String jwksUrl = "http://localhost:8080/oauth2/jwks";
        private String issuer = "";
        private String audience = "";
        private int timeoutSeconds = 5;
        private int jwksCacheSeconds = 300;

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public String getJwksUrl() {
            return jwksUrl;
        }

        public void setJwksUrl(String jwksUrl) {
            this.jwksUrl = jwksUrl;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public int getTimeoutSeconds() {
            return timeoutSeconds;
        }

        public void setTimeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
        }

        public int getJwksCacheSeconds() {
            return jwksCacheSeconds;
        }

        public void setJwksCacheSeconds(int jwksCacheSeconds) {
            this.jwksCacheSeconds = jwksCacheSeconds;
        }
    }

    public static class Registration {
        private boolean enabled = true;
        private boolean requireReview = true;
        private int rateLimitPerMinute = 10;
        private String defaultTenantId = "00000000-0000-0000-0000-000000000001";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isRequireReview() {
            return requireReview;
        }

        public void setRequireReview(boolean requireReview) {
            this.requireReview = requireReview;
        }

        public int getRateLimitPerMinute() {
            return rateLimitPerMinute;
        }

        public void setRateLimitPerMinute(int rateLimitPerMinute) {
            this.rateLimitPerMinute = rateLimitPerMinute;
        }

        public String getDefaultTenantId() {
            return defaultTenantId;
        }

        public void setDefaultTenantId(String defaultTenantId) {
            this.defaultTenantId = defaultTenantId;
        }
    }

    public static class Batch {
        private int maxItems = 500;

        public int getMaxItems() {
            return maxItems;
        }

        public void setMaxItems(int maxItems) {
            this.maxItems = maxItems;
        }
    }
}
