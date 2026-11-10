package com.platform.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public class AppProps {
    private String issuer = "http://localhost:8080";
    private String baseUrl = "http://localhost:8080";
    private String internalToken = "dev-internal-token-change-me";
    private String encryptionKey = "dev-encryption-key-change-me-32bytes";
    private String cookieDomain = "";
    private boolean cookieSecure = false;
    private String corsOrigins = "*";
    private boolean registrationEnabled = true;
    private boolean requireEmailVerification = false;
    private long accessTokenTtl = 900;
    private long refreshTokenTtl = 2592000;
    private long idTokenTtl = 900;
    private long sessionTtl = 604800;
    private long codeTtl = 300;
    private String eventsTarget = "http://localhost:8081/api/v1/internal/events";
    private String userServiceUrl = "http://localhost:8081";
    private String notificationWebhook = "";
    private int loginMaxAttempts = 5;
    private long loginLockSeconds = 900;
    private long otpTtlSeconds = 300;
    private long passwordMaxAgeDays = 0;
    private String webauthnRpId = "localhost";
    private String webauthnRpName = "Auth Center";
    private String webauthnOrigin = "http://localhost:8080";
    private boolean bootstrapEnabled = true;
    private String bootstrapAdminUsername = "admin";
    private String bootstrapAdminEmail = "admin@example.com";
    private String bootstrapAdminPassword = "Admin@12345";
    private String bootstrapClientSecret = "dev-client-secret-change-me";

    public String getIssuer() { return issuer; }
    public void setIssuer(String v) { this.issuer = v; }
    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String v) { this.baseUrl = v; }
    public String getInternalToken() { return internalToken; }
    public void setInternalToken(String v) { this.internalToken = v; }
    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String v) { this.encryptionKey = v; }
    public String getCookieDomain() { return cookieDomain; }
    public void setCookieDomain(String v) { this.cookieDomain = v; }
    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean v) { this.cookieSecure = v; }
    public String getCorsOrigins() { return corsOrigins; }
    public void setCorsOrigins(String v) { this.corsOrigins = v; }
    public boolean isRegistrationEnabled() { return registrationEnabled; }
    public void setRegistrationEnabled(boolean v) { this.registrationEnabled = v; }
    public boolean isRequireEmailVerification() { return requireEmailVerification; }
    public void setRequireEmailVerification(boolean v) { this.requireEmailVerification = v; }
    public long getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(long v) { this.accessTokenTtl = v; }
    public long getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(long v) { this.refreshTokenTtl = v; }
    public long getIdTokenTtl() { return idTokenTtl; }
    public void setIdTokenTtl(long v) { this.idTokenTtl = v; }
    public long getSessionTtl() { return sessionTtl; }
    public void setSessionTtl(long v) { this.sessionTtl = v; }
    public long getCodeTtl() { return codeTtl; }
    public void setCodeTtl(long v) { this.codeTtl = v; }
    public String getEventsTarget() { return eventsTarget; }
    public void setEventsTarget(String v) { this.eventsTarget = v; }
    public String getUserServiceUrl() { return userServiceUrl; }
    public void setUserServiceUrl(String v) { this.userServiceUrl = v; }
    public String getNotificationWebhook() { return notificationWebhook; }
    public void setNotificationWebhook(String v) { this.notificationWebhook = v; }
    public int getLoginMaxAttempts() { return loginMaxAttempts; }
    public void setLoginMaxAttempts(int v) { this.loginMaxAttempts = v; }
    public long getLoginLockSeconds() { return loginLockSeconds; }
    public void setLoginLockSeconds(long v) { this.loginLockSeconds = v; }
    public long getOtpTtlSeconds() { return otpTtlSeconds; }
    public void setOtpTtlSeconds(long v) { this.otpTtlSeconds = v; }
    public long getPasswordMaxAgeDays() { return passwordMaxAgeDays; }
    public void setPasswordMaxAgeDays(long v) { this.passwordMaxAgeDays = v; }
    public String getWebauthnRpId() { return webauthnRpId; }
    public void setWebauthnRpId(String v) { this.webauthnRpId = v; }
    public String getWebauthnRpName() { return webauthnRpName; }
    public void setWebauthnRpName(String v) { this.webauthnRpName = v; }
    public String getWebauthnOrigin() { return webauthnOrigin; }
    public void setWebauthnOrigin(String v) { this.webauthnOrigin = v; }
    public boolean isBootstrapEnabled() { return bootstrapEnabled; }
    public void setBootstrapEnabled(boolean v) { this.bootstrapEnabled = v; }
    public String getBootstrapAdminUsername() { return bootstrapAdminUsername; }
    public void setBootstrapAdminUsername(String v) { this.bootstrapAdminUsername = v; }
    public String getBootstrapAdminEmail() { return bootstrapAdminEmail; }
    public void setBootstrapAdminEmail(String v) { this.bootstrapAdminEmail = v; }
    public String getBootstrapAdminPassword() { return bootstrapAdminPassword; }
    public void setBootstrapAdminPassword(String v) { this.bootstrapAdminPassword = v; }
    public String getBootstrapClientSecret() { return bootstrapClientSecret; }
    public void setBootstrapClientSecret(String v) { this.bootstrapClientSecret = v; }
}
