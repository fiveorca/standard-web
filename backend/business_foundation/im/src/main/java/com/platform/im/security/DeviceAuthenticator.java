package com.platform.im.security;

import java.util.UUID;

public interface DeviceAuthenticator {
    AuthPrincipal authenticate(String deviceId, String token, UUID tenantId);

    AuthPrincipal resolve(String deviceId, UUID tenantId);
}
