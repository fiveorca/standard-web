package com.platform.im.infrastructure.email;

import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.shared.ApiException;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Component
public class EmailProviderRegistry {
    private final Map<EmailProviderType, EmailProvider> providers = new EnumMap<>(EmailProviderType.class);

    public EmailProviderRegistry(List<EmailProvider> providerList) {
        for (EmailProvider provider : providerList) {
            providers.put(provider.type(), provider);
        }
    }

    public EmailProvider require(EmailProviderType type) {
        EmailProvider provider = providers.get(type);
        if (provider == null) {
            throw ApiException.unavailable("未注册的邮件供应商类型: " + type);
        }
        return provider;
    }
}
