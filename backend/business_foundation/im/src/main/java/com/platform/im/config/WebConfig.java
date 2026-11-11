package com.platform.im.config;

import com.platform.im.infrastructure.ratelimit.RequestRateLimiter;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AppProperties props;
    private final AuditInterceptor auditInterceptor;
    private final RequestRateLimiter rateLimiter;

    public WebConfig(AppProperties props, AuditInterceptor auditInterceptor,
                     RequestRateLimiter rateLimiter) {
        this.props = props;
        this.auditInterceptor = auditInterceptor;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String origins = props.cors;
        registry.addMapping("/**")
                .allowedOriginPatterns(origins == null || origins.isBlank() ? new String[]{"*"} : origins.split(","))
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
                .allowedHeaders("*")
                .exposedHeaders("X-Request-Id")
                .allowCredentials(true)
                .maxAge(3600);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RateLimitInterceptor(rateLimiter))
                .addPathPatterns("/api/v1/**")
                .excludePathPatterns("/api/v1/internal/**");
        registry.addInterceptor(auditInterceptor).addPathPatterns("/api/v1/admin/**");
    }
}
