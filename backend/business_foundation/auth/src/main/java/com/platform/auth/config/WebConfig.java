package com.platform.auth.config;

import com.platform.auth.common.AuthContextResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AuthContextResolver authContextResolver;
    private final AppProps props;

    public WebConfig(AuthContextResolver authContextResolver, AppProps props) {
        this.authContextResolver = authContextResolver;
        this.props = props;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(authContextResolver);
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String origins = props.getCorsOrigins();
        registry.addMapping("/**")
                .allowedOriginPatterns(origins == null || origins.isBlank() ? new String[]{"*"} : origins.split(","))
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .exposedHeaders("X-Request-Id")
                .allowCredentials(true)
                .maxAge(3600);
    }

    @Bean
    public org.springframework.web.filter.OncePerRequestFilter traceFilter() {
        return new TraceFilter();
    }
}
