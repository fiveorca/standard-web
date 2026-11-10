package com.platform.user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AuthContextResolver authContextResolver;
    private final AppProperties props;

    public WebConfig(AuthContextResolver authContextResolver, AppProperties props) {
        this.authContextResolver = authContextResolver;
        this.props = props;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(authContextResolver);
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String origins = props.getCors();
        registry.addMapping("/**")
                .allowedOriginPatterns(origins == null || origins.isBlank() ? new String[]{"*"} : origins.split(","))
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .exposedHeaders("X-Request-Id", "ETag")
                .allowCredentials(true)
                .maxAge(3600);
    }

    @Bean
    public OncePerRequestFilter traceFilter() {
        return new TraceFilter();
    }
}
