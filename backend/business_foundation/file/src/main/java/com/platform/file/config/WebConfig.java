package com.platform.file.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AppProperties props;

    public WebConfig(AppProperties props) {
        this.props = props;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String origins = props.cors;
        registry.addMapping("/**")
                .allowedOriginPatterns(origins == null || origins.isBlank() ? new String[]{"*"} : origins.split(","))
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
                .allowedHeaders("*")
                .exposedHeaders("X-Request-Id", "ETag", "Content-Disposition")
                .allowCredentials(true)
                .maxAge(3600);
    }

    @Bean
    public OncePerRequestFilter traceFilter() {
        return new TraceFilter();
    }
}
