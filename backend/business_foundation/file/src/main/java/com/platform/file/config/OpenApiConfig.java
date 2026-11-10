package com.platform.file.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI fileServiceOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("File System Service API")
                        .version("1.0.0")
                        .description("统一文件存储服务：存储配置、服务端上传、分片上传、对象存储直传授权、"
                                + "文件记录、内容去重、临时下载授权、孤儿文件清理与一致性检查。"))
                .components(new Components().addSecuritySchemes("ApiKey",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-Key")))
                .addSecurityItem(new SecurityRequirement().addList("ApiKey"));
    }
}
