package com.faithsafe.api.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.security.SecurityScheme;

@OpenAPIDefinition(
    servers = {
        @Server(
            description = "Local server",
            url = "http://localhost:8080/"
        ),
        @Server(
            description = "Production server",
            url = "https://api.faithsafe.net/"
        )
    },
    security = {
        @SecurityRequirement(name = "bearerAuth")
    }
)
@Configuration
public class OpenApiConfig {

  @Bean
  public OpenAPI customApi() {
    return new OpenAPI()
        .components(new io.swagger.v3.oas.models.Components()
            .addSecuritySchemes(
                "BearerAuth",
                new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .description("Auth with JWT Token")
                    .bearerFormat("JWT")
            ));
  }
}
