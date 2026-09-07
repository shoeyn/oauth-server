package com.example.authserver.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Cross-Origin Resource Sharing (CORS) configuration for OAuth 2.1 & OIDC public endpoints.
 * Allows web-based Single Page Applications (SPAs) and external clients to discover metadata,
 * fetch public JWKS, exchange authorization codes with DPoP proofs, and query userinfo.
 */
@Configuration
public class CorsConfig {

    @Value("${auth.cors.allowed-origins:*}")
    private String allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        if ("*".equals(allowedOrigins.trim())) {
            config.addAllowedOriginPattern("*");
        } else {
            List<String> origins = Arrays.stream(allowedOrigins.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList();
            config.setAllowedOrigins(origins);
        }

        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "DELETE"));
        config.setAllowedHeaders(List.of(
                "Authorization",
                "DPoP",
                "Content-Type",
                "If-None-Match",
                "X-Admin-Api-Key",
                "X-Requested-With",
                "Accept"
        ));
        config.setExposedHeaders(List.of("ETag", "DPoP-Nonce"));
        config.setMaxAge(3600L);
        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
