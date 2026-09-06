package com.example.authserver.config;

import com.example.authserver.security.AuthenticatedUser;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            Authentication principal = context.getPrincipal();
            AuthenticatedUser userDetails = null;

            if (principal != null && principal.getDetails() instanceof AuthenticatedUser user) {
                userDetails = user;
            } else {
                org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization =
                        context.get(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.class);
                if (authorization != null) {
                    Authentication userAuth = authorization.getAttribute(java.security.Principal.class.getName());
                    if (userAuth != null && userAuth.getDetails() instanceof AuthenticatedUser user) {
                        userDetails = user;
                        principal = userAuth;
                    }
                }
            }

            // Customizing Access Token (user_token)
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                // Security Improvement (RFC 9449 Section 6): Proof-of-Possession Access Token Binding
                // When a DPoP proof is supplied during code exchange or token refresh,
                // cryptographically bind the access token to the client's public key by embedding the confirmation 'cnf'
                // claim containing the JWK thumbprint ('jkt'). This transforms the token into a sender-constrained DPoP token.
                org.springframework.security.oauth2.jwt.Jwt dPoPProof =
                        context.get(org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext.DPOP_PROOF_KEY);
                if (dPoPProof != null) {
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> jwkHeader = (java.util.Map<String, Object>) dPoPProof.getHeaders().get("jwk");
                    if (jwkHeader != null) {
                        try {
                            com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK.parse(jwkHeader);
                            String jkt = jwk.computeThumbprint().toString();
                            context.getClaims().claim("cnf", java.util.Map.of("jkt", jkt));
                        } catch (Exception ignored) {
                        }
                    }
                }

                context.getClaims().claim("token_type_category", "user_token");
                context.getClaims().claim("user_id", principal != null ? principal.getName() : "unknown");
                // Pre-determined client scopes assigned strictly from registered client
                context.getClaims().claim("scope", context.getRegisteredClient().getScopes());

                if (principal != null) {
                    List<String> authorities = principal.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
                    context.getClaims().claim("authorities", authorities);
                }

                if (userDetails != null) {
                    if (userDetails.email() != null) {
                        context.getClaims().claim("email", userDetails.email());
                    }
                    if (userDetails.name() != null) {
                        context.getClaims().claim("name", userDetails.name());
                    }
                    if (userDetails.roles() != null && !userDetails.roles().isEmpty()) {
                        context.getClaims().claim("roles", userDetails.roles());
                    }
                    if (userDetails.authenticatedAt() != null) {
                        context.getClaims().claim("authenticated_at", userDetails.authenticatedAt());
                    }
                }
            }

            // Customizing ID Token (OpenID Connect assertion)
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getClaims().claim("token_type_category", "id_token");
                context.getClaims().claim("auth_time", Instant.now().getEpochSecond());

                if (userDetails != null) {
                    if (userDetails.email() != null && context.getAuthorizedScopes().contains(OidcScopes.EMAIL)) {
                        context.getClaims().claim("email", userDetails.email());
                    }
                    if (userDetails.name() != null && context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
                        context.getClaims().claim("name", userDetails.name());
                    }
                }
            }
        };
    }
}
