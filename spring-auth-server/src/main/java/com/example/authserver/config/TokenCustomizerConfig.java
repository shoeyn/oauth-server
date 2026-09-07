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
            UserData userData = null;

            if (principal != null) {
                userData = extractUserData(principal.getDetails());
            }

            if (userData == null) {
                org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization =
                        context.get(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.class);
                if (authorization != null) {
                    Authentication userAuth = authorization.getAttribute(java.security.Principal.class.getName());
                    if (userAuth != null) {
                        userData = extractUserData(userAuth.getDetails());
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
                            java.util.Map<String, Object> cnf = new java.util.LinkedHashMap<>();
                            cnf.put("jkt", jkt);
                            context.getClaims().claim("cnf", cnf);
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

                if (userData != null) {
                    if (userData.email() != null) {
                        context.getClaims().claim("email", userData.email());
                    }
                    if (userData.name() != null) {
                        context.getClaims().claim("name", userData.name());
                    }
                    if (userData.roles() != null && !userData.roles().isEmpty()) {
                        context.getClaims().claim("roles", userData.roles());
                    }
                    if (userData.authenticatedAt() != null) {
                        context.getClaims().claim("authenticated_at", userData.authenticatedAt());
                    }
                }
            }

            // Customizing ID Token (OpenID Connect assertion)
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getClaims().claim("token_type_category", "id_token");

                if (userData != null) {
                    if (userData.email() != null && context.getAuthorizedScopes().contains(OidcScopes.EMAIL)) {
                        context.getClaims().claim("email", userData.email());
                    }
                    if (userData.name() != null && context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
                        context.getClaims().claim("name", userData.name());
                    }
                }
            }
        };
    }

    @SuppressWarnings("unchecked")
    private UserData extractUserData(Object details) {
        if (details instanceof AuthenticatedUser u) {
            return new UserData(u.email(), u.name(), u.roles(), u.authenticatedAt());
        } else if (details instanceof java.util.Map<?, ?> m) {
            String email = m.get("email") != null ? m.get("email").toString() : null;
            String name = m.get("name") != null ? m.get("name").toString() : null;
            List<String> roles = m.get("roles") instanceof List<?> r ? (List<String>) r : List.of();
            String authAt = m.get("authenticated_at") != null ? m.get("authenticated_at").toString() : null;
            return new UserData(email, name, roles, authAt);
        }
        return null;
    }

    private record UserData(String email, String name, List<String> roles, String authenticatedAt) {}
}
