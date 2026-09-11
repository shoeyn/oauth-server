package com.example.authserver.config;

import com.example.authserver.security.AuthenticatedUser;
import com.nimbusds.jose.jwk.JWK;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
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
                OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
                if (authorization != null) {
                    Authentication userAuth = authorization.getAttribute(Principal.class.getName());
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
                Jwt dPoPProof = context.get(OAuth2TokenContext.DPOP_PROOF_KEY);
                if (dPoPProof != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> jwkHeader = (Map<String, Object>) dPoPProof.getHeaders().get("jwk");
                    if (jwkHeader != null) {
                        try {
                            JWK jwk = JWK.parse(jwkHeader);
                            String jkt = jwk.computeThumbprint().toString();
                            Map<String, Object> cnf = new LinkedHashMap<>();
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

                // OpenID Connect Core 1.0 Section 3.1.3.6: Access Token Hash (at_hash)
                // Binding: leftmost 128 bits of SHA-256 of access token value, base64url encoded
                OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
                if (authorization != null) {
                    OAuth2Authorization.Token<OAuth2AccessToken> accessTokenHolder = authorization.getAccessToken();
                    if (accessTokenHolder != null && accessTokenHolder.getToken() != null) {
                        String atHash = computeOidcHash(accessTokenHolder.getToken().getTokenValue());
                        if (atHash != null) {
                            context.getClaims().claim("at_hash", atHash);
                        }
                    }

                    // OpenID Connect Core 1.0 Section 3.3.2.11: Code Hash (c_hash)
                    // Binding: leftmost 128 bits of SHA-256 of authorization code value, base64url encoded
                    OAuth2Authorization.Token<OAuth2AuthorizationCode> codeHolder =
                            authorization.getToken(OAuth2AuthorizationCode.class);
                    if (codeHolder != null && codeHolder.getToken() != null) {
                        String cHash = computeOidcHash(codeHolder.getToken().getTokenValue());
                        if (cHash != null) {
                            context.getClaims().claim("c_hash", cHash);
                        }
                    }
                }

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

    private static String computeOidcHash(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
            byte[] leftmost128 = Arrays.copyOf(digest, 16);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(leftmost128);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private UserData extractUserData(Object details) {
        if (details instanceof AuthenticatedUser u) {
            return new UserData(u.email(), u.name(), u.roles(), u.authenticatedAt());
        } else if (details instanceof Map<?, ?> m) {
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
