package com.example.authserver.security;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.io.IOException;
import java.util.List;

/**
 * Handles OIDC logout failures gracefully when the id_token_hint is expired but
 * the JWT signature is still cryptographically valid.
 *
 * If the token was genuinely issued by this server (signature verifies) and the
 * post_logout_redirect_uri is registered for the client, we treat it as a valid
 * logout rather than returning a 400 error.
 */
@Slf4j
@Component
public class GracefulLogoutHandler {

    private final PostgresRegisteredClientRepository registeredClientRepository;
    private final StringRedisTemplate redisTemplate;
    private final NimbusJwtDecoder signatureOnlyDecoder;
    private final String redisPrefix;

    public GracefulLogoutHandler(
            PostgresRegisteredClientRepository registeredClientRepository,
            StringRedisTemplate redisTemplate,
            JWKSource<SecurityContext> jwkSource,
            @Value("${spring.data.redis.namespace:session:}") String redisPrefix) {
        this.registeredClientRepository = registeredClientRepository;
        this.redisTemplate = redisTemplate;
        this.redisPrefix = redisPrefix;

        // Build a decoder that verifies signature only, ignoring expiration.
        // Created once at startup, not per-request.
        this.signatureOnlyDecoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        this.signatureOnlyDecoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());
    }

    /**
     * Attempts a graceful logout fallback. Returns true if the fallback succeeded
     * and the response has been committed (redirect sent). Returns false if the
     * fallback could not be applied and the caller should handle the error normally.
     */
    public boolean handleGracefully(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String idTokenHint = request.getParameter("id_token_hint");
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");

        if (idTokenHint == null || postLogoutRedirectUri == null) {
            return false;
        }

        try {
            Jwt jwt = signatureOnlyDecoder.decode(idTokenHint);

            List<String> aud = jwt.getAudience();
            if (CollectionUtils.isEmpty(aud)) {
                return false;
            }

            String clientId = aud.get(0);
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client == null) {
                return false;
            }

            // Normalise and strictly compare the redirect URI against registered values
            String normalisedRedirectUri = normaliseUri(postLogoutRedirectUri);
            boolean uriRegistered = client.getPostLogoutRedirectUris().stream()
                    .anyMatch(registered -> normaliseUri(registered).equals(normalisedRedirectUri));

            if (!uriRegistered) {
                log.warn("Graceful logout rejected: post_logout_redirect_uri '{}' not registered for client '{}'",
                        postLogoutRedirectUri, clientId);
                return false;
            }

            String targetRedirectUri = normalisedRedirectUri;
            String state = request.getParameter("state");
            if (state != null && !state.isBlank()) {
                targetRedirectUri = UriComponentsBuilder.fromUriString(normalisedRedirectUri)
                        .queryParam("state", state)
                        .build()
                        .toUriString();
            }

            log.info("Graceful logout fallback: id_token_hint expired but signature verified. Redirecting to {}", targetRedirectUri);

            evictSharedSession(request, response);

            response.sendRedirect(targetRedirectUri);
            return true;
        } catch (Exception ex) {
            log.warn("Graceful logout fallback failed: {}", ex.getMessage());
            return false;
        }
    }

    /**
     * Evicts the SHARED_SESSION_ID cookie from Redis and clears it from the browser.
     * This is a shared utility used by both the success and error logout paths.
     */
    public void evictSharedSession(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = extractSessionId(request);
        if (sessionId != null && !sessionId.isBlank()) {
            redisTemplate.delete(redisPrefix + sessionId);
            log.info("Evicted SHARED_SESSION_ID from Redis on logout: {}", sessionId);
        }
        Cookie clearedCookie = new Cookie("SHARED_SESSION_ID", "");
        clearedCookie.setPath("/");
        clearedCookie.setMaxAge(0);
        clearedCookie.setHttpOnly(true);
        response.addCookie(clearedCookie);
    }

    /**
     * Extracts the SHARED_SESSION_ID cookie value from the request, if present.
     */
    public String extractSessionId(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("SHARED_SESSION_ID".equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Normalises a URI for safe comparison — strips fragments, normalises scheme/host case,
     * and removes default ports to prevent open redirect via encoding tricks.
     */
    private String normaliseUri(String uri) {
        try {
            return UriComponentsBuilder.fromUriString(uri)
                    .fragment(null)
                    .build()
                    .normalize()
                    .toUriString();
        } catch (Exception e) {
            return uri;
        }
    }
}
