package com.example.authserver.controller;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authserver.security.OidcBackChannelLogoutService;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SessionInfoController {

    private final OAuth2AuthorizationService authorizationService;
    private final StringRedisTemplate redisTemplate;
    private final OidcBackChannelLogoutService oidcBackChannelLogoutService;

    @Value("${auth.admin.api-key:secret-admin-key}")
    private String adminApiKey;

    @GetMapping("/me")
    public Map<String, Object> me(Principal principal) {
        if (principal instanceof Authentication auth) {
            return Map.of(
                    "username", auth.getName(),
                    "authorities", auth.getAuthorities(),
                    "details", auth.getDetails() != null ? auth.getDetails() : Map.of()
            );
        }
        return Map.of("principal", principal != null ? principal.getName() : "anonymous");
    }

    /**
     * Administrative session revocation endpoint.
     * Revokes active authorization tokens on the authorization server, evicts the shared Redis SSO session,
     * and dispatches an OIDC back-channel logout notification to client applications.
     */
    @PostMapping("/api/admin/revoke-session")
    public ResponseEntity<Map<String, Object>> revokeSession(
            @RequestHeader(value = "X-Admin-Api-Key", required = false) String apiKeyHeader,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String sessionId) {

        // Validate administrative API key using constant-time byte comparison to mitigate timing attacks
        byte[] expectedKeyBytes = adminApiKey.getBytes(StandardCharsets.UTF_8);
        byte[] providedKeyBytes = apiKeyHeader != null ? apiKeyHeader.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (apiKeyHeader == null || !MessageDigest.isEqual(expectedKeyBytes, providedKeyBytes)) {
            log.warn("Blocked unauthorized admin session revocation attempt: missing or invalid X-Admin-Api-Key");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthorized", "message", "Invalid or missing administrative API key"));
        }

        log.warn("ADMIN REVOCATION TRIGGERED: token={}, sessionId={}",
                token != null ? "[PROTECTED]" : "null", sessionId);

        boolean tokenRevoked = false;
        if (token != null && !token.isBlank()) {
            OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (authorization == null) {
                authorization = authorizationService.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
            }
            if (authorization != null) {
                authorizationService.remove(authorization);
                tokenRevoked = true;
                log.info("Successfully revoked OAuth2Authorization id={}", authorization.getId());
            }
        }

        // Validate UUID syntax before executing Redis operations to protect against key injection
        boolean sessionEvicted = false;
        if (sessionId != null && !sessionId.isBlank()) {
            try {
                UUID parsedUuid = UUID.fromString(sessionId.trim());
                Boolean deleted = redisTemplate.delete("session:" + parsedUuid);
                sessionEvicted = Boolean.TRUE.equals(deleted);
                log.info("Evicted session:{} from Redis: {}", parsedUuid, sessionEvicted);
            } catch (IllegalArgumentException e) {
                log.warn("Rejected invalid UUID in admin session revocation: {}", sessionId);
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "invalid_session_id",
                        "message", "Session ID must be a valid UUID"
                ));
            }
        }

        // Dispatch OpenID Connect Back-Channel Logout 1.0 notification to connected clients
        oidcBackChannelLogoutService.dispatchLogout(null, "demo-client", null, sessionId);

        return ResponseEntity.ok(Map.of(
                "status", "REVOKED",
                "token_revoked", tokenRevoked,
                "session_evicted", sessionEvicted,
                "message", "Session terminated early by Authorization Server due to security/fraud policy"
        ));
    }
}
