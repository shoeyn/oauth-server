package com.example.authserver.security;

import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating user session and authorization token revocation across PostgreSQL and Redis.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserSessionRevocationService {

    private final OAuth2AuthorizationService authorizationService;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public record RevocationResult(int purgedAuthorizations, boolean sessionEvicted) {}

    /**
     * Revokes all authorizations for the specified user or authorization, and terminates active Redis SSO sessions.
     */
    public RevocationResult revokeUserGlobally(String resolvedUsername, OAuth2Authorization singleAuthorization, String resolvedSessionId) {
        int purgedAuthorizations = 0;
        boolean sessionEvicted = false;

        // 1. Purge authorizations in database
        if (resolvedUsername != null && !resolvedUsername.isBlank()) {
            purgedAuthorizations = jdbcTemplate.update(
                    "DELETE FROM oauth2_authorization WHERE principal_name = ?",
                    resolvedUsername
            );
            log.info("Force signed out user '{}' everywhere: purged {} authorizations from PostgreSQL",
                    resolvedUsername, purgedAuthorizations);
        } else if (singleAuthorization != null) {
            authorizationService.remove(singleAuthorization);
            purgedAuthorizations = 1;
        }

        // 2. Globally evict any active Redis SSO sessions matching user using safe SCAN
        if (resolvedUsername != null && !resolvedUsername.isBlank()) {
            final String usernameFragment = "\"username\":\"" + resolvedUsername + "\"";
            try (Cursor<String> cursor = redisTemplate.scan(
                    ScanOptions.scanOptions().match("session:*").count(100).build())) {
                while (cursor.hasNext()) {
                    String sKey = cursor.next();
                    String sessionJson = redisTemplate.opsForValue().get(sKey);
                    if (sessionJson != null && sessionJson.contains(usernameFragment)) {
                        redisTemplate.delete(sKey);
                        sessionEvicted = true;
                        log.info("Globally evicted active SSO Redis session {} for user {}", sKey, resolvedUsername);
                    }
                }
            } catch (Exception ex) {
                log.warn("Error scanning active user sessions in Redis: {}", ex.getMessage());
            }
        }

        // 3. Evict specific session ID if provided
        if (resolvedSessionId != null && !resolvedSessionId.isBlank()) {
            try {
                UUID parsedUuid = UUID.fromString(resolvedSessionId.trim());
                Boolean deleted = redisTemplate.delete("session:" + parsedUuid);
                if (Boolean.TRUE.equals(deleted)) {
                    sessionEvicted = true;
                }
                log.info("Evicted session:{} from Redis: {}", parsedUuid, sessionEvicted);
            } catch (IllegalArgumentException e) {
                log.warn("Rejected invalid UUID in session revocation: {}", resolvedSessionId);
            }
        }

        return new RevocationResult(purgedAuthorizations, sessionEvicted);
    }
}
