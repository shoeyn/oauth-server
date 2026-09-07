package com.example.authserver.task;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Scheduled background service to automatically prune expired OAuth 2.1 authorizations
 * from PostgreSQL (oauth2_authorization), preventing table bloat and maintaining B-tree index performance.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2AuthorizationCleanupService {

    private final JdbcTemplate jdbcTemplate;

    @Value("${auth.cleanup.enabled:true}")
    private boolean cleanupEnabled;

    @Value("${auth.cleanup.retention-days:30}")
    private int retentionDays;

    private static final String DELETE_EXPIRED_SQL = """
        DELETE FROM oauth2_authorization
        WHERE (refresh_token_expires_at IS NOT NULL AND refresh_token_expires_at < ?)
           OR (refresh_token_expires_at IS NULL AND access_token_expires_at IS NOT NULL AND access_token_expires_at < ?)
           OR (refresh_token_expires_at IS NULL AND access_token_expires_at IS NULL AND authorization_code_expires_at IS NOT NULL AND authorization_code_expires_at < ?)
        """;

    @Scheduled(cron = "${auth.cleanup.cron:0 0 2 * * *}")
    public void scheduledCleanup() {
        if (!cleanupEnabled) {
            log.debug("Automated OAuth2 authorization cleanup is disabled");
            return;
        }
        pruneExpiredAuthorizations(retentionDays);
    }

    public int pruneExpiredAuthorizations(int daysOld) {
        Instant threshold = Instant.now().minus(Duration.ofDays(daysOld));
        Timestamp thresholdTs = Timestamp.from(threshold);
        log.info("Starting automated pruning of expired OAuth2 authorizations older than {} days (threshold: {})", daysOld, threshold);

        try {
            int rowsDeleted = jdbcTemplate.update(DELETE_EXPIRED_SQL, thresholdTs, thresholdTs, thresholdTs);
            log.info("Completed automated OAuth2 authorization pruning: removed {} expired authorization record(s)", rowsDeleted);
            return rowsDeleted;
        } catch (Exception e) {
            log.error("Failed to prune expired OAuth2 authorizations: {}", e.getMessage(), e);
            return 0;
        }
    }
}
