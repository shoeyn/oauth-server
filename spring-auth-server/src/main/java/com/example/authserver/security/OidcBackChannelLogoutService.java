package com.example.authserver.security;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriUtils;

/**
 * OpenID Connect Back-Channel Logout 1.0 service.
 * Asynchronously generates and delivers signed logout_token JWTs to registered client
 * back-channel logout endpoints, enabling direct server-to-server session invalidation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OidcBackChannelLogoutService {

    private final JwtEncoder jwtEncoder;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Value("${auth.client.backchannel-logout-url:http://localhost:8080/oidc/backchannel_logout}")
    private String defaultBackchannelLogoutUrl;

    private final RestClient restClient = RestClient.builder().build();

    public void dispatchLogout(String clientLogoutUri, String clientId, String sub, String sid) {
        if (clientId == null || clientId.isBlank()) {
            log.warn("Skipping back-channel logout: clientId is required but was null/blank (sub={})", sub);
            return;
        }

        String targetUri = (clientLogoutUri != null && !clientLogoutUri.isBlank())
                ? clientLogoutUri
                : defaultBackchannelLogoutUrl;

        try {
            Instant now = Instant.now();
            JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                    .issuer(issuerUrl)
                    .audience(List.of(clientId))
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(120))
                    .id(UUID.randomUUID().toString())
                    // OIDC Back-Channel Logout 1.0 Section 2.4:
                    // MUST contain the "events" claim with "http://schemas.openid.net/event/backchannel-logout"
                    .claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));

            if (sub != null && !sub.isBlank()) {
                claimsBuilder.subject(sub);
            }
            if (sid != null && !sid.isBlank()) {
                claimsBuilder.claim("sid", sid);
            }

            // OIDC Back-Channel Logout 1.0 Section 2.4:
            // MUST NOT contain a "nonce" claim to avoid token confusion attacks with ID tokens
            JwtClaimsSet claims = claimsBuilder.build();
            JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();

            String logoutToken = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

            // Asynchronous non-blocking dispatch with exponential backoff retries
            java.util.concurrent.CompletableFuture.runAsync(() -> {
                int maxRetries = 3;
                for (int attempt = 1; attempt <= maxRetries; attempt++) {
                    try {
                        log.info("Dispatching OIDC Back-Channel Logout to {} (sub={}, sid={}, attempt={}/{})",
                                targetUri, sub, sid, attempt, maxRetries);

                        restClient.post()
                                .uri(URI.create(targetUri))
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .body("logout_token=" + UriUtils.encode(logoutToken, StandardCharsets.UTF_8))
                                .retrieve()
                                .toBodilessEntity();

                        log.info("OIDC Back-Channel Logout successfully delivered to {}", targetUri);
                        return;
                    } catch (Exception e) {
                        if (attempt < maxRetries) {
                            long backoffMs = (long) (Math.pow(2, attempt - 1) * 200);
                            log.warn("OIDC Back-Channel Logout attempt {} failed for {}: {}. Retrying in {}ms...",
                                    attempt, targetUri, e.getMessage(), backoffMs);
                            try {
                                Thread.sleep(backoffMs);
                            } catch (InterruptedException ie) {
                                Thread.currentThread().interrupt();
                                break;
                            }
                        } else {
                            log.warn("Failed to deliver OIDC Back-Channel Logout to {} after {} attempts: {}",
                                    targetUri, maxRetries, e.getMessage());
                        }
                    }
                }
            });
        } catch (Exception e) {
            log.warn("Failed to build or sign OIDC Back-Channel Logout token: {}", e.getMessage());
        }
    }
}
