package com.example.authserver.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriUtils;

/**
 * OpenID Connect Back-Channel Logout 1.0 Implementation (RFC Spec)
 * Security Improvement: Asynchronously sends cryptographically signed logout_token JWTs
 * to registered client back-channel endpoints so clients can terminate sessions server-to-server.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OidcBackChannelLogoutService {

    private final RSAKey serverRsaKey;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Value("${auth.client.backchannel-logout-url:http://localhost:8080/oidc/backchannel_logout}")
    private String defaultBackchannelLogoutUrl;

    private final RestClient restClient = RestClient.builder().build();

    public void dispatchLogout(String clientLogoutUri, String clientId, String sub, String sid) {
        String targetUri = (clientLogoutUri != null && !clientLogoutUri.isBlank())
                ? clientLogoutUri
                : defaultBackchannelLogoutUrl;

        try {
            long now = Instant.now().getEpochSecond();
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuerUrl)
                    .audience(clientId != null ? clientId : "demo-client")
                    .issueTime(new Date(now * 1000))
                    .jwtID(UUID.randomUUID().toString())
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
            JWTClaimsSet claims = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(serverRsaKey.getKeyID())
                    .type(new JOSEObjectType("JWT"))
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(serverRsaKey.toRSAPrivateKey()));
            String logoutToken = signedJWT.serialize();

            // Performance & Resilience: Asynchronous non-blocking dispatch with automated retries
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
