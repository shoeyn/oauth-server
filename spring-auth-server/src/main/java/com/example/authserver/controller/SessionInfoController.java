package com.example.authserver.controller;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.UserSessionRevocationService;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SessionInfoController {

    private final OAuth2AuthorizationService authorizationService;
    private final UserSessionRevocationService revocationService;
    private final OidcBackChannelLogoutService oidcBackChannelLogoutService;
    private final RegisteredClientRepository registeredClientRepository;

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
            @RequestParam(required = false) String sessionId,
            @RequestParam(required = false) String username) {

        // Validate administrative API key using constant-time byte comparison to mitigate timing attacks
        byte[] expectedKeyBytes = adminApiKey.getBytes(StandardCharsets.UTF_8);
        byte[] providedKeyBytes = apiKeyHeader != null ? apiKeyHeader.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (apiKeyHeader == null || !MessageDigest.isEqual(expectedKeyBytes, providedKeyBytes)) {
            log.warn("Blocked unauthorized admin session revocation attempt: missing or invalid X-Admin-Api-Key");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthorized", "message", "Invalid or missing administrative API key"));
        }

        log.warn("GLOBAL USER SIGN-OUT / FRAUD REVOCATION TRIGGERED: token={}, sessionId={}, username={}",
                token != null ? "[PROTECTED]" : "null", sessionId, username);

        boolean tokenRevoked = false;
        String resolvedSessionId = sessionId;
        String resolvedUsername = username;
        String resolvedClientId = null;
        OAuth2Authorization singleAuthorization = null;

        if (token != null && !token.isBlank()) {
            singleAuthorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (singleAuthorization == null) {
                singleAuthorization = authorizationService.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
            }
            if (singleAuthorization != null) {
                tokenRevoked = true;
                if (resolvedUsername == null || resolvedUsername.isBlank()) {
                    resolvedUsername = singleAuthorization.getPrincipalName();
                }
                if (singleAuthorization.getRegisteredClientId() != null) {
                    RegisteredClient rc = registeredClientRepository.findById(singleAuthorization.getRegisteredClientId());
                    if (rc != null) {
                        resolvedClientId = rc.getClientId();
                    }
                }

                Authentication userAuth = singleAuthorization.getAttribute(java.security.Principal.class.getName());
                if (userAuth != null && userAuth.getDetails() instanceof Map<?, ?> details) {
                    Object sidObj = details.get("session_id");
                    if (sidObj != null && (resolvedSessionId == null || resolvedSessionId.isBlank())) {
                        resolvedSessionId = sidObj.toString();
                    }
                }
            }
        }

        // Delegate persistence purge and Redis eviction to UserSessionRevocationService
        UserSessionRevocationService.RevocationResult result = revocationService.revokeUserGlobally(
                resolvedUsername, singleAuthorization, resolvedSessionId);

        // Dispatch OpenID Connect Back-Channel Logout 1.0 notification to connected clients
        if (resolvedClientId != null && !resolvedClientId.isBlank()) {
            oidcBackChannelLogoutService.dispatchLogout(
                    null,
                    resolvedClientId,
                    resolvedUsername,
                    resolvedSessionId
            );
        } else {
            log.warn("Skipping back-channel logout dispatch: could not resolve clientId from token/session (token={}, username={})",
                    token != null ? "[PROTECTED]" : "null", resolvedUsername);
        }

        return ResponseEntity.ok(Map.of(
                "status", "REVOKED",
                "username", resolvedUsername != null ? resolvedUsername : "unknown",
                "authorizations_purged", result.purgedAuthorizations(),
                "token_revoked", tokenRevoked,
                "session_evicted", result.sessionEvicted(),
                "message", "User force signed out everywhere by Authorization Server due to security/fraud policy"
        ));
    }
}
