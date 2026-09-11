package com.example.authserver.controller;

import com.example.authserver.client.ClientConfigDto;
import com.example.authserver.client.ClientReloadRedisSubscriber;
import com.example.authserver.client.PostgresRegisteredClientRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative REST Controller for OAuth 2.1 Registered Clients.
 *
 * <p>Enforces the organizational constraint that only the Java application connects directly
 * to PostgreSQL. External management clients (such as the Next.js Client Manager) invoke these
 * authenticated endpoints to manage registered clients without requiring database credentials.</p>
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class ClientAdminController {

    private final PostgresRegisteredClientRepository clientRepository;
    private final StringRedisTemplate redisTemplate;

    @Value("${auth.admin.api-key:secret-admin-key}")
    private String adminApiKey;

    private boolean isAuthorized(String apiKeyHeader) {
        if (apiKeyHeader == null || apiKeyHeader.isBlank()) {
            return false;
        }
        return MessageDigest.isEqual(
                apiKeyHeader.getBytes(StandardCharsets.UTF_8),
                adminApiKey.getBytes(StandardCharsets.UTF_8)
        );
    }

    private Map<String, Object> toSummaryMap(RegisteredClient c) {
        var pubKey = clientRepository.getClientPublicKey(c.getClientId());
        String pem = "";
        if (pubKey != null) {
            try {
                String b64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
                pem = "-----BEGIN PUBLIC KEY-----\n" + b64.replaceAll("(.{64})", "$1\n").trim() + "\n-----END PUBLIC KEY-----";
            } catch (Exception ignored) {}
        }

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", c.getId());
        map.put("clientId", c.getClientId());
        map.put("clientName", c.getClientName() != null ? c.getClientName() : c.getClientId());
        map.put("clientAuthenticationMethods", c.getClientAuthenticationMethods().stream().map(m -> m.getValue()).toList());
        map.put("authorizationGrantTypes", c.getAuthorizationGrantTypes().stream().map(g -> g.getValue()).toList());
        map.put("redirectUris", c.getRedirectUris());
        map.put("postLogoutRedirectUris", c.getPostLogoutRedirectUris());
        map.put("scopes", c.getScopes());
        map.put("requireProofKey", c.getClientSettings().isRequireProofKey());
        map.put("requireAuthorizationConsent", c.getClientSettings().isRequireAuthorizationConsent());
        Boolean requirePar = c.getClientSettings().getSetting("settings.client.require-pushed-authorization-requests");
        map.put("requirePushedAuthorizationRequests", requirePar != null ? requirePar : true);
        map.put("accessTokenTimeToLiveMinutes", c.getTokenSettings().getAccessTokenTimeToLive().toMinutes());
        map.put("refreshTokenTimeToLiveDays", c.getTokenSettings().getRefreshTokenTimeToLive().toDays());
        map.put("publicKeyPem", pem);
        return map;
    }

    /**
     * Lists all registered OAuth 2.1 clients persisted in PostgreSQL.
     */
    @GetMapping("/api/admin/clients")
    public ResponseEntity<?> listClients(
            @RequestHeader(value = "X-Admin-Api-Key", required = false) String apiKeyHeader) {
        if (!isAuthorized(apiKeyHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        Collection<RegisteredClient> clients = clientRepository.findAll();
        List<Map<String, Object>> summaries = clients.stream().map(this::toSummaryMap).toList();
        return ResponseEntity.ok(summaries);
    }

    /**
     * Gets an individual registered client by client_id.
     */
    @GetMapping("/api/admin/clients/{clientId}")
    public ResponseEntity<?> getClient(
            @RequestHeader(value = "X-Admin-Api-Key", required = false) String apiKeyHeader,
            @PathVariable String clientId) {
        if (!isAuthorized(apiKeyHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        RegisteredClient c = clientRepository.findByClientId(clientId);
        if (c == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Client not found"));
        }

        return ResponseEntity.ok(toSummaryMap(c));
    }

    /**
     * Persists or updates an OAuth 2.1 client in PostgreSQL and synchronizes the near-cache across the cluster.
     */
    @PostMapping("/api/admin/clients")
    public ResponseEntity<?> saveClient(
            @RequestHeader(value = "X-Admin-Api-Key", required = false) String apiKeyHeader,
            @RequestBody ClientConfigDto dto) {
        if (!isAuthorized(apiKeyHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        if (dto.clientId() == null || dto.clientId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "clientId is required"));
        }

        log.info("Admin API: Saving registered client '{}' to PostgreSQL...", dto.clientId());
        clientRepository.saveDtoToDatabase(dto);
        clientRepository.reloadNearCacheFromDatabase();

        // Broadcast cluster reload event via Redis Pub/Sub
        try {
            redisTemplate.convertAndSend(ClientReloadRedisSubscriber.RELOAD_TOPIC,
                    String.format("{\"action\":\"save\",\"clientId\":\"%s\"}", dto.clientId()));
        } catch (Exception e) {
            log.warn("Failed to publish Redis reload event for client '{}': {}", dto.clientId(), e.getMessage());
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "status", "created",
                "clientId", dto.clientId()
        ));
    }

    /**
     * Deletes an OAuth 2.1 client from PostgreSQL and purges it from the near-cache across the cluster.
     */
    @DeleteMapping("/api/admin/clients/{clientId}")
    public ResponseEntity<?> deleteClient(
            @RequestHeader(value = "X-Admin-Api-Key", required = false) String apiKeyHeader,
            @PathVariable String clientId) {
        if (!isAuthorized(apiKeyHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        log.info("Admin API: Deleting registered client '{}' from PostgreSQL...", clientId);
        clientRepository.deleteClient(clientId);

        // Broadcast cluster reload event via Redis Pub/Sub
        try {
            redisTemplate.convertAndSend(ClientReloadRedisSubscriber.RELOAD_TOPIC,
                    String.format("{\"action\":\"delete\",\"clientId\":\"%s\"}", clientId));
        } catch (Exception e) {
            log.warn("Failed to publish Redis reload event for deleted client '{}': {}", clientId, e.getMessage());
        }

        return ResponseEntity.ok(Map.of("status", "deleted", "clientId", clientId));
    }
}
