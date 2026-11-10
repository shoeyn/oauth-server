package com.example.authserver.controller;

import com.example.authserver.api.ClientAdminApi;
import com.example.authserver.client.ClientConfigDto;
import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.example.authserver.model.ClientActionResponse;
import com.example.authserver.model.ClientConfig;
import com.example.authserver.model.ClientSummary;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative REST Controller for OAuth 2.1 Registered Clients.
 *
 * <p>Implements contract-first OpenAPI interface {@link ClientAdminApi}. Enforces the
 * organizational constraint that only the Java application connects directly to PostgreSQL.
 * External management clients (such as the Next.js Client Manager) invoke these authenticated
 * endpoints to manage registered clients without requiring database credentials.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class ClientAdminController implements ClientAdminApi {

  private final PostgresRegisteredClientRepository clientRepository;
  private final StringRedisTemplate redisTemplate;

  @Value("${auth.admin.api-key:secret-admin-key}")
  private String adminApiKey;

  @Value("${spring.data.redis.channel.reload:oauth2as:clients:reload}")
  private String reloadTopic;

  private boolean isAuthorized(String apiKeyHeader) {
    if (apiKeyHeader == null || apiKeyHeader.isBlank()) {
      return false;
    }
    return MessageDigest.isEqual(
        apiKeyHeader.getBytes(StandardCharsets.UTF_8),
        adminApiKey.getBytes(StandardCharsets.UTF_8));
  }

  private ClientSummary toSummary(RegisteredClient c) {
    var pubKey = clientRepository.getClientPublicKey(c.getClientId());
    String pem = "";
    if (pubKey != null) {
      try {
        String b64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
        pem =
            "-----BEGIN PUBLIC KEY-----\n"
                + b64.replaceAll("(.{64})", "$1\n").trim()
                + "\n-----END PUBLIC KEY-----";
      } catch (Exception ignored) {
      }
    }

    Boolean requirePar =
        c.getClientSettings().getSetting("settings.client.require-pushed-authorization-requests");

    return new ClientSummary()
        .id(c.getId())
        .clientId(c.getClientId())
        .clientName(c.getClientName() != null ? c.getClientName() : c.getClientId())
        .clientAuthenticationMethods(
            c.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .toList())
        .authorizationGrantTypes(
            c.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).toList())
        .redirectUris(new ArrayList<>(c.getRedirectUris()))
        .postLogoutRedirectUris(new ArrayList<>(c.getPostLogoutRedirectUris()))
        .scopes(new ArrayList<>(c.getScopes()))
        .requireProofKey(c.getClientSettings().isRequireProofKey())
        .requireAuthorizationConsent(c.getClientSettings().isRequireAuthorizationConsent())
        .requirePushedAuthorizationRequests(requirePar != null ? requirePar : true)
        .accessTokenTimeToLiveMinutes(c.getTokenSettings().getAccessTokenTimeToLive().toMinutes())
        .refreshTokenTimeToLiveDays(c.getTokenSettings().getRefreshTokenTimeToLive().toDays())
        .publicKeyPem(pem);
  }

  private ClientConfigDto toDto(ClientConfig c) {
    return new ClientConfigDto(
        c.getClientId(),
        c.getClientName(),
        c.getClientAuthenticationMethods(),
        c.getAuthorizationGrantTypes(),
        c.getRedirectUris() != null ? new HashSet<>(c.getRedirectUris()) : null,
        c.getPostLogoutRedirectUris() != null ? new HashSet<>(c.getPostLogoutRedirectUris()) : null,
        c.getScopes() != null ? new HashSet<>(c.getScopes()) : null,
        c.getRequireProofKey(),
        c.getRequireAuthorizationConsent(),
        c.getRequirePushedAuthorizationRequests(),
        c.getAccessTokenTimeToLiveMinutes(),
        c.getRefreshTokenTimeToLiveDays(),
        c.getPublicKeyPem());
  }

  /** Lists all registered OAuth 2.1 clients persisted in PostgreSQL. */
  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<List<ClientSummary>> listClients(String xAdminApiKey) {
    if (!isAuthorized(xAdminApiKey)) {
      return (ResponseEntity<List<ClientSummary>>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
    }

    Collection<RegisteredClient> clients = clientRepository.findAll();
    List<ClientSummary> summaries = clients.stream().map(this::toSummary).toList();
    return ResponseEntity.ok(summaries);
  }

  /** Gets an individual registered client by client_id. */
  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<ClientSummary> getClient(String clientId, String xAdminApiKey) {
    if (!isAuthorized(xAdminApiKey)) {
      return (ResponseEntity<ClientSummary>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
    }

    RegisteredClient c = clientRepository.findByClientId(clientId);
    if (c == null) {
      return (ResponseEntity<ClientSummary>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Client not found"));
    }

    return ResponseEntity.ok(toSummary(c));
  }

  /**
   * Persists or updates an OAuth 2.1 client in PostgreSQL and synchronizes the near-cache across
   * the cluster.
   */
  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<ClientActionResponse> saveClient(
      ClientConfig clientConfig, String xAdminApiKey) {
    if (!isAuthorized(xAdminApiKey)) {
      return (ResponseEntity<ClientActionResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
    }

    if (clientConfig.getClientId() == null || clientConfig.getClientId().isBlank()) {
      return (ResponseEntity<ClientActionResponse>)
          (ResponseEntity<?>)
              ResponseEntity.badRequest().body(Map.of("error", "clientId is required"));
    }

    log.info(
        "Admin API: Saving registered client '{}' to PostgreSQL...", clientConfig.getClientId());
    ClientConfigDto dto = toDto(clientConfig);
    clientRepository.saveDtoToDatabase(dto);
    clientRepository.reloadNearCacheFromDatabase();

    // Broadcast cluster reload event via Redis Pub/Sub
    try {
      redisTemplate.convertAndSend(
          reloadTopic,
          String.format("{\"action\":\"save\",\"clientId\":\"%s\"}", clientConfig.getClientId()));
    } catch (Exception e) {
      log.warn(
          "Failed to publish Redis reload event for client '{}': {}",
          clientConfig.getClientId(),
          e.getMessage());
    }

    return ResponseEntity.status(HttpStatus.CREATED)
        .body(new ClientActionResponse().status("created").clientId(clientConfig.getClientId()));
  }

  /**
   * Deletes an OAuth 2.1 client from PostgreSQL and purges it from the near-cache across the
   * cluster.
   */
  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<ClientActionResponse> deleteClient(String clientId, String xAdminApiKey) {
    if (!isAuthorized(xAdminApiKey)) {
      return (ResponseEntity<ClientActionResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
    }

    log.info("Admin API: Deleting registered client '{}' from PostgreSQL...", clientId);
    clientRepository.deleteClient(clientId);

    // Broadcast cluster reload event via Redis Pub/Sub
    try {
      redisTemplate.convertAndSend(
          reloadTopic, String.format("{\"action\":\"delete\",\"clientId\":\"%s\"}", clientId));
    } catch (Exception e) {
      log.warn(
          "Failed to publish Redis reload event for deleted client '{}': {}",
          clientId,
          e.getMessage());
    }

    return ResponseEntity.ok(new ClientActionResponse().status("deleted").clientId(clientId));
  }
}
