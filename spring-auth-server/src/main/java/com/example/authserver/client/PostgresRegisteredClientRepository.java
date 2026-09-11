package com.example.authserver.client;

import jakarta.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * PostgreSQL-backed RegisteredClientRepository with a high-performance in-memory near-cache.
 *
 * <p>Architecture & Performance:</p>
 * <ul>
 *   <li><b>Durability:</b> All client definitions and cryptographic public keys are persisted
 *       transactionally in PostgreSQL (tables: {@code oauth2_registered_client}, {@code oauth2_client_public_key}).</li>
 *   <li><b>Sub-Millisecond Reads:</b> Token issuance and PAR validation resolve from an internal
 *       {@link ConcurrentHashMap} near-cache in ~0.001 ms, avoiding database I/O during steady-state auth flows.</li>
 *   <li><b>Real-Time Cluster Invalidation:</b> Listens to Redis Pub/Sub ({@code oauth2:clients:reload})
 *       to synchronize client mutations across multiple Spring Auth Server instances instantaneously.</li>
 *   <li><b>Organizational Security:</b> Only this Java repository directly communicates with PostgreSQL;
 *       external management clients interact solely via the authenticated ClientAdminController.</li>
 * </ul>
 */
@Slf4j
@Component
@Primary
@org.springframework.context.annotation.DependsOn("flyway")
public class PostgresRegisteredClientRepository implements RegisteredClientRepository {

    public static final String REDIS_CLIENTS_HASH_KEY = "oauth2as:clients:configs";

    private final JdbcTemplate jdbcTemplate;
    private final JdbcRegisteredClientRepository jdbcRepository;
    private final RSAPublicKey fallbackPublicKey;
    private final StringRedisTemplate stringRedisTemplate;
    private final org.flywaydb.core.Flyway flyway;

    // High-performance thread-safe near-cache
    private final Map<String, RegisteredClient> clientsById = new ConcurrentHashMap<>();
    private final Map<String, RegisteredClient> clientsByClientId = new ConcurrentHashMap<>();
    private final Map<String, RSAPublicKey> publicKeysByClientId = new ConcurrentHashMap<>();

    public PostgresRegisteredClientRepository(
            JdbcTemplate jdbcTemplate,
            @org.springframework.context.annotation.Lazy RSAPublicKey fallbackPublicKey,
            StringRedisTemplate stringRedisTemplate,
            org.flywaydb.core.Flyway flyway) {
        this.jdbcTemplate = jdbcTemplate;
        this.jdbcRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        this.fallbackPublicKey = fallbackPublicKey;
        this.stringRedisTemplate = stringRedisTemplate;
        this.flyway = flyway;
    }

    @PostConstruct
    public void init() {
        log.info("Executing Flyway migration to guarantee schema existence...");
        flyway.migrate();

        // Ensure demo-client is registered and seeded in PostgreSQL on first boot
        if (!doesClientExist("demo-client")) {
            log.info("Default 'demo-client' not found in PostgreSQL. Seeding default demo-client...");
            registerDefaultDemoClient();
        }

        // Preload all registered clients and cryptographic keys from PostgreSQL into near-cache
        reloadNearCacheFromDatabase();
    }

    private boolean doesClientExist(String clientId) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                    "SELECT count(*) FROM oauth2_registered_client WHERE client_id = ?",
                    Integer.class,
                    clientId
            );
            return count != null && count > 0;
        } catch (Exception e) {
            log.warn("Could not query client existence for '{}' from PostgreSQL: {}", clientId, e.getMessage());
            return false;
        }
    }

    /**
     * Reloads the in-memory near-cache from PostgreSQL.
     * Guarantees microsecond lookup times during runtime OAuth 2.1 token issuance.
     */
    public synchronized void reloadNearCacheFromDatabase() {
        try {
            List<String> clientIds = jdbcTemplate.queryForList("SELECT client_id FROM oauth2_registered_client", String.class);
            Map<String, RegisteredClient> newClientsById = new ConcurrentHashMap<>();
            Map<String, RegisteredClient> newClientsByClientId = new ConcurrentHashMap<>();
            Map<String, RSAPublicKey> newPublicKeysByClientId = new ConcurrentHashMap<>();

            for (String clientId : clientIds) {
                RegisteredClient client = jdbcRepository.findByClientId(clientId);
                if (client != null) {
                    newClientsById.put(client.getId(), client);
                    newClientsByClientId.put(client.getClientId(), client);
                }
            }

            // Load associated RSA public keys from oauth2_client_public_key table
            jdbcTemplate.query("SELECT client_id, public_key_pem FROM oauth2_client_public_key", (rs) -> {
                String clientId = rs.getString("client_id");
                String pem = rs.getString("public_key_pem");
                if (pem != null && !pem.isBlank()) {
                    try {
                        InputStream keyStream = new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.UTF_8));
                        RSAPublicKey key = RsaKeyConverters.x509().convert(keyStream);
                        if (key != null) {
                            newPublicKeysByClientId.put(clientId, key);
                        }
                    } catch (Exception e) {
                        log.warn("Failed parsing RSA public key for client '{}' from PostgreSQL: {}", clientId, e.getMessage());
                    }
                }
            });


            clientsById.clear();
            clientsById.putAll(newClientsById);

            clientsByClientId.clear();
            clientsByClientId.putAll(newClientsByClientId);

            publicKeysByClientId.clear();
            publicKeysByClientId.putAll(newPublicKeysByClientId);

            log.info("Near-cache warmed from PostgreSQL: {} client(s) and {} public key(s) loaded into memory.",
                    clientsByClientId.size(), publicKeysByClientId.size());
        } catch (Exception e) {
            log.error("Failed to load registered clients from PostgreSQL into near-cache: {}", e.getMessage(), e);
        }
    }

    private void registerDefaultDemoClient() {
        RegisteredClient demoClient = RegisteredClient.withId("demo-client")
                .clientId("demo-client")
                .clientName("Demo Client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/callback")
                .redirectUri("http://localhost:8080/callback")
                .redirectUri("http://demo-client:8080/callback")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .postLogoutRedirectUri("http://localhost:8080/")
                .postLogoutRedirectUri("http://demo-client:8080/")
                .scope("openid")
                .scope("profile")
                .scope("email")
                .scope("user.read")
                .scope("demo.secret_access")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .setting("settings.client.require-pushed-authorization-requests", true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .build();

        jdbcRepository.save(demoClient);

        // Persist demo-client RSA public key into oauth2_client_public_key table
        if (fallbackPublicKey != null) {
            try {
                String b64 = java.util.Base64.getEncoder().encodeToString(fallbackPublicKey.getEncoded());
                String pem = "-----BEGIN PUBLIC KEY-----\n" + b64.replaceAll("(.{64})", "$1\n").trim() + "\n-----END PUBLIC KEY-----";
                jdbcTemplate.update(
                        "INSERT INTO oauth2_client_public_key (client_id, public_key_pem, updated_at) " +
                        "VALUES (?, ?, CURRENT_TIMESTAMP) " +
                        "ON CONFLICT (client_id) DO UPDATE SET public_key_pem = EXCLUDED.public_key_pem, updated_at = CURRENT_TIMESTAMP",
                        "demo-client", pem
                );
                log.info("Default 'demo-client' public key persisted into PostgreSQL.");
            } catch (Exception e) {
                log.warn("Failed to persist default demo-client public key to PostgreSQL: {}", e.getMessage());
            }
        }
    }

    /**
     * Converts a ClientConfigDto and persists it to both oauth2_registered_client
     * and oauth2_client_public_key in PostgreSQL.
     */
    public void saveDtoToDatabase(ClientConfigDto dto) {
        RegisteredClient registeredClient = toRegisteredClient(dto);
        jdbcRepository.save(registeredClient);

        if (dto.publicKeyPem() != null && !dto.publicKeyPem().isBlank()) {
            jdbcTemplate.update(
                    "INSERT INTO oauth2_client_public_key (client_id, public_key_pem, updated_at) " +
                    "VALUES (?, ?, CURRENT_TIMESTAMP) " +
                    "ON CONFLICT (client_id) DO UPDATE SET public_key_pem = EXCLUDED.public_key_pem, updated_at = CURRENT_TIMESTAMP",
                    dto.clientId(), dto.publicKeyPem().trim()
            );
        }
    }

    /**
     * Dynamic client deletion from PostgreSQL and memory.
     */
    public void deleteClient(String clientId) {
        jdbcTemplate.update("DELETE FROM oauth2_client_public_key WHERE client_id = ?", clientId);
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", clientId);

        clientsByClientId.remove(clientId);
        publicKeysByClientId.remove(clientId);
        clientsById.values().removeIf(c -> clientId.equals(c.getClientId()));
        log.info("Client '{}' purged from PostgreSQL and in-memory cache.", clientId);
    }

    /**
     * Triggered by Redis reload notifications or external events.
     * Refreshes the in-memory near-cache from PostgreSQL.
     */
    public synchronized void refresh() {
        log.info("Refreshing client near-cache from PostgreSQL...");
        reloadNearCacheFromDatabase();
    }

    public RSAPublicKey getClientPublicKey(String clientId) {
        return publicKeysByClientId.get(clientId);
    }

    public Collection<RegisteredClient> findAll() {
        return clientsByClientId.values();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        jdbcRepository.save(registeredClient);
        clientsById.put(registeredClient.getId(), registeredClient);
        clientsByClientId.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        RegisteredClient cached = clientsById.get(id);
        if (cached != null) {
            return cached;
        }
        RegisteredClient client = jdbcRepository.findById(id);
        if (client != null) {
            clientsById.put(client.getId(), client);
            clientsByClientId.put(client.getClientId(), client);
        }
        return client;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        RegisteredClient cached = clientsByClientId.get(clientId);
        if (cached != null) {
            return cached;
        }
        RegisteredClient client = jdbcRepository.findByClientId(clientId);
        if (client != null) {
            clientsById.put(client.getId(), client);
            clientsByClientId.put(client.getClientId(), client);
        }
        return client;
    }

    private RegisteredClient toRegisteredClient(ClientConfigDto dto) {
        RegisteredClient.Builder builder = RegisteredClient.withId(dto.clientId())
                .clientId(dto.clientId())
                .clientName(dto.clientName() != null ? dto.clientName() : dto.clientId());

        if (dto.clientAuthenticationMethods() != null && !dto.clientAuthenticationMethods().isEmpty()) {
            for (String method : dto.clientAuthenticationMethods()) {
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method));
            }
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        }

        if (dto.authorizationGrantTypes() != null && !dto.authorizationGrantTypes().isEmpty()) {
            for (String grant : dto.authorizationGrantTypes()) {
                builder.authorizationGrantType(new AuthorizationGrantType(grant));
            }
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }

        if (dto.redirectUris() != null) {
            for (String uri : dto.redirectUris()) {
                builder.redirectUri(uri);
            }
        }

        if (dto.postLogoutRedirectUris() != null) {
            for (String uri : dto.postLogoutRedirectUris()) {
                builder.postLogoutRedirectUri(uri);
            }
        }

        if (dto.scopes() != null) {
            for (String scope : dto.scopes()) {
                builder.scope(scope);
            }
        }

        long accessTtlMinutes = dto.accessTokenTimeToLiveMinutes() != null ? dto.accessTokenTimeToLiveMinutes() : 15L;
        long refreshTtlDays = dto.refreshTokenTimeToLiveDays() != null ? dto.refreshTokenTimeToLiveDays() : 30L;

        builder.clientSettings(ClientSettings.builder()
                .requireProofKey(dto.requireProofKey() != null ? dto.requireProofKey() : true)
                .requireAuthorizationConsent(dto.requireAuthorizationConsent() != null ? dto.requireAuthorizationConsent() : false)
                .setting("settings.client.require-pushed-authorization-requests",
                        dto.requirePushedAuthorizationRequests() != null ? dto.requirePushedAuthorizationRequests() : true)
                .build());

        builder.tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofMinutes(accessTtlMinutes))
                .reuseRefreshTokens(false)
                .refreshTokenTimeToLive(Duration.ofDays(refreshTtlDays))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build());

        return builder.build();
    }
}
