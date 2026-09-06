package com.example.authserver.client;

import jakarta.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.S3Object;
import tools.jackson.databind.ObjectMapper;

@Slf4j
@Component
public class S3RegisteredClientRepository implements RegisteredClientRepository {

    private final S3Client s3Client;
    private final String bucketName;
    private final ObjectMapper objectMapper;
    private final RSAPublicKey fallbackPublicKey;

    private final Map<String, RegisteredClient> clientsById = new ConcurrentHashMap<>();
    private final Map<String, RegisteredClient> clientsByClientId = new ConcurrentHashMap<>();
    private final Map<String, RSAPublicKey> publicKeysByClientId = new ConcurrentHashMap<>();

    public S3RegisteredClientRepository(
            S3Client s3Client,
            @Value("${aws.s3.bucket:oauth2-clients}") String bucketName,
            ObjectMapper objectMapper,
            @org.springframework.context.annotation.Lazy RSAPublicKey fallbackPublicKey) {
        this.s3Client = s3Client;
        this.bucketName = bucketName;
        this.objectMapper = objectMapper;
        this.fallbackPublicKey = fallbackPublicKey;
    }

    @PostConstruct
    public void init() {
        log.info("Initializing S3RegisteredClientRepository from bucket: {}", bucketName);
        refresh();
        if (clientsByClientId.isEmpty() && fallbackPublicKey != null) {
            log.info("S3 bucket empty or unavailable on startup; initializing fallback demo-client");
            registerFallbackDemoClient();
        }
    }

    private void registerFallbackDemoClient() {
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
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .build();

        clientsById.put(demoClient.getId(), demoClient);
        clientsByClientId.put(demoClient.getClientId(), demoClient);
        publicKeysByClientId.put(demoClient.getClientId(), fallbackPublicKey);
    }

    public synchronized void refresh() {
        log.info("Refreshing OAuth 2.1 client configurations from S3 bucket '{}'...", bucketName);
        try {
            ListObjectsV2Response listResponse = s3Client.listObjectsV2(
                    ListObjectsV2Request.builder()
                            .bucket(bucketName)
                            .prefix("clients/")
                            .build()
            );

            Map<String, RegisteredClient> newClientsById = new ConcurrentHashMap<>();
            Map<String, RegisteredClient> newClientsByClientId = new ConcurrentHashMap<>();
            Map<String, RSAPublicKey> newPublicKeysByClientId = new ConcurrentHashMap<>();

            for (S3Object s3Object : listResponse.contents()) {
                String key = s3Object.key();
                if (!key.endsWith(".json")) {
                    continue;
                }

                try (ResponseInputStream<GetObjectResponse> s3Stream = s3Client.getObject(
                        GetObjectRequest.builder().bucket(bucketName).key(key).build())) {

                    ClientConfigDto dto = objectMapper.readValue(s3Stream, ClientConfigDto.class);
                    if (dto.clientId() == null || dto.clientId().isBlank()) {
                        log.warn("Skipping client config in '{}': missing clientId", key);
                        continue;
                    }

                    RegisteredClient registeredClient = toRegisteredClient(dto);
                    newClientsById.put(registeredClient.getId(), registeredClient);
                    newClientsByClientId.put(registeredClient.getClientId(), registeredClient);

                    if (dto.publicKeyPem() != null && !dto.publicKeyPem().isBlank()) {
                        try {
                            InputStream keyStream = new ByteArrayInputStream(dto.publicKeyPem().trim().getBytes(StandardCharsets.UTF_8));
                            RSAPublicKey publicKey = RsaKeyConverters.x509().convert(keyStream);
                            if (publicKey != null) {
                                newPublicKeysByClientId.put(registeredClient.getClientId(), publicKey);
                            }
                        } catch (Exception e) {
                            log.error("Failed to parse RSA public key for client '{}': {}", dto.clientId(), e.getMessage());
                        }
                    }

                    log.info("Loaded client config from S3: id={}, clientId={}, scopes={}",
                            registeredClient.getId(), registeredClient.getClientId(), registeredClient.getScopes());
                } catch (Exception e) {
                    log.error("Failed to load client configuration object '{}' from S3: {}", key, e.getMessage(), e);
                }
            }

            if (!newClientsByClientId.isEmpty()) {
                clientsById.clear();
                clientsById.putAll(newClientsById);

                clientsByClientId.clear();
                clientsByClientId.putAll(newClientsByClientId);

                publicKeysByClientId.clear();
                publicKeysByClientId.putAll(newPublicKeysByClientId);

                log.info("Successfully refreshed S3RegisteredClientRepository: {} client(s) loaded.", clientsByClientId.size());
            } else {
                log.warn("No client configurations found in S3 bucket '{}/clients/'. Retaining existing in-memory cache ({} clients).",
                        bucketName, clientsByClientId.size());
            }

        } catch (Exception e) {
            log.error("Error connecting to S3 bucket '{}' to refresh clients: {}", bucketName, e.getMessage(), e);
        }
    }

    public RSAPublicKey getClientPublicKey(String clientId) {
        return publicKeysByClientId.get(clientId);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        clientsById.put(registeredClient.getId(), registeredClient);
        clientsByClientId.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientsById.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientsByClientId.get(clientId);
    }

    private RegisteredClient toRegisteredClient(ClientConfigDto dto) {
        RegisteredClient.Builder builder = RegisteredClient.withId(dto.clientId())
                .clientId(dto.clientId())
                .clientName(dto.clientName() != null ? dto.clientName() : dto.clientId());

        // Client authentication methods
        if (dto.clientAuthenticationMethods() != null && !dto.clientAuthenticationMethods().isEmpty()) {
            for (String method : dto.clientAuthenticationMethods()) {
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method));
            }
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        }

        // Grant types
        if (dto.authorizationGrantTypes() != null && !dto.authorizationGrantTypes().isEmpty()) {
            for (String grant : dto.authorizationGrantTypes()) {
                builder.authorizationGrantType(new AuthorizationGrantType(grant));
            }
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }

        // Redirect URIs
        if (dto.redirectUris() != null) {
            for (String uri : dto.redirectUris()) {
                builder.redirectUri(uri);
            }
        }

        // Post-logout redirect URIs
        if (dto.postLogoutRedirectUris() != null) {
            for (String uri : dto.postLogoutRedirectUris()) {
                builder.postLogoutRedirectUri(uri);
            }
        }

        // Scopes
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
