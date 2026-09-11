package com.example.authserver.security;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Custom {@link JwtDecoderFactory} for RFC 7523 private_key_jwt client assertions.
 * <p>
 * Fetches the client's registered RSA public key from {@link PostgresRegisteredClientRepository},
 * enforces strict RS256 algorithm pinning, validates subject, issuer, and exact audience against
 * the authorization server's issuer URL, and protects against JTI replay attacks using Redis.
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class ClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

    private final PostgresRegisteredClientRepository registeredClientRepository;
    private final StringRedisTemplate redisTemplate;
    private final String issuerUrl;

    private final Map<String, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

    @Override
    public JwtDecoder createDecoder(RegisteredClient registeredClient) {
        RSAPublicKey clientKey = registeredClientRepository.getClientPublicKey(registeredClient.getClientId());
        if (clientKey == null) {
            log.warn("Client assertion failed: No RSA public key found for client '{}'", registeredClient.getClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                            "Client '" + registeredClient.getClientId() + "' has no registered public key.",
                            "https://datatracker.ietf.org/doc/html/rfc7523#section-3")
            );
        }

        String cacheKey = registeredClient.getClientId() + ":" + clientKey.hashCode();
        return decoderCache.computeIfAbsent(cacheKey, (k) -> {
            log.info("Constructing and caching JwtDecoder for registered client: {}", registeredClient.getClientId());
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(clientKey)
                    .signatureAlgorithm(SignatureAlgorithm.RS256)
                    .build();

            // Allow maximum 60 seconds clock skew for client assertion validity
            OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator(Duration.ofSeconds(60));

            // Strict Algorithm Pinning (RFC 7523 & RFC 8725 Section 3.1)
            OAuth2TokenValidator<Jwt> algorithmValidator = (jwt) -> {
                Object alg = jwt.getHeaders().get("alg");
                if (alg == null || !"RS256".equalsIgnoreCase(alg.toString())) {
                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                            "invalid_client_assertion",
                            "Strict Algorithm Pinning: Only 'RS256' algorithm is permitted for client assertions. Rejected: " + alg,
                            null));
                }
                return OAuth2TokenValidatorResult.success();
            };

            // RFC 7523 Client assertion claims validator
            OAuth2TokenValidator<Jwt> clientValidator = (jwt) -> {
                if (!registeredClient.getClientId().equals(jwt.getSubject())) {
                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                            "invalid_client_assertion",
                            "JWT Subject does not match client_id",
                            null));
                }
                String issuer = jwt.getClaimAsString("iss");
                if (issuer != null && !registeredClient.getClientId().equals(issuer)) {
                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                            "invalid_client_assertion",
                            "JWT Issuer does not match client_id",
                            null));
                }

                // RFC 7523 Section 3: The audience MUST identify the authorization server
                // either by its issuer URL or by the specific endpoint URL (e.g. /oauth2/token, /oauth2/par)
                List<String> audiences = jwt.getAudience();
                boolean validAudience = audiences != null && audiences.stream()
                        .anyMatch(aud -> aud != null && (aud.equals(issuerUrl) || aud.startsWith(issuerUrl + "/")));
                if (!validAudience) {
                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                            "invalid_client_assertion",
                            "JWT Audience does not match this authorization server's issuer URL or endpoint URL",
                            null));
                }

                // JTI Replay Protection
                String jti = jwt.getId();
                if (jti != null && !jti.isBlank()) {
                    Boolean isNew = redisTemplate.opsForValue().setIfAbsent("oauth2as:jti:" + jti, "1", Duration.ofMinutes(5));
                    if (Boolean.FALSE.equals(isNew)) {
                        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                "invalid_client_assertion",
                                "JWT Assertion replay detected: jti has already been used",
                                null));
                    }
                }

                return OAuth2TokenValidatorResult.success();
            };

            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestampValidator, algorithmValidator, clientValidator));
            return decoder;
        });
    }
}
