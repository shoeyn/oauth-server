package com.example.authserver.security;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Custom {@link JwtDecoderFactory} for RFC 7523 private_key_jwt client assertions.
 *
 * <p>Fetches the client's registered EC public key from {@link PostgresRegisteredClientRepository},
 * enforces strict ES256 algorithm pinning, validates subject, issuer, and exact audience against
 * the authorization server's issuer URL and configured canonical audiences, and enforces mandatory
 * unique JTI replay protection using Redis.
 */
@Slf4j
public class ClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

  private final PostgresRegisteredClientRepository registeredClientRepository;
  private final StringRedisTemplate redisTemplate;
  private final String issuerUrl;
  private final Set<String> allowedAudiences;

  private final Map<String, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

  public ClientAssertionDecoderFactory(
      PostgresRegisteredClientRepository registeredClientRepository,
      StringRedisTemplate redisTemplate,
      String issuerUrl) {
    this(registeredClientRepository, redisTemplate, issuerUrl, null, null);
  }

  public ClientAssertionDecoderFactory(
      PostgresRegisteredClientRepository registeredClientRepository,
      StringRedisTemplate redisTemplate,
      String issuerUrl,
      String internalIssuerUrl,
      String acceptedAudiences) {
    this.registeredClientRepository = registeredClientRepository;
    this.redisTemplate = redisTemplate;
    this.issuerUrl = issuerUrl;
    this.allowedAudiences = buildAllowedAudiences(issuerUrl, internalIssuerUrl, acceptedAudiences);
  }

  private static Set<String> buildAllowedAudiences(
      String issuerUrl, String internalIssuerUrl, String acceptedAudiences) {
    Set<String> set = new HashSet<>();
    List<String> bases = new ArrayList<>();
    if (issuerUrl != null && !issuerUrl.isBlank()) {
      bases.add(issuerUrl.trim());
    }
    if (internalIssuerUrl != null && !internalIssuerUrl.isBlank()) {
      bases.add(internalIssuerUrl.trim());
    }
    if (acceptedAudiences != null && !acceptedAudiences.isBlank()) {
      for (String aud : acceptedAudiences.split(",")) {
        String trimmed = aud.trim();
        if (!trimmed.isEmpty()) {
          bases.add(trimmed);
        }
      }
    }

    for (String base : bases) {
      set.add(base);
      String normalized = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
      set.add(normalized);
      set.add(normalized + "/");
      set.add(normalized + "/oauth2/token");
      set.add(normalized + "/oauth2/par");
      set.add(normalized + "/oauth2/introspect");
      set.add(normalized + "/oauth2/revoke");
      set.add(normalized + "/oauth2/jwks");
      set.add(normalized + "/userinfo");
      set.add(normalized + "/connect/register");
    }
    return Collections.unmodifiableSet(set);
  }

  @Override
  public JwtDecoder createDecoder(RegisteredClient registeredClient) {
    ECPublicKey clientKey =
        registeredClientRepository.getClientPublicKey(registeredClient.getClientId());
    if (clientKey == null) {
      log.warn(
          "Client assertion failed: No EC public key found for client '{}'",
          registeredClient.getClientId());
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_CLIENT,
              "Client '" + registeredClient.getClientId() + "' has no registered public key.",
              "https://datatracker.ietf.org/doc/html/rfc7523#section-3"));
    }

    String cacheKey = registeredClient.getClientId() + ":" + clientKey.hashCode();
    return decoderCache.computeIfAbsent(
        cacheKey,
        (k) -> {
          log.info(
              "Constructing and caching JwtDecoder for registered client: {}",
              registeredClient.getClientId());
          ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
          jwtProcessor.setJWSKeySelector(
              (header, context) -> {
                if (header.getAlgorithm() == null
                    || !JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                  return Collections.emptyList();
                }
                return Collections.singletonList(clientKey);
              });
          jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {});
          NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);

          // Allow maximum 60 seconds clock skew for client assertion validity
          OAuth2TokenValidator<Jwt> timestampValidator =
              new JwtTimestampValidator(Duration.ofSeconds(60));

          // Strict Algorithm Pinning (RFC 7523 & RFC 8725 Section 3.1)
          OAuth2TokenValidator<Jwt> algorithmValidator =
              (jwt) -> {
                Object alg = jwt.getHeaders().get("alg");
                if (alg == null || !"ES256".equalsIgnoreCase(alg.toString())) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion",
                          "Strict Algorithm Pinning: Only 'ES256' algorithm is permitted for client assertions. Rejected: "
                              + alg,
                          null));
                }
                return OAuth2TokenValidatorResult.success();
              };

          // RFC 7523 Client assertion claims validator
          OAuth2TokenValidator<Jwt> clientValidator =
              (jwt) -> {
                if (!registeredClient.getClientId().equals(jwt.getSubject())) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion",
                          "JWT Subject does not match client_id",
                          null));
                }
                String issuer = jwt.getClaimAsString("iss");
                if (issuer != null && !registeredClient.getClientId().equals(issuer)) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion", "JWT Issuer does not match client_id", null));
                }

                // RFC 7523 Section 3: The audience MUST identify the authorization server
                // either by its issuer URL or by the specific endpoint URL (e.g. /oauth2/token,
                // /oauth2/par)
                List<String> audiences = jwt.getAudience();
                boolean validAudience =
                    audiences != null
                        && audiences.stream()
                            .anyMatch(
                                aud ->
                                    aud != null
                                        && (allowedAudiences.contains(aud)
                                            || (issuerUrl != null
                                                && (aud.equals(issuerUrl)
                                                    || aud.startsWith(issuerUrl + "/")))));
                if (!validAudience) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion",
                          "JWT Audience does not match this authorization server's issuer URL or endpoint URL",
                          null));
                }

                // RFC 7523 Section 3: The JWT MUST contain a 'jti' (JWT ID) claim.
                // Mandatory JTI Replay Protection: reject assertions without a unique jti.
                String jti = jwt.getId();
                if (jti == null || jti.isBlank()) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion",
                          "JWT Client Assertion MUST contain a unique 'jti' (JWT ID) claim",
                          "https://datatracker.ietf.org/doc/html/rfc7523#section-3"));
                }

                Boolean isNew =
                    redisTemplate
                        .opsForValue()
                        .setIfAbsent("oauth2as:jti:" + jti, "1", Duration.ofMinutes(5));
                if (Boolean.FALSE.equals(isNew)) {
                  return OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          "invalid_client_assertion",
                          "JWT Assertion replay detected: jti has already been used",
                          null));
                }

                return OAuth2TokenValidatorResult.success();
              };

          decoder.setJwtValidator(
              new DelegatingOAuth2TokenValidator<>(
                  timestampValidator, algorithmValidator, clientValidator));
          return decoder;
        });
  }
}
