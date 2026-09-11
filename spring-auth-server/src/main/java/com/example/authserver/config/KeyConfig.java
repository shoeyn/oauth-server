package com.example.authserver.config;

import com.example.authserver.security.KmsJwtEncoder;
import com.example.authserver.security.KmsRsaSigner;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

/**
 * Enterprise Key Configuration with Hardware Security Module (HSM) / AWS KMS Support,
 * Graceful Multi-Key JWKS Rotation, and Strict Algorithm Pinning.
 *
 * Multi-Key Rotation Architecture:
 * - Active key: Resolved from aws.kms.key-alias (alias/oauth2-signing-key) used to sign all new tokens.
 * - Previous key(s): Resolved from aws.kms.previous-key-aliases (alias/oauth2-signing-key-previous).
 *   Published in /oauth2/jwks alongside the active key so valid in-flight tokens verify without disruption.
 */
@Slf4j
@Configuration
public class KeyConfig {

    @Value("${aws.kms.enabled:true}")
    private boolean kmsEnabled;

    @Value("${aws.kms.key-alias:alias/oauth2-signing-key}")
    private String kmsKeyAlias;

    @Value("${aws.kms.previous-key-aliases:alias/oauth2-signing-key-previous}")
    private String previousKeyAliases;

    @Value("classpath:keys/server_private_key.pem")
    private Resource serverPrivateKeyResource;

    @Value("classpath:keys/server_public_key.pem")
    private Resource serverPublicKeyResource;

    @Value("classpath:keys/demo_client_public_key.pem")
    private Resource demoClientPublicKeyResource;

    @Bean
    public RSAPublicKey demoClientPublicKey() throws Exception {
        try (var is = demoClientPublicKeyResource.getInputStream()) {
            return RsaKeyConverters.x509().convert(is);
        }
    }

    @Bean
    public RSAKey serverRsaKey(@Autowired(required = false) KmsClient kmsClient) throws Exception {
        if (kmsEnabled) {
            log.info("Initializing active HSM / AWS KMS asymmetric signing key using alias: {}", kmsKeyAlias);
            if (kmsClient == null) {
                throw new IllegalStateException("Strict Fail-Closed: aws.kms.enabled is true but KmsClient bean is null.");
            }

            try {
                // Fetch public key from KMS once at startup and cache in-memory
                GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(kmsKeyAlias).build();
                GetPublicKeyResponse response = kmsClient.getPublicKey(request);
                byte[] publicKeyDer = response.publicKey().asByteArray();

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDer));

                log.info("Successfully fetched and cached active AWS KMS RSA public key (KeyId: {})", response.keyId());

                return new RSAKey.Builder(publicKey)
                        .keyID("kms-auth-server-key-1")
                        .algorithm(JWSAlgorithm.RS256)
                        .build();
            } catch (Exception ex) {
                log.error("Strict Fail-Closed: Failed to retrieve active public key from AWS KMS for {}: {}",
                        kmsKeyAlias, ex.getMessage(), ex);
                throw new IllegalStateException("Strict Fail-Closed: AWS KMS is unavailable. Aborting startup to prevent cryptographic downgrade: " + ex.getMessage(), ex);
            }
        } else {
            log.warn("aws.kms.enabled=false. Initializing in-memory RSA key pair from local classpath (OFFLINE DEV ONLY).");
            RSAPrivateKey privateKey;
            try (var is = serverPrivateKeyResource.getInputStream()) {
                privateKey = RsaKeyConverters.pkcs8().convert(is);
            }
            RSAPublicKey publicKey;
            try (var is = serverPublicKeyResource.getInputStream()) {
                publicKey = RsaKeyConverters.x509().convert(is);
            }

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID("auth-server-key-1")
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        }
    }

    @Bean
    public JWSSigner jwsSigner(
            @Autowired(required = false) KmsClient kmsClient,
            RSAKey serverRsaKey) throws Exception {
        if (kmsEnabled) {
            log.info("Registering KmsRsaSigner backed by AWS KMS ({})", kmsKeyAlias);
            return new KmsRsaSigner(kmsClient, kmsKeyAlias);
        } else {
            log.info("Registering local RSASSASigner with in-memory private key");
            return new RSASSASigner(serverRsaKey.toRSAPrivateKey());
        }
    }

    @Bean
    public JwtEncoder jwtEncoder(
            JWKSource<SecurityContext> jwkSource,
            JWSSigner jwsSigner,
            RSAKey serverRsaKey) {
        if (kmsEnabled && jwsSigner instanceof KmsRsaSigner kmsRsaSigner) {
            log.info("Registering KmsJwtEncoder for OAuth 2.1 access and ID token issuance with keyId: {}", serverRsaKey.getKeyID());
            return new KmsJwtEncoder(kmsRsaSigner, serverRsaKey.getKeyID());
        } else {
            log.info("Registering standard NimbusJwtEncoder with local in-memory JWKSource");
            return new NimbusJwtEncoder(jwkSource);
        }
    }

    /**
     * Graceful Multi-Key JWKS Source:
     * Publishes the active KMS signing key AND any previous/rotated KMS keys in the JWKS array.
     * Clients and resource servers can verify in-flight tokens signed with previous keys during rotation windows.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Autowired(required = false) KmsClient kmsClient,
            RSAKey serverRsaKey) {
        List<JWK> jwkList = new ArrayList<>();
        jwkList.add(serverRsaKey.toPublicJWK());

        if (kmsEnabled && kmsClient != null && StringUtils.hasText(previousKeyAliases)) {
            String[] aliases = previousKeyAliases.split(",");
            for (String alias : aliases) {
                String trimmedAlias = alias.trim();
                if (trimmedAlias.isEmpty()) {
                    continue;
                }
                try {
                    log.info("Checking for previous/rotated KMS signing key alias: {}", trimmedAlias);
                    GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(trimmedAlias).build();
                    GetPublicKeyResponse response = kmsClient.getPublicKey(request);
                    byte[] prevDer = response.publicKey().asByteArray();

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    RSAPublicKey prevPublicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(prevDer));

                    RSAKey prevRsaKey = new RSAKey.Builder(prevPublicKey)
                            .keyID("kms-auth-server-key-previous")
                            .algorithm(JWSAlgorithm.RS256)
                            .build();

                    jwkList.add(prevRsaKey.toPublicJWK());
                    log.info("Successfully added previous KMS signing key to JWKS for graceful rotation (Alias: {}, KeyId: {})",
                            trimmedAlias, response.keyId());
                } catch (Exception ex) {
                    log.debug("No active previous KMS key found for alias '{}' (single-key mode): {}",
                            trimmedAlias, ex.getMessage());
                }
            }
        }

        JWKSet jwkSet = new JWKSet(jwkList);
        log.info("JWKS endpoint initialized with {} public key(s) (Graceful Multi-Key Rotation enabled)", jwkList.size());
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Strict Algorithm Pinning for Resource Server & Token Introspection:
     * Verifies tokens against published JWKS and enforces that JWS alg is strictly 'RS256'.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder jwtDecoder =
                (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

        OAuth2TokenValidator<Jwt> algorithmValidator = (jwt) -> {
            Object alg = jwt.getHeaders().get("alg");
            if (alg == null || !"RS256".equalsIgnoreCase(alg.toString())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                        "invalid_token",
                        "Strict Algorithm Pinning: Only 'RS256' algorithm is permitted. Rejected algorithm: " + alg,
                        null));
            }
            return OAuth2TokenValidatorResult.success();
        };

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(),
                algorithmValidator
        ));
        return jwtDecoder;
    }
}
