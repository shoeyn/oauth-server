package com.example.authserver.config;

import com.example.authserver.security.KmsJwtEncoder;
import com.example.authserver.security.KmsRsaSigner;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

/**
 * Enterprise Key Configuration with Hardware Security Module (HSM) / AWS KMS Support.
 *
 * When aws.kms.enabled=true (production default):
 * - Private key material NEVER enters application or host memory (FIPS 140-2 Level 3 / FIPS 140-3).
 * - Public key is resolved once from AWS KMS at startup and published via /oauth2/jwks.
 * - Enforces Strict Fail-Closed: If KMS is unreachable, startup aborts rather than degrading security.
 *
 * When aws.kms.enabled=false:
 * - Falls back to local classpath in-memory RSA key pair (strictly for offline unit testing).
 */
@Slf4j
@Configuration
public class KeyConfig {

    @Value("${aws.kms.enabled:true}")
    private boolean kmsEnabled;

    @Value("${aws.kms.key-alias:alias/oauth2-signing-key}")
    private String kmsKeyAlias;

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
            log.info("Initializing HSM / AWS KMS asymmetric signing key using alias: {}", kmsKeyAlias);
            if (kmsClient == null) {
                throw new IllegalStateException("Strict Fail-Closed: aws.kms.enabled is true but KmsClient bean is null.");
            }

            try {
                // Resilience: Query KMS for public key (DER X.509 format)
                GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(kmsKeyAlias).build();
                GetPublicKeyResponse response = kmsClient.getPublicKey(request);
                byte[] publicKeyDer = response.publicKey().asByteArray();

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDer));

                log.info("Successfully fetched and cached AWS KMS RSA public key (KeyId: {})", response.keyId());

                // Construct public-only RSAKey: Private key NEVER leaves AWS KMS hardware boundary!
                return new RSAKey.Builder(publicKey)
                        .keyID("kms-auth-server-key-1")
                        .build();
            } catch (Exception ex) {
                log.error("Strict Fail-Closed: Failed to retrieve public key from AWS KMS for {}: {}",
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

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey serverRsaKey) {
        // Publishes strictly the public key components at /oauth2/jwks
        JWKSet jwkSet = new JWKSet(serverRsaKey.toPublicJWK());
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
