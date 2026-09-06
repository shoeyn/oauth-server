package com.example.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
public class KeyConfig {

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
    public RSAKey serverRsaKey() throws Exception {
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

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey serverRsaKey) {
        JWKSet jwkSet = new JWKSet(serverRsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
