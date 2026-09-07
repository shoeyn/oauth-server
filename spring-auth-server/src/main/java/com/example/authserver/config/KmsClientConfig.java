package com.example.authserver.config;

import java.net.URI;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.retry.backoff.BackoffStrategy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * AWS KMS Client Configuration with Enterprise Resilience & High-Availability Tuning.
 * Configured with exponential backoff and full jitter for handling transient connection hiccups.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aws.kms.enabled", havingValue = "true", matchIfMissing = true)
public class KmsClientConfig {

    @Value("${aws.kms.endpoint:http://localhost:4566}")
    private String endpoint;

    @Value("${aws.region:us-east-1}")
    private String region;

    @Value("${aws.access-key-id:test}")
    private String accessKey;

    @Value("${aws.secret-access-key:test}")
    private String secretKey;

    @Bean
    public KmsClient kmsClient() {
        // Resilience: Configured with 3-attempt exponential backoff with full jitter to avoid thundering herd
        ClientOverrideConfiguration overrideConfig = ClientOverrideConfiguration.builder()
                .retryPolicy(RetryPolicy.builder()
                        .numRetries(3)
                        .backoffStrategy(BackoffStrategy.defaultStrategy())
                        .build())
                .apiCallTimeout(Duration.ofSeconds(5))
                .apiCallAttemptTimeout(Duration.ofSeconds(2))
                .build();

        return KmsClient.builder()
                .endpointOverride(URI.create(endpoint))
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey)))
                .overrideConfiguration(overrideConfig)
                .build();
    }
}
