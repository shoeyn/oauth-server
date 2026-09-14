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
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * AWS KMS Client Configuration with Enterprise Resilience & High-Availability Tuning.
 * Configured with exponential backoff and full jitter for handling transient connection hiccups.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aws.kms.enabled", havingValue = "true", matchIfMissing = true)
public class KmsClientConfig {

    @Value("${aws.kms.endpoint}")
    private String endpoint;

    @Value("${aws.region:us-east-1}")
    private String region;

    @Value("${aws.access-key-id:test}")
    private String accessKey;

    @Value("${aws.secret-access-key:test}")
    private String secretKey;

    @Bean
    public KmsClient kmsClient() {
        // Resilience: standard retry strategy (exponential backoff with jitter) capped at 3 total
        // attempts to avoid thundering herd. Uses the non-deprecated RetryStrategy API (AWS SDK v2).
        ClientOverrideConfiguration overrideConfig = ClientOverrideConfiguration.builder()
                .retryStrategy(AwsRetryStrategy.standardRetryStrategy()
                        .toBuilder()
                        .maxAttempts(3)
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
