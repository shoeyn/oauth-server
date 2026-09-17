package com.example.authserver.security;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OidcBackChannelLogoutServiceTest {

  private static final String ISSUER = "http://localhost:9000";
  private static final String DEFAULT_LOGOUT_URL = "http://localhost:8080/oidc/backchannel_logout";

  @Mock private JwtEncoder jwtEncoder;

  private OidcBackChannelLogoutService service;

  @BeforeEach
  void setUp() {
    service = new OidcBackChannelLogoutService(jwtEncoder);
    ReflectionTestUtils.setField(service, "issuerUrl", ISSUER);
    ReflectionTestUtils.setField(service, "defaultBackchannelLogoutUrl", DEFAULT_LOGOUT_URL);
  }

  private Jwt sampleJwt() {
    Instant now = Instant.now();
    return Jwt.withTokenValue("signed.logout.token")
        .header("alg", "ES256")
        .issuer(ISSUER)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(120))
        .claim("events", Map.of())
        .build();
  }

  /** Installs a RestClient whose terminal call is recorded, avoiding real network I/O. */
  private AtomicInteger installRecordingRestClient(boolean shouldFail) {
    AtomicInteger callCount = new AtomicInteger(0);
    RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
    when(restClient
            .post()
            .uri(any(URI.class))
            .contentType(any())
            .body(any(String.class))
            .retrieve()
            .toBodilessEntity())
        .thenAnswer(
            invocation -> {
              callCount.incrementAndGet();
              if (shouldFail) {
                throw new RuntimeException("delivery failed");
              }
              return null;
            });
    ReflectionTestUtils.setField(service, "restClient", restClient);
    return callCount;
  }

  @Test
  void dispatchLogout_SkipsWhenClientIdNull() {
    service.dispatchLogout(DEFAULT_LOGOUT_URL, null, "sub-1", "sid-1");

    verify(jwtEncoder, never()).encode(any());
  }

  @Test
  void dispatchLogout_SkipsWhenClientIdBlank() {
    service.dispatchLogout(DEFAULT_LOGOUT_URL, "   ", "sub-1", "sid-1");

    verify(jwtEncoder, never()).encode(any());
  }

  @Test
  void dispatchLogout_BuildsSignedTokenAndDeliversToExplicitUri() {
    AtomicReference<JwtEncoderParameters> captured = new AtomicReference<>();
    when(jwtEncoder.encode(any()))
        .thenAnswer(
            inv -> {
              captured.set(inv.getArgument(0));
              return sampleJwt();
            });
    AtomicInteger calls = installRecordingRestClient(false);

    service.dispatchLogout("http://custom/logout", "client-a", "sub-1", "sid-1");

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(1, calls.get()));

    // Verify the signed logout_token claims conform to OIDC Back-Channel Logout 1.0.
    JwtClaimsSet claims = captured.get().getClaims();
    assertEquals(ISSUER, claims.getClaim("iss").toString());
    assertEquals(List.of("client-a"), claims.getAudience());
    assertEquals("sub-1", claims.getSubject());
    assertEquals("sid-1", claims.getClaim("sid"));
    assertNotNull(claims.getClaim("events"));
    // MUST NOT contain a nonce claim (spec Section 2.4).
    assertNull(claims.getClaim("nonce"));
  }

  @Test
  void dispatchLogout_UsesDefaultUri_WhenClientLogoutUriBlank() {
    when(jwtEncoder.encode(any())).thenReturn(sampleJwt());
    AtomicInteger calls = installRecordingRestClient(false);

    service.dispatchLogout("  ", "client-b", null, null);

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(1, calls.get()));
    verify(jwtEncoder).encode(any());
  }

  @Test
  void dispatchLogout_OmitsSubAndSid_WhenBlank() {
    AtomicReference<JwtEncoderParameters> captured = new AtomicReference<>();
    when(jwtEncoder.encode(any()))
        .thenAnswer(
            inv -> {
              captured.set(inv.getArgument(0));
              return sampleJwt();
            });
    installRecordingRestClient(false);

    service.dispatchLogout(null, "client-c", "  ", "  ");

    assertNotNull(captured.get());
    JwtClaimsSet claims = captured.get().getClaims();
    assertNull(claims.getSubject());
    assertNull(claims.getClaim("sid"));
  }

  @Test
  void dispatchLogout_SwallowsEncodingFailure() {
    when(jwtEncoder.encode(any())).thenThrow(new JwtEncodingException("kms down"));

    // Must not propagate: back-channel logout is best-effort.
    service.dispatchLogout(DEFAULT_LOGOUT_URL, "client-d", "sub", "sid");

    verify(jwtEncoder).encode(any());
  }

  @Test
  void dispatchLogout_RetriesThreeTimesOnDeliveryFailure() {
    when(jwtEncoder.encode(any())).thenReturn(sampleJwt());
    AtomicInteger calls = installRecordingRestClient(true);

    service.dispatchLogout("http://custom/logout", "client-e", "sub", "sid");

    // 3 attempts with exponential backoff before giving up.
    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(3, calls.get()));
  }

  @Test
  void dispatchLogout_StopsRetrying_WhenBackoffInterrupted() {
    when(jwtEncoder.encode(any())).thenReturn(sampleJwt());

    AtomicInteger calls = new AtomicInteger(0);
    RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
    when(restClient
            .post()
            .uri(any(URI.class))
            .contentType(any())
            .body(any(String.class))
            .retrieve()
            .toBodilessEntity())
        .thenAnswer(
            invocation -> {
              calls.incrementAndGet();
              // Interrupt the dispatching thread so the subsequent backoff Thread.sleep
              // throws InterruptedException, exercising the interrupt-handling break path.
              Thread.currentThread().interrupt();
              throw new RuntimeException("delivery failed");
            });
    ReflectionTestUtils.setField(service, "restClient", restClient);

    service.dispatchLogout("http://custom/logout", "client-f", "sub", "sid");

    // Only a single attempt should occur: the interrupt breaks out of the retry loop.
    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(1, calls.get()));
  }
}
