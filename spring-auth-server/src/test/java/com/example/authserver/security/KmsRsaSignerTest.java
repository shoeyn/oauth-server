package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

@ExtendWith(MockitoExtension.class)
class KmsRsaSignerTest {

  @Mock private KmsClient kmsClient;

  private KmsRsaSigner signer;

  private final byte[] signingInput = "signing-input".getBytes();

  @BeforeEach
  void setUp() {
    signer = new KmsRsaSigner(kmsClient, "alias/oauth2-signing-key");
  }

  private JWSHeader rs256Header() {
    return new JWSHeader(JWSAlgorithm.RS256);
  }

  @Test
  void supportedJWSAlgorithms_ReturnsOnlyRs256() {
    Set<JWSAlgorithm> supported = signer.supportedJWSAlgorithms();

    assertEquals(1, supported.size());
    assertTrue(supported.contains(JWSAlgorithm.RS256));
  }

  @Test
  void getJCAContext_IsNotNull() {
    assertNotNull(signer.getJCAContext());
  }

  @Test
  void sign_RejectsUnsupportedAlgorithm() {
    JWSHeader hs256 = new JWSHeader(JWSAlgorithm.HS256);

    JOSEException ex = assertThrows(JOSEException.class, () -> signer.sign(hs256, signingInput));

    assertTrue(ex.getMessage().contains("Unsupported JWS algorithm"));
  }

  @Test
  void sign_ReturnsBase64Signature_OnSuccess() throws Exception {
    byte[] sigBytes = new byte[] {1, 2, 3, 4};
    SignResponse resp = SignResponse.builder().signature(SdkBytes.fromByteArray(sigBytes)).build();
    when(kmsClient.sign(any(SignRequest.class))).thenReturn(resp);

    Base64URL result = signer.sign(rs256Header(), signingInput);

    assertEquals(Base64URL.encode(sigBytes), result);
    verify(kmsClient, times(1)).sign(any(SignRequest.class));
  }

  @Test
  void sign_RetriesThenSucceeds_OnTransientFailure() throws Exception {
    byte[] sigBytes = new byte[] {9, 8, 7};
    SignResponse resp = SignResponse.builder().signature(SdkBytes.fromByteArray(sigBytes)).build();
    when(kmsClient.sign(any(SignRequest.class)))
        .thenThrow(KmsException.builder().message("transient").build())
        .thenReturn(resp);

    Base64URL result = signer.sign(rs256Header(), signingInput);

    assertEquals(Base64URL.encode(sigBytes), result);
    verify(kmsClient, times(2)).sign(any(SignRequest.class));
  }

  @Test
  void sign_FailsClosed_AfterAllRetriesExhausted() {
    when(kmsClient.sign(any(SignRequest.class)))
        .thenThrow(KmsException.builder().message("kms down").build());

    JOSEException ex =
        assertThrows(JOSEException.class, () -> signer.sign(rs256Header(), signingInput));

    assertTrue(ex.getMessage().contains("Strict Fail-Closed"));
    verify(kmsClient, times(3)).sign(any(SignRequest.class));
  }

  @Test
  void sign_ThrowsAndSetsInterruptFlag_WhenInterruptedDuringBackoff() {
    when(kmsClient.sign(any(SignRequest.class)))
        .thenThrow(KmsException.builder().message("transient").build());

    // Interrupt the current thread so Thread.sleep in the backoff throws InterruptedException.
    Thread.currentThread().interrupt();
    try {
      JOSEException ex =
          assertThrows(JOSEException.class, () -> signer.sign(rs256Header(), signingInput));
      assertTrue(ex.getMessage().contains("Interrupted during KMS sign retry"));
      assertTrue(Thread.currentThread().isInterrupted());
    } finally {
      // Clear the interrupt flag so it does not leak into subsequent tests.
      Thread.interrupted();
    }
  }
}
