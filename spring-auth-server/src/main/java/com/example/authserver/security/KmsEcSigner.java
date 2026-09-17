package com.example.authserver.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.util.Collections;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Hardware Security Module (HSM) / AWS KMS-backed JWS Signer. Delegates cryptographic signing to
 * AWS KMS using elliptic curve cryptography (KeySpec ECC_NIST_P256, SIGN_VERIFY). The private key
 * NEVER touches application memory (FIPS 140-2 Level 3 / FIPS 140-3).
 *
 * <p>Signature Transcoding: AWS KMS returns ECDSA signatures encoded in ASN.1 DER format. RFC 7515
 * §A.3 strictly requires JWS ES256 signatures to be 64-byte raw concatenated (R || S) big-endian
 * integers (IEEE P1363 format). This class automatically transcodes the DER signature to IEEE P1363
 * before encoding to Base64URL.
 *
 * <p>Resilience: Implements multi-attempt retry with backoff against transient KMS connectivity
 * issues. Fail-Closed: Never falls back to insecure local keys if KMS fails.
 */
@Slf4j
public class KmsEcSigner implements JWSSigner {

  private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS =
      Collections.singleton(JWSAlgorithm.ES256);

  private final KmsClient kmsClient;
  private final String keyIdOrAlias;
  private final JCAContext jcaContext = new JCAContext();

  public KmsEcSigner(KmsClient kmsClient, String keyIdOrAlias) {
    this.kmsClient = kmsClient;
    this.keyIdOrAlias = keyIdOrAlias;
  }

  @Override
  public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
    if (!SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
      throw new JOSEException("Unsupported JWS algorithm by KMS signer: " + header.getAlgorithm());
    }

    int maxAttempts = 3;
    Exception lastException = null;

    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        SignRequest signRequest =
            SignRequest.builder()
                .keyId(keyIdOrAlias)
                .message(SdkBytes.fromByteArray(signingInput))
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build();

        SignResponse signResponse = kmsClient.sign(signRequest);
        byte[] derSignature = signResponse.signature().asByteArray();
        // Transcode ASN.1 DER to 64-byte IEEE P1363 (R || S) format for JWS RFC 7515 §A.3
        byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(derSignature, 64);
        return Base64URL.encode(jwsSignature);
      } catch (Exception e) {
        lastException = e;
        if (attempt < maxAttempts) {
          long backoffMs = (long) (Math.pow(2, attempt - 1) * 100);
          log.warn(
              "KMS sign attempt {} failed for key {}: {}. Retrying in {}ms...",
              attempt,
              keyIdOrAlias,
              e.getMessage(),
              backoffMs);
          try {
            Thread.sleep(backoffMs);
          } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new JOSEException("Interrupted during KMS sign retry: " + ex.getMessage(), ex);
          }
        } else {
          log.error(
              "All {} attempts to sign payload with AWS KMS failed for key: {}",
              maxAttempts,
              keyIdOrAlias,
              e);
        }
      }
    }

    // Strict Fail-Closed: Throw exception rather than degrading cryptographic security
    throw new JOSEException(
        "Strict Fail-Closed: AWS KMS cryptographic signing failed after "
            + maxAttempts
            + " attempts: "
            + (lastException != null ? lastException.getMessage() : "unknown error"),
        lastException);
  }

  @Override
  public Set<JWSAlgorithm> supportedJWSAlgorithms() {
    return SUPPORTED_ALGORITHMS;
  }

  @Override
  public JCAContext getJCAContext() {
    return jcaContext;
  }
}
