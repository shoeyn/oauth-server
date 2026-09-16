package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

@ExtendWith(MockitoExtension.class)
class KmsJwtEncoderTest {

  @Mock private KmsRsaSigner kmsRsaSigner;

  private JwtClaimsSet sampleClaims() {
    Instant now = Instant.now();
    return JwtClaimsSet.builder()
        .issuer("http://localhost:9000")
        .subject("user-1")
        .issuedAt(now)
        .expiresAt(now.plusSeconds(120))
        .claim("custom", "value")
        .build();
  }

  private void stubSuccessfulSigner() throws Exception {
    when(kmsRsaSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
    when(kmsRsaSigner.sign(any(JWSHeader.class), any(byte[].class)))
        .thenReturn(Base64URL.encode(new byte[] {1, 2, 3, 4}));
  }

  @Test
  void encode_ProducesSignedJwt_UsingDefaultKeyId() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, sampleClaims()));

    assertNotNull(jwt.getTokenValue());
    // Token value is a serialized JWS (three dot-separated segments)
    assertEquals(3, jwt.getTokenValue().split("\\.").length);
    assertEquals("kms-default-key", jwt.getHeaders().get("kid"));
    assertEquals("value", jwt.getClaims().get("custom"));
  }

  @Test
  void encode_PrefersHeaderKeyId_OverDefaultAndCopiesCustomHeaders() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    JwsHeader header =
        JwsHeader.with(SignatureAlgorithm.RS256)
            .keyId("explicit-key")
            .header("customHeader", "hv")
            .build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, sampleClaims()));

    assertEquals("explicit-key", jwt.getHeaders().get("kid"));
    assertEquals("hv", jwt.getHeaders().get("customHeader"));
  }

  @Test
  void encode_WrapsSignerFailure_InJwtEncodingException() throws Exception {
    when(kmsRsaSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
    when(kmsRsaSigner.sign(any(JWSHeader.class), any(byte[].class)))
        .thenThrow(new RuntimeException("kms exploded"));
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
    JwtEncoderParameters params = JwtEncoderParameters.from(header, sampleClaims());

    JwtEncodingException ex =
        assertThrows(JwtEncodingException.class, () -> encoder.encode(params));

    assertTrue(ex.getMessage().contains("Strict Fail-Closed"));
  }

  @Test
  void encode_HandlesNullDefaultKeyId_WhenHeaderHasNoKid() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, null);

    JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, sampleClaims()));

    assertNotNull(jwt.getTokenValue());
  }

  @Test
  void encode_HandlesBlankHeaderKid_FallsBackToDefault() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId("  ").build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, sampleClaims()));

    assertEquals("kms-default-key", jwt.getHeaders().get("kid"));
  }

  @Test
  void encode_HandlesNonInstantClaims() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer("http://localhost:9000")
            .claim("scope", Collections.singletonList("openid"))
            .build();
    JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, claims));

    assertNotNull(jwt.getTokenValue());
  }

  @Test
  void encode_SkipsReservedHeaders_AlgKidTyp() throws Exception {
    stubSuccessfulSigner();
    KmsJwtEncoder encoder = new KmsJwtEncoder(kmsRsaSigner, "kms-default-key");

    // Reserved headers (alg/kid/typ) present on the source header must be filtered out
    // (they are set explicitly by the encoder), while other custom headers are copied.
    JwsHeader header =
        JwsHeader.with(SignatureAlgorithm.RS256)
            .header("kid", "source-kid")
            .header("typ", "at+jwt")
            .header("extra", "kept")
            .build();
    Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, sampleClaims()));

    assertNotNull(jwt.getTokenValue());
    assertEquals("kept", jwt.getHeaders().get("extra"));
  }
}
