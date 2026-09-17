package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClientAssertionDecoderFactoryTest {

  private static final String ISSUER = "http://localhost:9000";
  private static final String CLIENT_ID = "demo-client";

  @Mock private PostgresRegisteredClientRepository repository;

  @Mock private StringRedisTemplate redisTemplate;

  @Mock private ValueOperations<String, String> valueOperations;

  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;
  private ClientAssertionDecoderFactory factory;
  private RegisteredClient registeredClient;

  @BeforeEach
  void setUp() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(256);
    KeyPair pair = gen.generateKeyPair();
    publicKey = (ECPublicKey) pair.getPublic();
    privateKey = (ECPrivateKey) pair.getPrivate();

    factory = new ClientAssertionDecoderFactory(repository, redisTemplate, ISSUER);
    registeredClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(CLIENT_ID)
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build();

    lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    lenient()
        .when(valueOperations.setIfAbsent(anyString(), eq("1"), any(Duration.class)))
        .thenReturn(Boolean.TRUE);
  }

  private String signedAssertion(JWTClaimsSet claims) throws Exception {
    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
    jwt.sign(new ECDSASigner(privateKey));
    return jwt.serialize();
  }

  private JWTClaimsSet.Builder validClaimsBuilder() {
    Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .subject(CLIENT_ID)
        .issuer(CLIENT_ID)
        .audience(ISSUER + "/oauth2/token")
        .jwtID(UUID.randomUUID().toString())
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(60)));
  }

  @Test
  void createDecoder_ThrowsInvalidClient_WhenNoPublicKeyRegistered() {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(null);

    OAuth2AuthenticationException ex =
        assertThrows(
            OAuth2AuthenticationException.class, () -> factory.createDecoder(registeredClient));

    assertEquals("invalid_client", ex.getError().getErrorCode());
  }

  @Test
  void decoder_DecodesValidAssertion() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().build());
    assertNotNull(decoder.decode(token).getSubject());
  }

  @Test
  void decoder_IsCached_ForSameClientAndKey() {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);

    JwtDecoder first = factory.createDecoder(registeredClient);
    JwtDecoder second = factory.createDecoder(registeredClient);

    assertSame(first, second);
  }

  @Test
  void decoder_RejectsAssertion_WhenSubjectMismatch() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().subject("someone-else").build());

    JwtException ex = assertThrows(JwtException.class, () -> decoder.decode(token));
    assertTrue(ex.getMessage().contains("Subject"));
  }

  @Test
  void decoder_RejectsAssertion_WhenIssuerMismatch() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().issuer("evil-client").build());

    JwtException ex = assertThrows(JwtException.class, () -> decoder.decode(token));
    assertTrue(ex.getMessage().contains("Issuer"));
  }

  @Test
  void decoder_RejectsAssertion_WhenAudienceInvalid() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().audience("https://other-server").build());

    JwtException ex = assertThrows(JwtException.class, () -> decoder.decode(token));
    assertTrue(ex.getMessage().contains("Audience"));
  }

  @Test
  void decoder_AcceptsAssertion_WhenAudienceIsExactIssuer() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().audience(ISSUER).build());
    assertNotNull(decoder.decode(token));
  }

  @Test
  void decoder_AcceptsAssertion_WhenIssuerAbsent() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(CLIENT_ID)
            .audience(ISSUER)
            .jwtID(UUID.randomUUID().toString())
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    String token = signedAssertion(claims);
    assertNotNull(decoder.decode(token));
  }

  @Test
  void decoder_RejectsAssertion_OnJtiReplay() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    when(valueOperations.setIfAbsent(anyString(), eq("1"), any(Duration.class)))
        .thenReturn(Boolean.FALSE);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token = signedAssertion(validClaimsBuilder().build());

    JwtException ex = assertThrows(JwtException.class, () -> decoder.decode(token));
    assertTrue(ex.getMessage().contains("replay"));
  }

  @Test
  void decoder_AcceptsAssertion_WhenNoJtiPresent() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(CLIENT_ID)
            .issuer(CLIENT_ID)
            .audience(ISSUER)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    String token = signedAssertion(claims);
    assertNotNull(decoder.decode(token));
  }

  @Test
  void decoder_RejectsAssertion_WhenAlgorithmNotEs256() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    // An HS256-signed assertion must be rejected by strict algorithm pinning.
    SignedJWT hs = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), validClaimsBuilder().build());
    hs.sign(new MACSigner(new byte[32]));

    assertThrows(JwtException.class, () -> decoder.decode(hs.serialize()));
  }

  @Test
  void decoder_DecodesValidAssertion_WithKidInHeader() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("demo-client-key-1").build();
    SignedJWT jwt = new SignedJWT(header, validClaimsBuilder().build());
    jwt.sign(new ECDSASigner(privateKey));

    assertNotNull(decoder.decode(jwt.serialize()).getSubject());
  }

  @Test
  void decoder_AcceptsAssertion_WhenAudienceEndsWithPar() throws Exception {
    when(repository.getClientPublicKey(CLIENT_ID)).thenReturn(publicKey);
    JwtDecoder decoder = factory.createDecoder(registeredClient);

    String token =
        signedAssertion(
            validClaimsBuilder().audience("http://spring-auth-server:9000/oauth2/par").build());
    assertNotNull(decoder.decode(token));
  }
}
