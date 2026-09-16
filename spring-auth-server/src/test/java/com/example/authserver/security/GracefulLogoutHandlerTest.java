package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class GracefulLogoutHandlerTest {

  @Mock private PostgresRegisteredClientRepository registeredClientRepository;

  @Mock private StringRedisTemplate redisTemplate;

  @Mock private HttpServletRequest request;

  @Mock private HttpServletResponse response;

  private GracefulLogoutHandler handler;
  private KeyPair keyPair;
  private RSAKey rsaKey;

  @BeforeEach
  void setUp() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();

    rsaKey =
        new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID("test-key-id")
            .build();

    JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    handler =
        new GracefulLogoutHandler(registeredClientRepository, redisTemplate, jwkSource, "session:");
  }

  private String createSignedJwt(String clientId, Date expiration) throws Exception {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("user-123")
            .audience(List.of(clientId))
            .expirationTime(expiration)
            .issueTime(new Date(expiration.getTime() - 3600_000L))
            .build();

    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key-id").build(), claims);

    signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
    return signedJWT.serialize();
  }

  @Test
  void handleGracefully_missingParameters_returnsFalse() throws Exception {
    when(request.getParameter("id_token_hint")).thenReturn(null);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(null);

    assertFalse(handler.handleGracefully(request, response));
  }

  @Test
  void handleGracefully_missingIdTokenHintOnly_returnsFalse() throws Exception {
    when(request.getParameter("id_token_hint")).thenReturn(null);
    when(request.getParameter("post_logout_redirect_uri"))
        .thenReturn("http://localhost:8080/logout");

    assertFalse(handler.handleGracefully(request, response));
  }

  @Test
  void handleGracefully_missingRedirectUriOnly_returnsFalse() throws Exception {
    when(request.getParameter("id_token_hint")).thenReturn("some-token");
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(null);

    assertFalse(handler.handleGracefully(request, response));
  }

  @Test
  void handleGracefully_emptyAudience_returnsFalse() throws Exception {
    // Valid signature, expired, but the audience list is empty → cannot resolve a client.
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("user-123")
            .audience(java.util.Collections.emptyList())
            .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
            .build();
    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key-id").build(), claims);
    signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));

    when(request.getParameter("id_token_hint")).thenReturn(signedJWT.serialize());
    when(request.getParameter("post_logout_redirect_uri"))
        .thenReturn("http://localhost:8080/logout-success");

    assertFalse(handler.handleGracefully(request, response));
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void handleGracefully_expiredTokenValidSignature_registeredUri_redirectsGracefully()
      throws Exception {
    String clientId = "demo-client";
    String redirectUri = "http://localhost:8080/logout-success";

    // Create an already expired token (1 hour in the past)
    Date expiredTime = Date.from(Instant.now().minusSeconds(3600));
    String expiredJwt = createSignedJwt(clientId, expiredTime);

    when(request.getParameter("id_token_hint")).thenReturn(expiredJwt);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(redirectUri);

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/callback")
            .postLogoutRedirectUri(redirectUri)
            .build();

    when(registeredClientRepository.findByClientId(clientId)).thenReturn(client);
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", "session-xyz")});

    boolean handled = handler.handleGracefully(request, response);

    assertTrue(handled);
    verify(redisTemplate).delete("session:session-xyz");
    verify(response)
        .addCookie(argThat(c -> "SHARED_SESSION_ID".equals(c.getName()) && c.getMaxAge() == 0));
    verify(response).sendRedirect(redirectUri);
  }

  @Test
  void handleGracefully_withStateParameter_preservesStateInRedirect() throws Exception {
    String clientId = "demo-client";
    String redirectUri = "http://localhost:8080/logout-success";
    String state = "test-state-token-1234";

    Date expiredTime = Date.from(Instant.now().minusSeconds(3600));
    String expiredJwt = createSignedJwt(clientId, expiredTime);

    when(request.getParameter("id_token_hint")).thenReturn(expiredJwt);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(redirectUri);
    when(request.getParameter("state")).thenReturn(state);

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/callback")
            .postLogoutRedirectUri(redirectUri)
            .build();

    when(registeredClientRepository.findByClientId(clientId)).thenReturn(client);
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", "session-xyz")});

    boolean handled = handler.handleGracefully(request, response);

    assertTrue(handled);
    verify(response).sendRedirect(redirectUri + "?state=" + state);
  }

  @Test
  void handleGracefully_unregisteredRedirectUri_returnsFalse() throws Exception {
    String clientId = "demo-client";
    String unapprovedUri = "http://evil.com/logout";

    Date expiredTime = Date.from(Instant.now().minusSeconds(3600));
    String expiredJwt = createSignedJwt(clientId, expiredTime);

    when(request.getParameter("id_token_hint")).thenReturn(expiredJwt);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(unapprovedUri);

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/callback")
            .postLogoutRedirectUri("http://localhost:8080/safe-logout")
            .build();

    when(registeredClientRepository.findByClientId(clientId)).thenReturn(client);

    boolean handled = handler.handleGracefully(request, response);

    assertFalse(handled);
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void handleGracefully_invalidSignature_returnsFalse() throws Exception {
    String forgedJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.forged_signature";

    when(request.getParameter("id_token_hint")).thenReturn(forgedJwt);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn("http://localhost:8080");

    assertFalse(handler.handleGracefully(request, response));
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void evictSharedSession_clearsRedisAndCookie() {
    when(request.getCookies())
        .thenReturn(
            new Cookie[] {
              new Cookie("OTHER_COOKIE", "value"),
              new Cookie("SHARED_SESSION_ID", "active-session-123")
            });

    handler.evictSharedSession(request, response);

    verify(redisTemplate).delete("session:active-session-123");
    verify(response)
        .addCookie(
            argThat(
                c ->
                    "SHARED_SESSION_ID".equals(c.getName())
                        && c.getMaxAge() == 0
                        && c.isHttpOnly()
                        && "/".equals(c.getPath())));
  }

  @Test
  void handleGracefully_tokenWithoutAudience_returnsFalse() throws Exception {
    // Signed token with a valid signature but no audience claim → cannot resolve a client.
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("user-123")
            .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
            .build();
    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key-id").build(), claims);
    signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));

    when(request.getParameter("id_token_hint")).thenReturn(signedJWT.serialize());
    when(request.getParameter("post_logout_redirect_uri"))
        .thenReturn("http://localhost:8080/logout-success");

    assertFalse(handler.handleGracefully(request, response));
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void handleGracefully_unknownClient_returnsFalse() throws Exception {
    String clientId = "ghost-client";
    Date expiredTime = Date.from(Instant.now().minusSeconds(3600));
    String expiredJwt = createSignedJwt(clientId, expiredTime);

    when(request.getParameter("id_token_hint")).thenReturn(expiredJwt);
    when(request.getParameter("post_logout_redirect_uri"))
        .thenReturn("http://localhost:8080/logout-success");
    when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

    assertFalse(handler.handleGracefully(request, response));
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  void extractSessionId_noCookies_returnsNull() {
    when(request.getCookies()).thenReturn(null);
    assertNull(handler.extractSessionId(request));
  }

  @Test
  void extractSessionId_noMatchingCookie_returnsNull() {
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("UNRELATED", "value")});
    assertNull(handler.extractSessionId(request));
  }

  @Test
  void evictSharedSession_noSessionCookie_stillClearsBrowserCookie() {
    // No SHARED_SESSION_ID present: Redis is not touched, but a zeroed cookie is still emitted.
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("UNRELATED", "value")});

    handler.evictSharedSession(request, response);

    verify(redisTemplate, never()).delete(anyString());
    verify(response)
        .addCookie(argThat(c -> "SHARED_SESSION_ID".equals(c.getName()) && c.getMaxAge() == 0));
  }

  @Test
  void evictSharedSession_blankSessionId_doesNotTouchRedis() {
    // SHARED_SESSION_ID present but blank → the !isBlank() guard skips the Redis delete.
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", "   ")});

    handler.evictSharedSession(request, response);

    verify(redisTemplate, never()).delete(anyString());
    verify(response)
        .addCookie(argThat(c -> "SHARED_SESSION_ID".equals(c.getName()) && c.getMaxAge() == 0));
  }

  @Test
  void handleGracefully_malformedRedirectUri_fallsBackToRawComparison() throws Exception {
    // A request post_logout_redirect_uri that cannot be parsed exercises the
    // normaliseUri catch fallback (returns the raw string). It does not match the
    // client's valid registered URI, so the fallback is safely rejected.
    String clientId = "demo-client";
    String malformedUri = "ht!tp://[not a uri";

    Date expiredTime = Date.from(Instant.now().minusSeconds(3600));
    String expiredJwt = createSignedJwt(clientId, expiredTime);

    when(request.getParameter("id_token_hint")).thenReturn(expiredJwt);
    when(request.getParameter("post_logout_redirect_uri")).thenReturn(malformedUri);

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/callback")
            .postLogoutRedirectUri("http://localhost:8080/safe-logout")
            .build();

    when(registeredClientRepository.findByClientId(clientId)).thenReturn(client);

    boolean handled = handler.handleGracefully(request, response);

    assertFalse(handled);
    verify(response, never()).sendRedirect(anyString());
  }
}
