package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClientPreDeterminedScopeAuthorizationRequestConverterTest {

  private static final String CLIENT_ID = "demo-client";
  private static final String REDIRECT_URI = "https://client.example/callback";

  @Mock private RegisteredClientRepository registeredClientRepository;

  @Mock private OAuth2AuthorizationService authorizationService;

  private ClientPreDeterminedScopeAuthorizationRequestConverter converter;

  @BeforeEach
  void setUp() {
    converter =
        new ClientPreDeterminedScopeAuthorizationRequestConverter(
            registeredClientRepository, authorizationService);
    SecurityContextHolder.getContext()
        .setAuthentication(new TestingAuthenticationToken("alice", "n/a", "ROLE_USER"));

    // The delegate OAuth2AuthorizationCodeRequestAuthenticationConverter requires an
    // AuthorizationServerContext to resolve endpoint settings (e.g. PAR detection).
    AuthorizationServerSettings settings =
        AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    AuthorizationServerContext context =
        new AuthorizationServerContext() {
          @Override
          public String getIssuer() {
            return "http://localhost:9000";
          }

          @Override
          public AuthorizationServerSettings getAuthorizationServerSettings() {
            return settings;
          }
        };
    AuthorizationServerContextHolder.setContext(context);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
    AuthorizationServerContextHolder.resetContext();
  }

  private RegisteredClient client(boolean requirePar, Set<String> scopes) {
    RegisteredClient.Builder builder =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(CLIENT_ID)
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(REDIRECT_URI);
    for (String s : scopes) {
      builder.scope(s);
    }
    builder.clientSettings(
        ClientSettings.builder()
            .requireProofKey(true)
            .setting("settings.client.require-pushed-authorization-requests", requirePar)
            .build());
    return builder.build();
  }

  private MockHttpServletRequest authorizeRequest(String requestUri) {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setServerName("localhost");
    request.setServerPort(9000);
    StringBuilder qs =
        new StringBuilder("response_type=code")
            .append("&client_id=")
            .append(CLIENT_ID)
            .append("&redirect_uri=")
            .append("https://client.example/callback")
            .append("&state=xyz-state");
    request.setParameter("response_type", "code");
    request.setParameter("client_id", CLIENT_ID);
    request.setParameter("redirect_uri", REDIRECT_URI);
    request.setParameter("state", "xyz-state");
    if (requestUri != null) {
      qs.append("&request_uri=").append(requestUri);
      request.setParameter("request_uri", requestUri);
    }
    request.setQueryString(qs.toString());
    return request;
  }

  @Test
  void convert_BindsServerDeterminedScopes_OnValidRequest() {
    MockHttpServletRequest request = authorizeRequest("urn:ietf:params:oauth:request_uri:abc");
    when(registeredClientRepository.findByClientId(CLIENT_ID))
        .thenReturn(client(true, Set.of("openid", "profile")));

    Authentication result = converter.convert(request);

    OAuth2AuthorizationCodeRequestAuthenticationToken token =
        assertInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationToken.class, result);
    assertEquals(Set.of("openid", "profile"), token.getScopes());
    assertEquals(CLIENT_ID, token.getClientId());
  }

  @Test
  void convert_RejectsDirectRequest_WhenParRequiredButRequestUriMissing() {
    MockHttpServletRequest request = authorizeRequest(null);
    when(registeredClientRepository.findByClientId(CLIENT_ID))
        .thenReturn(client(true, Set.of("openid")));

    OAuth2AuthorizationCodeRequestAuthenticationException ex =
        assertThrows(
            OAuth2AuthorizationCodeRequestAuthenticationException.class,
            () -> converter.convert(request));

    assertEquals("invalid_request", ex.getError().getErrorCode());
    assertTrue(ex.getError().getDescription().contains("Pushed Authorization Requests"));
  }

  @Test
  void convert_AllowsDirectRequest_WhenParNotRequired() {
    MockHttpServletRequest request = authorizeRequest(null);
    when(registeredClientRepository.findByClientId(CLIENT_ID))
        .thenReturn(client(false, Set.of("openid")));

    Authentication result = converter.convert(request);

    OAuth2AuthorizationCodeRequestAuthenticationToken token =
        assertInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationToken.class, result);
    assertEquals(Set.of("openid"), token.getScopes());
  }

  @Test
  void convert_BindsEmptyScopes_WhenClientNotFound() {
    MockHttpServletRequest request = authorizeRequest(null);
    when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);

    Authentication result = converter.convert(request);

    OAuth2AuthorizationCodeRequestAuthenticationToken token =
        assertInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationToken.class, result);
    assertTrue(token.getScopes().isEmpty());
  }

  @Test
  void convert_ForwardsIdpError_WithDirectParameters() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setParameter("error", "access_denied");
    request.setParameter("error_description", "user cancelled");
    request.setParameter("client_id", CLIENT_ID);
    request.setParameter("redirect_uri", REDIRECT_URI);
    request.setParameter("state", "s1");

    OAuth2AuthorizationCodeRequestAuthenticationException ex =
        assertThrows(
            OAuth2AuthorizationCodeRequestAuthenticationException.class,
            () -> converter.convert(request));

    assertEquals("access_denied", ex.getError().getErrorCode());
    assertEquals("user cancelled", ex.getError().getDescription());
  }

  @Test
  void convert_ForwardsIdpError_ResolvingMissingParamsFromPar() {
    String requestUri = "urn:ietf:params:oauth:request_uri:par123";
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setParameter("error", "server_error");
    request.setParameter("request_uri", requestUri);

    OAuth2AuthorizationRequest authReq =
        OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("http://localhost:9000/oauth2/authorize")
            .clientId(CLIENT_ID)
            .redirectUri(REDIRECT_URI)
            .state("resolved-state")
            .build();
    OAuth2Authorization authorization =
        OAuth2Authorization.withRegisteredClient(client(true, Set.of("openid")))
            .principalName("alice")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .attribute(OAuth2AuthorizationRequest.class.getName(), authReq)
            .build();

    when(authorizationService.findByToken(eq("par123"), any(OAuth2TokenType.class)))
        .thenReturn(authorization);

    OAuth2AuthorizationCodeRequestAuthenticationException ex =
        assertThrows(
            OAuth2AuthorizationCodeRequestAuthenticationException.class,
            () -> converter.convert(request));

    assertEquals("server_error", ex.getError().getErrorCode());
  }

  @Test
  void convert_ForwardsIdpError_WhenAnonymousPrincipal() {
    SecurityContextHolder.clearContext();
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setParameter("error", "access_denied");
    request.setParameter("client_id", CLIENT_ID);
    request.setParameter("redirect_uri", REDIRECT_URI);
    request.setParameter("state", "s1");

    assertThrows(
        OAuth2AuthorizationCodeRequestAuthenticationException.class,
        () -> converter.convert(request));
  }

  @Test
  void convert_ForwardsIdpError_WithRequestUriButNullPar_KeepsDirectParams() {
    // request_uri present, redirect_uri present but state missing -> attempts PAR resolution,
    // which returns null (no stored authorization) so direct params are retained.
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setParameter("error", "access_denied");
    request.setParameter("client_id", CLIENT_ID);
    request.setParameter("redirect_uri", REDIRECT_URI);
    request.setParameter("request_uri", "urn:ietf:params:oauth:request_uri:missing");
    when(authorizationService.findByToken(eq("missing"), any(OAuth2TokenType.class)))
        .thenReturn(null);

    OAuth2AuthorizationCodeRequestAuthenticationException ex =
        assertThrows(
            OAuth2AuthorizationCodeRequestAuthenticationException.class,
            () -> converter.convert(request));

    assertEquals("access_denied", ex.getError().getErrorCode());
  }

  @Test
  void convert_ForwardsIdpError_ResolvingOnlyStateFromPar_WhenRedirectPresent() {
    // redirect_uri present, state absent -> only the state is recovered from the stored PAR
    // request.
    String requestUri = "urn:ietf:params:oauth:request_uri:par-partial";
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
    request.setParameter("error", "temporarily_unavailable");
    request.setParameter("client_id", CLIENT_ID);
    request.setParameter("redirect_uri", REDIRECT_URI);
    request.setParameter("request_uri", requestUri);

    OAuth2AuthorizationRequest authReq =
        OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("http://localhost:9000/oauth2/authorize")
            .clientId(CLIENT_ID)
            .redirectUri(REDIRECT_URI)
            .state("state-from-par")
            .build();
    OAuth2Authorization authorization =
        OAuth2Authorization.withRegisteredClient(client(true, Set.of("openid")))
            .principalName("alice")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .attribute(OAuth2AuthorizationRequest.class.getName(), authReq)
            .build();
    when(authorizationService.findByToken(eq("par-partial"), any(OAuth2TokenType.class)))
        .thenReturn(authorization);

    OAuth2AuthorizationCodeRequestAuthenticationException ex =
        assertThrows(
            OAuth2AuthorizationCodeRequestAuthenticationException.class,
            () -> converter.convert(request));

    assertEquals("temporarily_unavailable", ex.getError().getErrorCode());
  }
}
