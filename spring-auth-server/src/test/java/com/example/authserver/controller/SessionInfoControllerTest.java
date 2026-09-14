package com.example.authserver.controller;

import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.UserSessionRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Principal;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SessionInfoControllerTest {

    private static final String API_KEY = "secret-admin-key";

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private UserSessionRevocationService revocationService;

    @Mock
    private OidcBackChannelLogoutService oidcBackChannelLogoutService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @InjectMocks
    private SessionInfoController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(controller, "adminApiKey", API_KEY);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    private UserSessionRevocationService.RevocationResult result(int purged, boolean evicted) {
        return new UserSessionRevocationService.RevocationResult(purged, evicted);
    }

    @Test
    void me_ReturnsAuthenticationDetails_WhenAuthenticationPrincipal() throws Exception {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("bob", "n/a", "ROLE_USER");

        mockMvc.perform(get("/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));
    }

    @Test
    void me_ReturnsPrincipalName_WhenPlainPrincipal() throws Exception {
        Principal principal = () -> "carol";

        mockMvc.perform(get("/me").principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.principal").value("carol"));
    }

    @Test
    void revokeSession_Unauthorized_WhenApiKeyMissing() throws Exception {
        mockMvc.perform(post("/api/admin/revoke-session"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"));

        verify(revocationService, never()).revokeUserGlobally(any(), any(), any());
    }

    @Test
    void revokeSession_Unauthorized_WhenApiKeyWrong() throws Exception {
        mockMvc.perform(post("/api/admin/revoke-session").header("X-Admin-Api-Key", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void revokeSession_RevokesByUsername_WhenNoToken() throws Exception {
        when(revocationService.revokeUserGlobally(eq("dave"), isNull(), eq("sess-1")))
                .thenReturn(result(2, true));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("username", "dave")
                        .param("sessionId", "sess-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"))
                .andExpect(jsonPath("$.username").value("dave"))
                .andExpect(jsonPath("$.token_revoked").value(false))
                .andExpect(jsonPath("$.session_evicted").value(true));

        // No clientId resolvable -> back-channel logout is skipped.
        verify(oidcBackChannelLogoutService, never()).dispatchLogout(any(), any(), any(), any());
    }

    @Test
    void revokeSession_ResolvesTokenAndDispatchesBackChannelLogout() throws Exception {
        String token = "access-token-value";
        String rcId = UUID.randomUUID().toString();

        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("erin");
        when(authorization.getRegisteredClientId()).thenReturn(rcId);
        TestingAuthenticationToken userAuth = new TestingAuthenticationToken("erin", "n/a");
        userAuth.setDetails(Map.of("session_id", "sid-from-token"));
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN)))
                .thenReturn(authorization);

        RegisteredClient rc = RegisteredClient.withId(rcId)
                .clientId("erin-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://c/cb")
                .build();
        when(registeredClientRepository.findById(rcId)).thenReturn(rc);

        when(revocationService.revokeUserGlobally(eq("erin"), eq(authorization), eq("sid-from-token")))
                .thenReturn(result(1, true));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_revoked").value(true))
                .andExpect(jsonPath("$.username").value("erin"));

        verify(oidcBackChannelLogoutService).dispatchLogout(isNull(), eq("erin-client"), eq("erin"), eq("sid-from-token"));
    }

    @Test
    void revokeSession_FallsBackToRefreshTokenLookup() throws Exception {
        String token = "refresh-token-value";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("frank");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(null);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(null);
        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.REFRESH_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("frank"), eq(authorization), isNull()))
                .thenReturn(result(1, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_revoked").value(true));

        // registeredClientId null -> no client resolution -> no dispatch.
        verify(oidcBackChannelLogoutService, never()).dispatchLogout(any(), any(), any(), any());
    }

    @Test
    void revokeSession_TokenNotFound_NoRevocationOfAuthorization() throws Exception {
        String token = "unknown-token";
        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(null);
        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.REFRESH_TOKEN))).thenReturn(null);
        when(revocationService.revokeUserGlobally(isNull(), isNull(), isNull()))
                .thenReturn(result(0, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_revoked").value(false))
                .andExpect(jsonPath("$.username").value("unknown"));
    }

    @Test
    void me_UsesEmptyDetails_WhenAuthenticationDetailsNull() throws Exception {
        // TestingAuthenticationToken has null details by default -> Map.of() fallback branch.
        TestingAuthenticationToken auth = new TestingAuthenticationToken("noDetails", "n/a", "ROLE_USER");

        mockMvc.perform(get("/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("noDetails"));
    }

    @Test
    void me_ReturnsAnonymous_WhenPrincipalNull() throws Exception {
        mockMvc.perform(get("/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.principal").value("anonymous"));
    }

    @Test
    void revokeSession_BlankToken_TreatedAsNoToken() throws Exception {
        when(revocationService.revokeUserGlobally(eq("gina"), isNull(), isNull()))
                .thenReturn(result(0, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", "   ")
                        .param("username", "gina"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_revoked").value(false));

        // token blank -> no authorization lookup performed.
        verify(authorizationService, never()).findByToken(anyString(), any(OAuth2TokenType.class));
    }

    @Test
    void revokeSession_KeepsProvidedUsernameAndSession_OverToken() throws Exception {
        // username + sessionId explicitly provided AND a token: the explicit values must be retained
        // (resolvedUsername already non-null, resolvedSessionId already non-null branches).
        String token = "tk";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("token-principal");
        when(authorization.getRegisteredClientId()).thenReturn("rc-id");

        Authentication userAuth = new TestingAuthenticationToken("token-principal", "n/a");
        ((TestingAuthenticationToken) userAuth).setDetails(Map.of("session_id", "token-sid"));
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(registeredClientRepository.findById("rc-id")).thenReturn(null); // rc == null branch
        when(revocationService.revokeUserGlobally(eq("explicit-user"), eq(authorization), eq("explicit-sid")))
                .thenReturn(result(1, true));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token)
                        .param("username", "explicit-user")
                        .param("sessionId", "explicit-sid"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("explicit-user"));

        // resolvedClientId null (rc was null) -> back-channel dispatch skipped.
        verify(oidcBackChannelLogoutService, never()).dispatchLogout(any(), any(), any(), any());
    }

    @Test
    void revokeSession_TokenWithoutUserAuthDetails_NoSessionResolved() throws Exception {
        String token = "tk2";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("harry");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        // userAuth present but details is not a Map -> instanceof branch false.
        Authentication userAuth = new TestingAuthenticationToken("harry", "n/a");
        ((TestingAuthenticationToken) userAuth).setDetails("plain-string-details");
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("harry"), eq(authorization), isNull()))
                .thenReturn(result(1, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_revoked").value(true));
    }

    @Test
    void me_IncludesDetails_WhenAuthenticationDetailsPresent() throws Exception {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("withDetails", "n/a", "ROLE_USER");
        auth.setDetails(Map.of("session_id", "sid-9"));

        mockMvc.perform(get("/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.details.session_id").value("sid-9"));
    }

    @Test
    void revokeSession_BlankUsernameParam_ResolvesUsernameFromToken() throws Exception {
        // username param is blank (isBlank() true) so the principal name is taken from the token.
        String token = "tk3";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("resolved-from-token");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(null);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("resolved-from-token"), eq(authorization), isNull()))
                .thenReturn(result(1, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token)
                        .param("username", "   "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("resolved-from-token"));
    }

    @Test
    void revokeSession_TokenWithMapDetailsButNoSessionId_LeavesSessionUnresolved() throws Exception {
        // userAuth details is a Map but lacks "session_id" (sidObj == null branch).
        String token = "tk4";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("ivan");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        Authentication userAuth = new TestingAuthenticationToken("ivan", "n/a");
        ((TestingAuthenticationToken) userAuth).setDetails(Map.of("other", "value"));
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("ivan"), eq(authorization), isNull()))
                .thenReturn(result(1, false));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token))
                .andExpect(status().isOk());
    }

    @Test
    void revokeSession_TokenMapDetailsWithSessionId_ButExplicitSessionKept() throws Exception {
        // sidObj != null but resolvedSessionId already provided -> inner assignment skipped
        // (resolvedSessionId == null false, isBlank() not evaluated further for assignment).
        String token = "tk5";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("jane");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        Authentication userAuth = new TestingAuthenticationToken("jane", "n/a");
        ((TestingAuthenticationToken) userAuth).setDetails(Map.of("session_id", "token-sid"));
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("jane"), eq(authorization), eq("explicit-sid")))
                .thenReturn(result(1, true));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token)
                        .param("sessionId", "explicit-sid"))
                .andExpect(status().isOk());
    }

    @Test
    void revokeSession_BlankSessionIdParam_ResolvesSessionFromTokenDetails() throws Exception {
        // sessionId param is blank (isBlank() true) so the session id is taken from token details.
        String token = "tk6";
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn("ken");
        when(authorization.getRegisteredClientId()).thenReturn(null);
        Authentication userAuth = new TestingAuthenticationToken("ken", "n/a");
        ((TestingAuthenticationToken) userAuth).setDetails(Map.of("session_id", "sid-from-details"));
        when(authorization.getAttribute(Principal.class.getName())).thenReturn(userAuth);

        when(authorizationService.findByToken(eq(token), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(revocationService.revokeUserGlobally(eq("ken"), eq(authorization), eq("sid-from-details")))
                .thenReturn(result(1, true));

        mockMvc.perform(post("/api/admin/revoke-session")
                        .header("X-Admin-Api-Key", API_KEY)
                        .param("token", token)
                        .param("sessionId", "   "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.session_evicted").value(true));
    }
}
