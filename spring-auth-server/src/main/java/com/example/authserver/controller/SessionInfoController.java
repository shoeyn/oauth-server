package com.example.authserver.controller;

import com.example.authserver.api.SessionInfoApi;
import com.example.authserver.model.RevocationResponse;
import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.UserSessionRevocationService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Controller providing user session information and administrative revocation.
 *
 * <p>Implements contract-first OpenAPI interface {@link SessionInfoApi}.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class SessionInfoController implements SessionInfoApi {

  private final OAuth2AuthorizationService authorizationService;
  private final UserSessionRevocationService revocationService;
  private final OidcBackChannelLogoutService oidcBackChannelLogoutService;
  private final RegisteredClientRepository registeredClientRepository;

  @Value("${auth.admin.api-key:secret-admin-key}")
  private String adminApiKey;

  private Principal resolveCurrentPrincipal() {
    ServletRequestAttributes attrs =
        (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
    if (attrs != null
        && attrs.getRequest() != null
        && attrs.getRequest().getUserPrincipal() != null) {
      return attrs.getRequest().getUserPrincipal();
    }
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
      return auth;
    }
    return null;
  }

  @Override
  public ResponseEntity<Map<String, Object>> getMe() {
    Principal principal = resolveCurrentPrincipal();
    if (principal instanceof Authentication auth) {
      return ResponseEntity.ok(
          Map.of(
              "username", auth.getName(),
              "authorities", auth.getAuthorities(),
              "details", auth.getDetails() != null ? auth.getDetails() : Map.of()));
    }
    return ResponseEntity.ok(
        Map.of("principal", principal != null ? principal.getName() : "anonymous"));
  }

  /**
   * Administrative session revocation endpoint. Revokes active authorization tokens on the
   * authorization server, evicts the shared Redis SSO session, and dispatches an OIDC back-channel
   * logout notification to client applications.
   */
  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<RevocationResponse> revokeSession(
      String token, String sessionId, String username, String xAdminApiKey) {

    // Validate administrative API key using constant-time byte comparison to mitigate timing
    // attacks
    byte[] expectedKeyBytes = adminApiKey.getBytes(StandardCharsets.UTF_8);
    byte[] providedKeyBytes =
        xAdminApiKey != null ? xAdminApiKey.getBytes(StandardCharsets.UTF_8) : new byte[0];
    if (xAdminApiKey == null || !MessageDigest.isEqual(expectedKeyBytes, providedKeyBytes)) {
      log.warn(
          "Blocked unauthorized admin session revocation attempt: missing or invalid X-Admin-Api-Key");
      return (ResponseEntity<RevocationResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                  .body(
                      Map.of(
                          "error",
                          "unauthorized",
                          "message",
                          "Invalid or missing administrative API key"));
    }

    log.warn(
        "GLOBAL USER SIGN-OUT / FRAUD REVOCATION TRIGGERED: token={}, sessionId={}, username={}",
        token != null ? "[PROTECTED]" : "null",
        sessionId,
        username);

    boolean tokenRevoked = false;
    String resolvedSessionId = sessionId;
    String resolvedUsername = username;
    String resolvedClientId = null;
    OAuth2Authorization singleAuthorization = null;

    if (token != null && !token.isBlank()) {
      singleAuthorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
      if (singleAuthorization == null) {
        singleAuthorization =
            authorizationService.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
      }
      if (singleAuthorization != null) {
        tokenRevoked = true;
        if (resolvedUsername == null || resolvedUsername.isBlank()) {
          resolvedUsername = singleAuthorization.getPrincipalName();
        }
        if (singleAuthorization.getRegisteredClientId() != null) {
          RegisteredClient rc =
              registeredClientRepository.findById(singleAuthorization.getRegisteredClientId());
          if (rc != null) {
            resolvedClientId = rc.getClientId();
          }
        }

        Authentication userAuth = singleAuthorization.getAttribute(Principal.class.getName());
        if (userAuth != null && userAuth.getDetails() instanceof Map<?, ?> details) {
          Object sidObj = details.get("session_id");
          if (sidObj != null && (resolvedSessionId == null || resolvedSessionId.isBlank())) {
            resolvedSessionId = sidObj.toString();
          }
        }
      }
    }

    // Delegate persistence purge and Redis eviction to UserSessionRevocationService
    UserSessionRevocationService.RevocationResult result =
        revocationService.revokeUserGlobally(
            resolvedUsername, singleAuthorization, resolvedSessionId);

    // Dispatch OpenID Connect Back-Channel Logout 1.0 notification to connected clients
    if (resolvedClientId != null && !resolvedClientId.isBlank()) {
      oidcBackChannelLogoutService.dispatchLogout(
          null, resolvedClientId, resolvedUsername, resolvedSessionId);
    } else {
      log.warn(
          "Skipping back-channel logout dispatch: could not resolve clientId from token/session"
              + " (token={}, username={})",
          token != null ? "[PROTECTED]" : "null",
          resolvedUsername);
    }

    return ResponseEntity.ok(
        new RevocationResponse()
            .status("REVOKED")
            .username(resolvedUsername != null ? resolvedUsername : "unknown")
            .authorizationsPurged(result.purgedAuthorizations())
            .tokenRevoked(tokenRevoked)
            .sessionEvicted(result.sessionEvicted())
            .message(
                "User force signed out everywhere by Authorization Server due to security/fraud"
                    + " policy"));
  }
}
