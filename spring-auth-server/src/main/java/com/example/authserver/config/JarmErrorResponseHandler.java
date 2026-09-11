package com.example.authserver.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * RFC 9221 JARM authorization error response handler.
 *
 * <p>On authorization endpoint errors, wraps {@code error}, {@code error_description}, {@code iss},
 * and {@code state} in a signed JWT (the {@code response} parameter) and redirects to the registered
 * redirect_uri. Falls back to 400 Bad Request if redirect context cannot be established securely.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class JarmErrorResponseHandler implements AuthenticationFailureHandler {

    private final JwtEncoder jwtEncoder;
    private final String issuerUrl;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        log.warn("OAuth 2.1 Authorization Endpoint Exception: {}", exception.getMessage());

        if (!(exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException authEx)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, exception.getMessage());
            return;
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken token = authEx.getAuthorizationCodeRequestAuthentication();
        OAuth2Error error = authEx.getError();

        String clientId    = token != null && StringUtils.hasText(token.getClientId())   ? token.getClientId()   : request.getParameter("client_id");
        String redirectUri = token != null && StringUtils.hasText(token.getRedirectUri()) ? token.getRedirectUri() : request.getParameter("redirect_uri");
        String state       = token != null && StringUtils.hasText(token.getState())       ? token.getState()      : request.getParameter("state");

        // Resolve missing parameters from the stored PAR request if a request_uri is present
        String requestUri = request.getParameter("request_uri");
        if (StringUtils.hasText(requestUri) && (!StringUtils.hasText(redirectUri) || !StringUtils.hasText(clientId) || !StringUtils.hasText(state))) {
            OAuth2AuthorizationRequest authReq = ParEndpointUtils.resolveAuthRequest(requestUri, authorizationService);
            if (authReq != null) {
                if (!StringUtils.hasText(redirectUri)) redirectUri = authReq.getRedirectUri();
                if (!StringUtils.hasText(state))       state       = authReq.getState();
                if (!StringUtils.hasText(clientId))    clientId    = authReq.getClientId();
            }
        }

        if (!StringUtils.hasText(clientId)) {
            log.warn("JARM error: missing client_id — cannot issue signed error response");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing client_id");
            return;
        }
        if (!StringUtils.hasText(redirectUri)) {
            log.warn("JARM error: missing redirect_uri for client '{}' — cannot redirect", clientId);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing redirect_uri");
            return;
        }

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            log.warn("JARM error: client '{}' not found", clientId);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid client_id");
            return;
        }
        if (!client.getRedirectUris().contains(redirectUri)) {
            log.warn("JARM error: redirect_uri '{}' not registered for client '{}'", redirectUri, clientId);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect_uri: not registered for client");
            return;
        }

        Instant now = Instant.now();
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(issuerUrl)
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(120))
                .claim("iss", issuerUrl)
                .claim("error", error.getErrorCode());

        if (StringUtils.hasText(error.getDescription())) claimsBuilder.claim("error_description", error.getDescription());
        if (StringUtils.hasText(error.getUri()))         claimsBuilder.claim("error_uri",         error.getUri());
        if (StringUtils.hasText(state))                  claimsBuilder.claim("state",              state);

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        Jwt jarmJwt = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()));

        String location = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("response", jarmJwt.getTokenValue())
                .build(true)
                .toUriString();

        log.info("RFC 9221 JARM: Signed error response (error='{}') issued to client '{}' at '{}'",
                error.getErrorCode(), clientId, redirectUri);
        new DefaultRedirectStrategy().sendRedirect(request, response, location);
    }
}
