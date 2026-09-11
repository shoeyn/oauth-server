package com.example.authserver.security;

import com.example.authserver.config.ParEndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Enforces server-determined scopes by binding registered client authorized scopes
 * to the authorization code request, mitigating client-side scope manipulation.
 */
@Slf4j
@RequiredArgsConstructor
public class ClientPreDeterminedScopeAuthorizationRequestConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationCodeRequestAuthenticationConverter defaultConverter =
            new OAuth2AuthorizationCodeRequestAuthenticationConverter();

    @Override
    public Authentication convert(HttpServletRequest request) {
        // Intercept IdP authentication errors and forward to JARM errorResponseHandler
        if (StringUtils.hasText(request.getParameter("error"))) {
            String errorCode = request.getParameter("error");
            String errorDesc = request.getParameter("error_description");
            String errorUri = request.getParameter("error_uri");
            String clientId = request.getParameter("client_id");
            String redirectUri = request.getParameter("redirect_uri");
            String state = request.getParameter("state");
            String requestUri = request.getParameter("request_uri");

            if ((!StringUtils.hasText(redirectUri) || !StringUtils.hasText(state)) && StringUtils.hasText(requestUri) && this.authorizationService != null) {
                OAuth2AuthorizationRequest authReq = ParEndpointUtils.resolveAuthRequest(requestUri, this.authorizationService);
                if (authReq != null) {
                    if (!StringUtils.hasText(redirectUri)) {
                        redirectUri = authReq.getRedirectUri();
                    }
                    if (!StringUtils.hasText(state)) {
                        state = authReq.getState();
                    }
                    if (!StringUtils.hasText(clientId)) {
                        clientId = authReq.getClientId();
                    }
                }
            }

            Authentication principal = SecurityContextHolder.getContext().getAuthentication();
            if (principal == null) {
                principal = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
            }
            OAuth2AuthorizationCodeRequestAuthenticationToken token = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    request.getRequestURI(),
                    clientId,
                    principal,
                    redirectUri,
                    state,
                    Collections.emptySet(),
                    Collections.emptyMap()
            );
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(errorCode, errorDesc, errorUri), token
            );
        }

        Authentication authentication = this.defaultConverter.convert(request);
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {

            Set<String> serverDeterminedScopes = Collections.emptySet();
            if (token.getClientId() != null) {
                RegisteredClient client = this.registeredClientRepository.findByClientId(token.getClientId());
                if (client != null) {
                    serverDeterminedScopes = client.getScopes();

                    // Strict RFC 9126 PAR Enforcement Check
                    Boolean requirePar = client.getClientSettings().getSetting("settings.client.require-pushed-authorization-requests");
                    if (Boolean.TRUE.equals(requirePar)) {
                        Object requestUri = token.getAdditionalParameters() != null ?
                                token.getAdditionalParameters().get("request_uri") : null;
                        if (requestUri == null || !StringUtils.hasText(requestUri.toString())) {
                            log.warn("Strict PAR Enforcement: Rejected direct authorization request for client '{}' missing request_uri.",
                                    token.getClientId());
                            throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(
                                    OAuth2ErrorCodes.INVALID_REQUEST,
                                    "Client '" + token.getClientId() + "' strictly requires Pushed Authorization Requests (PAR, RFC 9126). Direct authorization requests without 'request_uri' are rejected.",
                                    "https://datatracker.ietf.org/doc/html/rfc9126"
                            ), token);
                        }
                    }
                }
            }
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    token.getAuthorizationUri(),
                    token.getClientId(),
                    (Authentication) token.getPrincipal(),
                    token.getRedirectUri(),
                    token.getState(),
                    serverDeterminedScopes,
                    token.getAdditionalParameters()
            );
        }
        return authentication;
    }
}
