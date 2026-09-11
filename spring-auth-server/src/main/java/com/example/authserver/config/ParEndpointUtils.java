package com.example.authserver.config;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.StringUtils;

/**
 * Utility helper for resolving PAR (RFC 9126) stored authorization requests.
 */
public final class ParEndpointUtils {

    public static final String PAR_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

    private ParEndpointUtils() {}

    /**
     * Resolves the stored {@link OAuth2AuthorizationRequest} from a PAR {@code request_uri},
     * recovering redirect_uri, state, and client_id when absent from query parameters.
     */
    public static OAuth2AuthorizationRequest resolveAuthRequest(String requestUri, OAuth2AuthorizationService authorizationService) {
        if (!StringUtils.hasText(requestUri) || authorizationService == null) {
            return null;
        }
        String stateToken = requestUri.startsWith(PAR_REQUEST_URI_PREFIX)
                ? requestUri.substring(PAR_REQUEST_URI_PREFIX.length())
                : requestUri;

        OAuth2Authorization auth = authorizationService.findByToken(
                stateToken, new OAuth2TokenType(OAuth2ParameterNames.STATE));
        if (auth == null) {
            return null;
        }
        return auth.getAttribute(OAuth2AuthorizationRequest.class.getName());
    }
}
