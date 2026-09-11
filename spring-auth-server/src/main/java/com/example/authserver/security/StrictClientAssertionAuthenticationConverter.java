package com.example.authserver.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Strict RFC 7523 private_key_jwt client authentication converter.
 * Immediately rejects client_secret_basic and client_secret_post.
 */
public class StrictClientAssertionAuthenticationConverter implements AuthenticationConverter {

    private final JwtClientAssertionAuthenticationConverter delegate =
            new JwtClientAssertionAuthenticationConverter();

    @Override
    public Authentication convert(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorization) && authorization.toLowerCase().startsWith("basic ")) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_CLIENT,
                            "Client authentication method 'client_secret_basic' is disabled. Only 'private_key_jwt' (RFC 7523) is permitted.",
                            "https://datatracker.ietf.org/doc/html/rfc7523"
                    )
            );
        }
        if (StringUtils.hasText(request.getParameter("client_secret"))) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_CLIENT,
                            "Client authentication method 'client_secret_post' is disabled. Only 'private_key_jwt' (RFC 7523) is permitted.",
                            "https://datatracker.ietf.org/doc/html/rfc7523"
                    )
            );
        }
        return this.delegate.convert(request);
    }
}
