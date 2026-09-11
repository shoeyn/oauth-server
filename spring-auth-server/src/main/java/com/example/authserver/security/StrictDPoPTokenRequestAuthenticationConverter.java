package com.example.authserver.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Enforces RFC 9449 Demonstrating Proof-of-Possession (DPoP) on token endpoint requests.
 * Rejects token grant requests that omit the DPoP HTTP proof header with invalid_dpop_proof.
 */
@Slf4j
public class StrictDPoPTokenRequestAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        String dpop = request.getHeader("DPoP");
        log.info("Checking DPoP requirement on token request: grantType={}, hasDPoP={}",
                grantType, StringUtils.hasText(dpop));

        if (StringUtils.hasText(grantType) && !StringUtils.hasText(dpop)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            "invalid_dpop_proof",
                            "DPoP proof header is strictly required on token endpoint requests (RFC 9449)",
                            "https://datatracker.ietf.org/doc/html/rfc9449#section-5"
                    )
            );
        }
        return null;
    }
}
