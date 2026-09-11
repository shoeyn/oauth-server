package com.example.authserver.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * RFC 9221 JARM authorization response handler.
 *
 * <p>On successful authorization code issuance, wraps the {@code code}, issuer, and {@code state}
 * in a signed JWT (the {@code response} parameter) and redirects to the registered redirect_uri.
 * Prevents response parameter tampering, code injection, and replay via cryptographic binding.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class JarmAuthorizationResponseHandler implements AuthenticationSuccessHandler {

    private final JwtEncoder jwtEncoder;
    private final String issuerUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unexpected authentication type");
            return;
        }

        String redirectUri = token.getRedirectUri();
        String clientId   = token.getClientId();

        if (!StringUtils.hasText(clientId)) {
            log.warn("JARM: Missing client_id on successful authorization");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing client_id");
            return;
        }

        Instant now = Instant.now();
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(issuerUrl)
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(120))
                .claim("code", token.getAuthorizationCode().getTokenValue());

        if (StringUtils.hasText(token.getState())) {
            claimsBuilder.claim("state", token.getState());
        }

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        Jwt jarmJwt = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()));

        String location = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("response", jarmJwt.getTokenValue())
                .build(true)
                .toUriString();

        log.info("RFC 9221 JARM: Signed authorization response issued to client '{}' at '{}'", clientId, redirectUri);
        new DefaultRedirectStrategy().sendRedirect(request, response, location);
    }
}
