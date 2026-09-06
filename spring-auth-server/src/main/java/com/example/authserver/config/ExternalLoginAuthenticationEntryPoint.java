package com.example.authserver.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

@Slf4j
public class ExternalLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String loginUrl;
    private final String issuerUrl;

    public ExternalLoginAuthenticationEntryPoint(String loginUrl, String issuerUrl) {
        this.loginUrl = loginUrl;
        this.issuerUrl = issuerUrl;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        // Security Improvement: Construct return_to using the configured, trusted issuerUrl
        // rather than blindly trusting request.getRequestURL() to prevent Host Header Poisoning attacks
        // (where an attacker crafts a malicious Host or X-Forwarded-Host header to poison the redirect destination).
        String requestPath = request.getRequestURI();
        StringBuilder returnTo = new StringBuilder();

        if (issuerUrl != null && !issuerUrl.isBlank()) {
            returnTo.append(issuerUrl.replaceAll("/+$", "")).append(requestPath);
        } else {
            returnTo.append(request.getRequestURL().toString());
        }

        if (request.getQueryString() != null && !request.getQueryString().isBlank()) {
            returnTo.append("?").append(request.getQueryString());
        }

        String encodedReturnTo = URLEncoder.encode(returnTo.toString(), StandardCharsets.UTF_8);
        String redirectUrl = loginUrl + (loginUrl.contains("?") ? "&" : "?") + "return_to=" + encodedReturnTo;

        log.debug("Redirecting unauthenticated user to external Rails login: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }
}
