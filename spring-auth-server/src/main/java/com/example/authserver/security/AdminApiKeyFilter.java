package com.example.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Spring Security filter enforcing constant-time X-Admin-Api-Key authentication
 * on all /api/admin/** routes as defense-in-depth behind perimeter proxies.
 */
@Slf4j
public class AdminApiKeyFilter extends OncePerRequestFilter {

    private final String expectedApiKey;

    public AdminApiKeyFilter(String expectedApiKey) {
        this.expectedApiKey = expectedApiKey;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/admin/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String apiKeyHeader = request.getHeader("X-Admin-Api-Key");
        byte[] expectedBytes = (expectedApiKey != null ? expectedApiKey : "").getBytes(StandardCharsets.UTF_8);
        byte[] providedBytes = apiKeyHeader != null ? apiKeyHeader.getBytes(StandardCharsets.UTF_8) : new byte[0];

        if (apiKeyHeader == null || !MessageDigest.isEqual(expectedBytes, providedBytes)) {
            log.warn("Blocked unauthorized admin request to {} from remote address {}: invalid or missing X-Admin-Api-Key",
                    request.getRequestURI(), request.getRemoteAddr());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid or missing administrative API key\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
