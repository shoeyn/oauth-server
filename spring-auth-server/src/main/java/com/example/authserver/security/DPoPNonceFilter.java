package com.example.authserver.security;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enforces RFC 9449 Section 8 Server-Provided Nonces.
 * Protects DPoP proofs against replay attacks within the clock-skew window.
 *
 * Flow:
 * 1. For requests to /oauth2/token, if client authentication is valid (e.g. client_assertion present),
 *    extracts the 'nonce' claim from the DPoP proof.
 * 2. Checks if the nonce exists in Redis (key: "dpop_nonce:" + nonce).
 * 3. If missing, invalid, or expired:
 *    - Generates a fresh server nonce and stores it in Redis with a 60-second TTL.
 *    - Sets the HTTP response header "DPoP-Nonce: <new-nonce>".
 *    - Responds with HTTP 400 Bad Request and error "use_dpop_nonce" per RFC 9449 Section 8.
 * 4. If valid, consumes (deletes) the single-use nonce from Redis and permits the request to continue.
 */
@Slf4j
@RequiredArgsConstructor
public class DPoPNonceFilter extends OncePerRequestFilter {

    private final StringRedisTemplate redisTemplate;

    private static final String NONCE_PREFIX = "dpop_nonce:";
    private static final Duration NONCE_TTL = Duration.ofSeconds(60);

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.equals("/oauth2/token");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // If client attempted basic auth or client_secret_post, let downstream filters reject with invalid_client
        String authHeader = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authHeader) && authHeader.toLowerCase().startsWith("basic ")) {
            filterChain.doFilter(request, response);
            return;
        }
        if (StringUtils.hasText(request.getParameter("client_secret"))) {
            filterChain.doFilter(request, response);
            return;
        }

        String dpop = request.getHeader("DPoP");
        if (!StringUtils.hasText(dpop)) {
            filterChain.doFilter(request, response);
            return;
        }

        String presentedNonce = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(dpop);
            presentedNonce = signedJWT.getJWTClaimsSet().getStringClaim("nonce");
        } catch (Exception e) {
            log.debug("Failed to parse DPoP proof JWT to inspect nonce: {}", e.getMessage());
        }

        boolean validNonce = false;
        if (StringUtils.hasText(presentedNonce)) {
            String redisKey = NONCE_PREFIX + presentedNonce;
            Boolean deleted = redisTemplate.delete(redisKey);
            validNonce = Boolean.TRUE.equals(deleted);
            log.debug("DPoP nonce check: nonce={}, valid={}", presentedNonce, validNonce);
        }

        if (!validNonce) {
            // Generate a fresh server-provided nonce with 60-second TTL
            String newNonce = UUID.randomUUID().toString();
            redisTemplate.opsForValue().set(NONCE_PREFIX + newNonce, "1", NONCE_TTL);

            log.info("RFC 9449 DPoP-Nonce challenge issued: newNonce={}", newNonce);
            response.setHeader("DPoP-Nonce", newNonce);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"use_dpop_nonce\",\"error_description\":\"Authorization server requires a valid DPoP-Nonce header\"}");
            return;
        }

        // On successful validation, supply a fresh nonce in the response header for future pipelined requests
        String nextNonce = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(NONCE_PREFIX + nextNonce, "1", NONCE_TTL);
        response.setHeader("DPoP-Nonce", nextNonce);

        filterChain.doFilter(request, response);
    }
}
