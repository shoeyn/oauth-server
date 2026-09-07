package com.example.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
public class SharedRedisSessionFilter extends OncePerRequestFilter {

    public static final String COOKIE_NAME = "SHARED_SESSION_ID";
    public static final String REDIS_PREFIX = "session:";

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final SecurityContextRepository securityContextRepository;

    public SharedRedisSessionFilter(StringRedisTemplate redisTemplate) {
        this(redisTemplate, JsonMapper.shared());
    }

    public SharedRedisSessionFilter(StringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper != null ? objectMapper : JsonMapper.shared();
        this.securityContextRepository = new HttpSessionSecurityContextRepository();
    }

    /**
     * Skips shared Redis session lookup for non-interactive machine-to-machine,
     * token exchange, JWKS, and discovery endpoints.
     * Only interactive user endpoints (such as /oauth2/authorize) require user session evaluation.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/oauth2/token") ||
               path.startsWith("/oauth2/par") ||
               path.startsWith("/oauth2/jwks") ||
               path.startsWith("/oauth2/introspect") ||
               path.startsWith("/oauth2/revoke") ||
               path.startsWith("/.well-known/") ||
               path.startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        boolean needsAuth = currentAuth == null || !currentAuth.isAuthenticated() || currentAuth instanceof AnonymousAuthenticationToken;

        if (needsAuth) {
            String sessionId = extractSessionId(request);
            UUID sessionUuid = parseUuid(sessionId);

            // Security Improvement: Validate session ID format using native Java UUID parser before issuing Redis lookup
            if (sessionUuid != null) {
                String redisKey = REDIS_PREFIX + sessionUuid;
                String sessionJson = redisTemplate.opsForValue().get(redisKey);

                if (sessionJson != null && !sessionJson.isBlank()) {
                    try {
                        AuthenticatedUser user = objectMapper.readValue(sessionJson, AuthenticatedUser.class);
                        List<GrantedAuthority> authorities = user.roles().stream()
                                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());

                        // Spring Security 7 multifactor / auth_time tracking for OIDC id_token
                        authorities.add(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY));

                        // Store user details as standard Map to guarantee safe Jackson serialization in JdbcOAuth2AuthorizationService
                        Map<String, Object> userDetails = new java.util.HashMap<>();
                        userDetails.put("username", user.username());
                        if (user.email() != null) userDetails.put("email", user.email());
                        if (user.name() != null) userDetails.put("name", user.name());
                        if (user.roles() != null) userDetails.put("roles", user.roles());
                        if (user.authenticatedAt() != null) userDetails.put("authenticated_at", user.authenticatedAt());

                        UsernamePasswordAuthenticationToken auth =
                                new UsernamePasswordAuthenticationToken(user.username(), null, authorities);
                        auth.setDetails(userDetails);

                        SecurityContext context = SecurityContextHolder.createEmptyContext();
                        context.setAuthentication(auth);
                        SecurityContextHolder.setContext(context);
                        securityContextRepository.saveContext(context, request, response);

                        log.info("Established SecurityContext from shared Redis session for user: {}", user.username());
                    } catch (Exception e) {
                        log.error("Failed to parse user JSON from Redis key {}: {}", redisKey, e.getMessage());
                    }
                } else {
                    log.debug("No session found in Redis for key {}", redisKey);
                }
            } else if (sessionId != null) {
                // Security Improvement: Log rejected malformed session identifiers
                log.warn("Rejected malformed SHARED_SESSION_ID cookie format: {}", sessionId);
            }
        }

        filterChain.doFilter(request, response);
    }

    // Security Improvement: Session identifier is ONLY extracted from HttpOnly cookies.
    // Query parameter session ID extraction has been explicitly eliminated to prevent CWE-598
    // (Stops session IDs from leaking into access logs, web server history, proxies, and HTTP Referer headers).
    private String extractSessionId(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // Security Improvement: Use native java.util.UUID parser to validate session ID format before issuing Redis queries
    private UUID parseUuid(String value) {
        if (value == null || value.length() != 36) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
