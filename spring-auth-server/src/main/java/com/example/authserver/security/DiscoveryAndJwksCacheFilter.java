package com.example.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Performance Improvement: In-Memory Response Caching & ETag filter for Well-Known & JWKS endpoints.
 * Avoids JSON re-serialization, cryptographic key extraction, and security filter overhead
 * for high-throughput public discovery endpoints (.well-known/openid-configuration,
 * .well-known/oauth-authorization-server, /oauth2/jwks).
 * Supports HTTP 304 Not Modified validation via ETags.
 */
public class DiscoveryAndJwksCacheFilter extends OncePerRequestFilter {

    private static final Map<String, CachedEntry> CACHE = new ConcurrentHashMap<>();

    private record CachedEntry(byte[] body, String contentType, String etag, long expiresAt) {}

    public static void clearCache() {
        CACHE.clear();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        return !(path.equals("/.well-known/openid-configuration") ||
                 path.equals("/.well-known/oauth-authorization-server") ||
                 path.equals("/oauth2/jwks"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        long now = System.currentTimeMillis();
        CachedEntry cached = CACHE.get(path);

        if (cached != null && cached.expiresAt() > now) {
            String ifNoneMatch = request.getHeader("If-None-Match");
            if (ifNoneMatch != null && ifNoneMatch.equals(cached.etag())) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                applyCacheHeaders(response, cached.etag());
                return;
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(cached.contentType());
            applyCacheHeaders(response, cached.etag());
            response.setContentLength(cached.body().length);
            response.getOutputStream().write(cached.body());
            response.flushBuffer();
            return;
        }

        // Intercept response
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, responseWrapper);

        if (responseWrapper.getStatus() == HttpServletResponse.SC_OK) {
            byte[] content = responseWrapper.getContentAsByteArray();
            if (content.length > 0) {
                String etag = computeEtag(content);
                String contentType = responseWrapper.getContentType();
                if (contentType == null) {
                    contentType = "application/json;charset=UTF-8";
                }

                // Cache in memory for 1 hour
                CACHE.put(path, new CachedEntry(content, contentType, etag, now + 3600_000L));
                applyCacheHeaders(responseWrapper, etag);
            }
        }
        responseWrapper.copyBodyToResponse();
    }

    private void applyCacheHeaders(HttpServletResponse response, String etag) {
        response.setHeader("ETag", etag);
        response.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
        response.setDateHeader("Expires", System.currentTimeMillis() + 3600_000L);
    }

    private String computeEtag(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return "\"" + HexFormat.of().formatHex(digest).substring(0, 32) + "\"";
        } catch (Exception e) {
            return "\"" + Integer.toHexString(java.util.Arrays.hashCode(data)) + "\"";
        }
    }
}
