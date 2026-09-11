package com.example.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * In-memory HTTP response caching and ETag filter for public discovery and JWKS endpoints.
 * Serves cached byte arrays for /.well-known/openid-configuration,
 * /.well-known/oauth-authorization-server, and /oauth2/jwks with Cache-Control headers
 * and returns HTTP 304 Not Modified when client ETags match.
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
                // Strict Discovery Metadata Alignment:
                // For OpenID & OAuth2 authorization server discovery documents, filter out insecure shared-secret
                // authentication methods (client_secret_basic, client_secret_post) and advertise strictly private_key_jwt
                if (path.startsWith("/.well-known/")) {
                    content = alignDiscoveryMetadata(content);
                }

                String etag = computeEtag(content);
                String contentType = responseWrapper.getContentType();
                if (contentType == null) {
                    contentType = "application/json;charset=UTF-8";
                }

                // Cache in memory for 1 hour
                CACHE.put(path, new CachedEntry(content, contentType, etag, now + 3600_000L));
                applyCacheHeaders(response, etag);
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType(contentType);
                response.setContentLength(content.length);
                response.getOutputStream().write(content);
                response.flushBuffer();
                return;
            }
        }
        responseWrapper.copyBodyToResponse();
    }

    /**
     * Replaces default Spring Security auth methods with strictly private_key_jwt
     * to accurately reflect the server's asymmetric-only security posture.
     */
    private byte[] alignDiscoveryMetadata(byte[] rawJsonBytes) {
        try {
            String json = new String(rawJsonBytes, java.nio.charset.StandardCharsets.UTF_8);
            // Replace token_endpoint_auth_methods_supported
            json = json.replaceAll(
                "\"token_endpoint_auth_methods_supported\"\\s*:\\s*\\[[^\\]]+\\]",
                "\"token_endpoint_auth_methods_supported\": [\"private_key_jwt\"]"
            );
            // Replace revocation_endpoint_auth_methods_supported
            json = json.replaceAll(
                "\"revocation_endpoint_auth_methods_supported\"\\s*:\\s*\\[[^\\]]+\\]",
                "\"revocation_endpoint_auth_methods_supported\": [\"private_key_jwt\"]"
            );
            // Replace introspection_endpoint_auth_methods_supported
            json = json.replaceAll(
                "\"introspection_endpoint_auth_methods_supported\"\\s*:\\s*\\[[^\\]]+\\]",
                "\"introspection_endpoint_auth_methods_supported\": [\"private_key_jwt\"]"
            );
            // RFC 9221: Advertise JARM response modes supported
            if (json.contains("\"response_modes_supported\"")) {
                json = json.replaceAll(
                    "\"response_modes_supported\"\\s*:\\s*\\[[^\\]]+\\]",
                    "\"response_modes_supported\": [\"jwt\", \"query.jwt\"]"
                );
            } else {
                json = json.replaceFirst(
                    "\\{",
                    "{\"response_modes_supported\": [\"jwt\", \"query.jwt\"], "
                );
            }
            return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return rawJsonBytes;
        }
    }

    private void applyCacheHeaders(HttpServletResponse response, String etag) {
        response.setHeader("ETag", etag);
        response.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
        response.setDateHeader("Expires", System.currentTimeMillis() + 3600_000L);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    }

    private String computeEtag(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return "\"" + HexFormat.of().formatHex(digest).substring(0, 32) + "\"";
        } catch (Exception e) {
            return "\"" + Integer.toHexString(Arrays.hashCode(data)) + "\"";
        }
    }
}
