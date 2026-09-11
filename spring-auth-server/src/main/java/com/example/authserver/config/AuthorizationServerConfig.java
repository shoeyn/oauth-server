package com.example.authserver.config;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.example.authserver.security.ClientAssertionDecoderFactory;
import com.example.authserver.security.ClientPreDeterminedScopeAuthorizationRequestConverter;
import com.example.authserver.security.DPoPNonceFilter;
import com.example.authserver.security.DiscoveryAndJwksCacheFilter;
import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.SharedRedisSessionFilter;
import com.example.authserver.security.StrictClientAssertionAuthenticationConverter;
import com.example.authserver.security.StrictDPoPTokenRequestAuthenticationConverter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Value("${auth.rails.login-url:http://localhost:3000/login}")
    private String railsLoginUrl;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            PostgresRegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            StringRedisTemplate redisTemplate,
            OidcBackChannelLogoutService oidcBackChannelLogoutService,
            JwtEncoder jwtEncoder) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, (authorizationServer) ->
                authorizationServer
                    .pushedAuthorizationRequestEndpoint(Customizer.withDefaults()) // Native RFC 9126 PAR support
                    .tokenIntrospectionEndpoint(Customizer.withDefaults()) // RFC 7662 Token Introspection
                    .tokenRevocationEndpoint(Customizer.withDefaults()) // RFC 7009 Token Revocation
                    // Enforce RFC 9449 Section 5: Require DPoP proof header on token exchange to sender-constrain tokens
                    .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint.accessTokenRequestConverter(new StrictDPoPTokenRequestAuthenticationConverter())
                    )
                    // Bind pre-determined authorized scopes strictly from registered client configuration
                    .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestConverter(new ClientPreDeterminedScopeAuthorizationRequestConverter(registeredClientRepository, authorizationService))
                        // RFC 9221: JWT-Secured Authorization Response Mode (JARM)
                        // Cryptographically signs the authorization response (code, iss, state) using AWS KMS RS256
                        .authorizationResponseHandler(new JarmAuthorizationResponseHandler(jwtEncoder, issuerUrl))
                        // RFC 9221 JARM: Cryptographically signs error responses (error, error_description, iss, state) using AWS KMS RS256
                        .errorResponseHandler(new JarmErrorResponseHandler(jwtEncoder, issuerUrl, registeredClientRepository, authorizationService))
                    )
                    .oidc(oidc -> oidc
                        .userInfoEndpoint(userInfo -> userInfo
                            .userInfoMapper(createOidcUserInfoMapper())
                            .errorResponseHandler((request, response, exception) -> {
                                log.error("UserInfo authentication failure: ", exception);
                                response.setStatus(401);
                                response.setContentType("application/json");
                                response.getWriter().write("{\"error\":\"invalid_token\",\"details\":\"" + exception.getMessage() + "\"}");
                            })
                        )
                        // OIDC RP-Initiated Logout: Invalidate local security context and evict shared SSO session
                        .logoutEndpoint(logoutEndpoint -> logoutEndpoint
                            .errorResponseHandler((request, response, exception) -> {
                                log.warn("OIDC Logout validation failure: {}", exception.getMessage());
                                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                                response.setContentType("application/json");
                                response.getWriter().write("{\"error\":\"invalid_request\",\"error_description\":\"" + exception.getMessage().replace("\"", "'") + "\"}");
                            })
                            .logoutResponseHandler((request, response, authentication) -> {
                                String sessionId = null;
                                if (request.getCookies() != null) {
                                    for (Cookie c : request.getCookies()) {
                                        if ("SHARED_SESSION_ID".equals(c.getName())) {
                                            sessionId = c.getValue();
                                            break;
                                        }
                                    }
                                }
                                if (sessionId != null && !sessionId.isBlank()) {
                                    redisTemplate.delete("session:" + sessionId);
                                    log.info("Evicted SHARED_SESSION_ID from Redis on OIDC logout: {}", sessionId);
                                }
                                Cookie clearedCookie = new Cookie("SHARED_SESSION_ID", "");
                                clearedCookie.setPath("/");
                                clearedCookie.setMaxAge(0);
                                clearedCookie.setHttpOnly(true);
                                response.addCookie(clearedCookie);

                                // OpenID Connect Back-Channel Logout 1.0:
                                // Asynchronously dispatch signed logout_token to registered client back-channel endpoint
                                String logoutClientId = null;
                                if (authentication instanceof OidcLogoutAuthenticationToken logoutToken) {
                                    logoutClientId = logoutToken.getClientId();
                                }
                                if (logoutClientId != null && !logoutClientId.isBlank()) {
                                    oidcBackChannelLogoutService.dispatchLogout(
                                            null, logoutClientId,
                                            authentication != null ? authentication.getName() : null,
                                            sessionId
                                    );
                                }

                                // Delegate to standard OIDC logout success handler for redirect to post_logout_redirect_uri
                                OidcLogoutAuthenticationSuccessHandler defaultHandler =
                                        new OidcLogoutAuthenticationSuccessHandler();
                                defaultHandler.onAuthenticationSuccess(request, response, authentication);
                            })
                        )
                    )
                    // Enforce RFC 7523 private_key_jwt client authentication exclusively.
                    // Shared-secret mechanisms (client_secret_basic, client_secret_post) are rejected.
                    .clientAuthentication(clientAuthentication -> {
                        clientAuthentication.authenticationConverters(converters -> {
                            converters.clear();
                            converters.add(new StrictClientAssertionAuthenticationConverter());
                        });
                        clientAuthentication.authenticationProviders(
                            configureClientAssertionAuthentication(registeredClientRepository, redisTemplate)
                        );
                    })
            )
            .oauth2ResourceServer(resourceServer -> resourceServer
                // Spring Security 7 natively auto-configures BearerTokenAuthenticationFilter (for Bearer)
                // and DPoPAuthenticationConfigurer (for DPoP proof validation and cnf sender constraint)
                .jwt(Customizer.withDefaults())
            )
            .cors(Customizer.withDefaults())
            .headers(headers -> headers
                .contentTypeOptions(Customizer.withDefaults())
                .frameOptions(frame -> frame.deny())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
            )
            .authorizeHttpRequests((authorize) ->
                authorize.anyRequest().authenticated()
            )
            // Route unauthenticated requests to the external Rails IdP with trusted issuer URL
            .exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new ExternalLoginAuthenticationEntryPoint(railsLoginUrl, issuerUrl))
            )
            // HTTP conditional caching filter (ETag/304) for high-frequency discovery and JWKS endpoints
            .addFilterBefore(
                new DiscoveryAndJwksCacheFilter(),
                SecurityContextHolderFilter.class
            )
            // RFC 9449 Section 8: Server-Provided DPoP-Nonce replay protection filter
            .addFilterAfter(
                new DPoPNonceFilter(redisTemplate),
                DiscoveryAndJwksCacheFilter.class
            )
            .addFilterAfter(
                new SharedRedisSessionFilter(redisTemplate),
                LogoutFilter.class
            );

        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> configureClientAssertionAuthentication(
            PostgresRegisteredClientRepository registeredClientRepository,
            StringRedisTemplate redisTemplate) {
        return (authenticationProviders) -> {
            // Permit only asymmetric private_key_jwt client authentication
            authenticationProviders.removeIf(provider -> !(provider instanceof JwtClientAssertionAuthenticationProvider));

            for (AuthenticationProvider provider : authenticationProviders) {
                if (provider instanceof JwtClientAssertionAuthenticationProvider jwtClientAssertionProvider) {
                    jwtClientAssertionProvider.setJwtDecoderFactory(
                            new ClientAssertionDecoderFactory(registeredClientRepository, redisTemplate, issuerUrl)
                    );
                }
            }
        };
    }

    // Architecture & Security: Pre-determined client scopes assigned strictly from registered client.
    // When clients omit 'scope' (as mandated by server-determined scope policy), this wrapper ensures
    // the registered client's authorized scopes are automatically attached to the authorization and access token.
    // Durability: Backed by PostgreSQL JdbcOAuth2AuthorizationService for zero-loss horizontal scaling.
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new ScopePropagatingOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUrl)
                // If PAR (RFC 9126) is enforced server-wide across all clients and you want to publish
                // this requirement in /.well-known/openid-configuration and /.well-known/oauth-authorization-server,
                // you can enable the following setting:
                // .requirePushedAuthorizationRequests(true)
                .build();
    }

    private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> createOidcUserInfoMapper() {
        return (context) -> {
            OAuth2Authorization authorization = context.getAuthorization();
            OAuth2Authorization.Token<OidcIdToken> idTokenHolder = authorization.getToken(OidcIdToken.class);
            OidcIdToken idToken = idTokenHolder != null ? idTokenHolder.getToken() : null;
            OAuth2AccessToken accessToken = context.getAccessToken();

            Map<String, Object> claims = new LinkedHashMap<>();
            if (idToken != null) {
                claims.put("sub", idToken.getSubject());
                if (accessToken.getScopes().contains(OidcScopes.PROFILE)) {
                    if (idToken.hasClaim("name")) {
                        claims.put("name", idToken.getClaim("name"));
                    }
                    if (idToken.hasClaim("preferred_username")) {
                        claims.put("preferred_username", idToken.getClaim("preferred_username"));
                    }
                }
                if (accessToken.getScopes().contains(OidcScopes.EMAIL)) {
                    if (idToken.hasClaim("email")) {
                        claims.put("email", idToken.getClaim("email"));
                    }
                }
            } else {
                claims.put("sub", authorization.getPrincipalName());
            }

            // Security Demonstration: Special claim ONLY accessible from the /userinfo call
            // locked behind the auto-assigned "demo.secret_access" scope.
            // Neither the ID token nor Access token contains this privileged claim!
            if (accessToken.getScopes().contains("demo.secret_access")) {
                claims.put("secret_clearance", "CONFIDENTIAL-ACCESS-LEVEL-4");
                claims.put("special_scope_grant", "auto_assigned:demo.secret_access");
                claims.put("vault_permission", "READ_RESTRICTED_RESOURCES");
            }

            return new OidcUserInfo(claims);
        };
    }
}
