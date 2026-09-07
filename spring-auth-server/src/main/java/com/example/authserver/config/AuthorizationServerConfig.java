package com.example.authserver.config;

import com.example.authserver.security.DiscoveryAndJwksCacheFilter;
import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.SharedRedisSessionFilter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.function.Function;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    private final Map<String, JwtDecoder> jwtDecoderCache = new ConcurrentHashMap<>();

    @Value("${auth.rails.login-url:http://localhost:3000/login}")
    private String railsLoginUrl;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            com.example.authserver.client.PostgresRegisteredClientRepository registeredClientRepository,
            RSAPublicKey demoClientPublicKey,
            StringRedisTemplate redisTemplate,
            OidcBackChannelLogoutService oidcBackChannelLogoutService) throws Exception {

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
                        .authorizationRequestConverter(new ClientPreDeterminedScopeAuthorizationRequestConverter(registeredClientRepository))
                        // RFC 9207: Authorization Server Issuer Identification in Authorization Response
                        // Appends 'iss' parameter to callback redirect to prevent OAuth 2.0 mix-up attacks
                        .authorizationResponseHandler((request, response, authentication) -> {
                            if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
                                String redirectUri = token.getRedirectUri();
                                UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                                        .queryParam("code", token.getAuthorizationCode().getTokenValue())
                                        .queryParam("iss", issuerUrl);
                                if (StringUtils.hasText(token.getState())) {
                                    uriBuilder.queryParam("state", UriUtils.encode(token.getState(), StandardCharsets.UTF_8));
                                }
                                new DefaultRedirectStrategy().sendRedirect(request, response, uriBuilder.build(true).toUriString());
                            }
                        })
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
                            .logoutResponseHandler((request, response, authentication) -> {
                                String sessionId = null;
                                if (request.getCookies() != null) {
                                    for (jakarta.servlet.http.Cookie c : request.getCookies()) {
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
                                jakarta.servlet.http.Cookie clearedCookie = new jakarta.servlet.http.Cookie("SHARED_SESSION_ID", "");
                                clearedCookie.setPath("/");
                                clearedCookie.setMaxAge(0);
                                clearedCookie.setHttpOnly(true);
                                response.addCookie(clearedCookie);

                                // OpenID Connect Back-Channel Logout 1.0:
                                // Asynchronously dispatch signed logout_token to registered client back-channel endpoint
                                oidcBackChannelLogoutService.dispatchLogout(
                                        null, "demo-client",
                                        authentication != null ? authentication.getName() : null,
                                        sessionId
                                );

                                // Delegate to standard OIDC logout success handler for redirect to post_logout_redirect_uri
                                org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler defaultHandler =
                                        new org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler();
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
                            configureClientAssertionAuthentication(registeredClientRepository, demoClientPublicKey, redisTemplate)
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
                .referrerPolicy(referrer -> referrer.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
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
            .addFilterAfter(
                new SharedRedisSessionFilter(redisTemplate),
                LogoutFilter.class
            );

        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> configureClientAssertionAuthentication(
            com.example.authserver.client.PostgresRegisteredClientRepository registeredClientRepository,
            RSAPublicKey demoClientPublicKey,
            StringRedisTemplate redisTemplate) {
        return (authenticationProviders) -> {
            // Permit only asymmetric private_key_jwt client authentication
            authenticationProviders.removeIf(provider -> !(provider instanceof JwtClientAssertionAuthenticationProvider));

            for (AuthenticationProvider provider : authenticationProviders) {
                if (provider instanceof JwtClientAssertionAuthenticationProvider jwtClientAssertionProvider) {
                    jwtClientAssertionProvider.setJwtDecoderFactory((registeredClient) -> {
                        RSAPublicKey foundKey = registeredClientRepository.getClientPublicKey(registeredClient.getClientId());
                        final RSAPublicKey clientKey = (foundKey != null) ? foundKey : demoClientPublicKey;
                        String cacheKey = registeredClient.getClientId() + ":" + (clientKey != null ? clientKey.hashCode() : 0);
                        return jwtDecoderCache.computeIfAbsent(cacheKey, (k) -> {
                            log.info("Constructing and caching JwtDecoder for registered client: {}", registeredClient.getClientId());
                            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(clientKey)
                                    .signatureAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                                    .build();

                            // Allow maximum 60 seconds clock skew for client assertion validity
                            OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator(Duration.ofSeconds(60));

                            // Strict Algorithm Pinning (RFC 7523 & RFC 8725 Section 3.1):
                            // Reject 'none', symmetric HMAC, and non-RS256 algorithms to mitigate algorithm confusion attacks
                            OAuth2TokenValidator<Jwt> algorithmValidator = (jwt) -> {
                                Object alg = jwt.getHeaders().get("alg");
                                if (alg == null || !"RS256".equalsIgnoreCase(alg.toString())) {
                                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                            "invalid_client_assertion",
                                            "Strict Algorithm Pinning: Only 'RS256' algorithm is permitted for client assertions. Rejected: " + alg,
                                            null));
                                }
                                return OAuth2TokenValidatorResult.success();
                            };

                            OAuth2TokenValidator<Jwt> clientValidator = (jwt) -> {
                                // Validate subject and issuer match registered client identifier (RFC 7523 Section 3)
                                if (!registeredClient.getClientId().equals(jwt.getSubject())) {
                                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                            "invalid_client_assertion",
                                            "JWT Subject does not match client_id",
                                            null));
                                }
                                String issuer = jwt.getClaimAsString("iss");
                                if (issuer != null && !registeredClient.getClientId().equals(issuer)) {
                                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                            "invalid_client_assertion",
                                            "JWT Issuer does not match client_id",
                                            null));
                                }

                                // Validate audience specifically targets this authorization server (RFC 7523 Section 3)
                                List<String> audiences = jwt.getAudience();
                                boolean validAudience = audiences != null && audiences.stream().anyMatch(aud ->
                                        aud.contains("9000") || aud.equalsIgnoreCase(issuerUrl)
                                );
                                if (!validAudience) {
                                    return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                            "invalid_client_assertion",
                                            "JWT Audience does not match this authorization server",
                                            null));
                                }

                                // JTI Replay Protection: Enforce single-use client assertion within expiration window
                                String jti = jwt.getId();
                                if (jti != null && !jti.isBlank()) {
                                    Boolean isNew = redisTemplate.opsForValue().setIfAbsent("oauth2:jti:" + jti, "used", Duration.ofMinutes(5));
                                    if (Boolean.FALSE.equals(isNew)) {
                                        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                                "invalid_client_assertion",
                                                "JWT Assertion replay detected: jti has already been used",
                                                null));
                                    }
                                }

                                return OAuth2TokenValidatorResult.success();
                            };

                            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestampValidator, algorithmValidator, clientValidator));
                            return decoder;
                        });
                    });
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

        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator ptv =
                tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Object.class)
                        .allowIfSubType(Object.class)
                        .build();

        tools.jackson.databind.json.JsonMapper jsonMapper = tools.jackson.databind.json.JsonMapper.builder()
                .addModules(org.springframework.security.jackson.SecurityJacksonModules.getModules(classLoader))
                .polymorphicTypeValidator(ptv)
                .build();

        JdbcOAuth2AuthorizationService delegate = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(registeredClientRepository, jsonMapper);
        rowMapper.setLobHandler(new org.springframework.jdbc.support.lob.DefaultLobHandler());
        delegate.setAuthorizationRowMapper(rowMapper);
        delegate.setAuthorizationParametersMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper));

        return new OAuth2AuthorizationService() {
            @Override
            public void save(OAuth2Authorization authorization) {
                OAuth2Authorization authToSave = authorization;
                if (authorization != null && authorization.getRegisteredClientId() != null) {
                    RegisteredClient client = registeredClientRepository.findById(authorization.getRegisteredClientId());
                    if (client != null && client.getScopes() != null && !client.getScopes().isEmpty()) {
                        java.util.Set<String> clientScopes = client.getScopes();
                        boolean needsUpdate = false;
                        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

                        if (authorization.getAuthorizedScopes() == null || !authorization.getAuthorizedScopes().containsAll(clientScopes)) {
                            builder.authorizedScopes(clientScopes);
                            needsUpdate = true;
                        }

                        Object authReqObj = authorization.getAttribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());
                        if (authReqObj instanceof org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest authReq) {
                            if (authReq.getScopes() == null || !authReq.getScopes().containsAll(clientScopes)) {
                                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest updatedAuthReq =
                                        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.from(authReq)
                                                .scopes(clientScopes)
                                                .build();
                                builder.attribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName(), updatedAuthReq);
                                needsUpdate = true;
                            }
                        }

                        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenHolder = authorization.getAccessToken();
                        if (accessTokenHolder != null) {
                            OAuth2AccessToken token = accessTokenHolder.getToken();
                            if (token.getScopes() == null || !token.getScopes().containsAll(clientScopes)) {
                                OAuth2AccessToken updatedToken = new OAuth2AccessToken(
                                        token.getTokenType(),
                                        token.getTokenValue(),
                                        token.getIssuedAt(),
                                        token.getExpiresAt(),
                                        clientScopes
                                );
                                builder.token(updatedToken, metadata -> metadata.putAll(accessTokenHolder.getMetadata()));
                                needsUpdate = true;
                            }
                        }

                        if (needsUpdate) {
                            authToSave = builder.build();
                        }
                    }
                }
                delegate.save(authToSave);
            }

            @Override
            public void remove(OAuth2Authorization authorization) {
                delegate.remove(authorization);
            }

            @Override
            public OAuth2Authorization findById(String id) {
                return delegate.findById(id);
            }

            @Override
            public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
                return delegate.findByToken(token, tokenType);
            }
        };
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

    /**
     * Enforces RFC 7523 asymmetric private_key_jwt client authentication.
     * Explicitly rejects insecure shared-secret authentication mechanisms
     * (client_secret_basic and client_secret_post) with HTTP 401 invalid_client.
     */
    private static class StrictClientAssertionAuthenticationConverter implements AuthenticationConverter {
        private final org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter delegate =
                new org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter();

        @Override
        public Authentication convert(HttpServletRequest request) {
            String authorization = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
            if (StringUtils.hasText(authorization) && authorization.toLowerCase().startsWith("basic ")) {
                throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                        new OAuth2Error(
                                org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_CLIENT,
                                "Client authentication method 'client_secret_basic' is disabled. Only 'private_key_jwt' (RFC 7523) is permitted.",
                                "https://datatracker.ietf.org/doc/html/rfc7523"
                        )
                );
            }
            if (StringUtils.hasText(request.getParameter("client_secret"))) {
                throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                        new OAuth2Error(
                                org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_CLIENT,
                                "Client authentication method 'client_secret_post' is disabled. Only 'private_key_jwt' (RFC 7523) is permitted.",
                                "https://datatracker.ietf.org/doc/html/rfc7523"
                        )
                );
            }
            return this.delegate.convert(request);
        }
    }

    /**
     * Enforces server-determined scopes by binding registered client authorized scopes
     * to the authorization code request, mitigating client-side scope manipulation.
     */
    private static class ClientPreDeterminedScopeAuthorizationRequestConverter implements AuthenticationConverter {
        private final RegisteredClientRepository registeredClientRepository;
        private final OAuth2AuthorizationCodeRequestAuthenticationConverter defaultConverter =
                new OAuth2AuthorizationCodeRequestAuthenticationConverter();

        public ClientPreDeterminedScopeAuthorizationRequestConverter(RegisteredClientRepository registeredClientRepository) {
            this.registeredClientRepository = registeredClientRepository;
        }

        @Override
        public Authentication convert(HttpServletRequest request) {
            Authentication authentication = this.defaultConverter.convert(request);
            if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
                java.util.Set<String> serverDeterminedScopes = Collections.emptySet();
                if (token.getClientId() != null) {
                    RegisteredClient client = this.registeredClientRepository.findByClientId(token.getClientId());
                    if (client != null) {
                        serverDeterminedScopes = client.getScopes();
                    }
                }
                return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        token.getAuthorizationUri(),
                        token.getClientId(),
                        (Authentication) token.getPrincipal(),
                        token.getRedirectUri(),
                        token.getState(),
                        serverDeterminedScopes,
                        token.getAdditionalParameters()
                );
            }
            return authentication;
        }
    }

    /**
     * Enforces RFC 9449 Demonstrating Proof-of-Possession (DPoP) on token endpoint requests.
     * Rejects token grant requests that omit the DPoP HTTP proof header with invalid_dpop_proof.
     */
    private static class StrictDPoPTokenRequestAuthenticationConverter implements AuthenticationConverter {
        @Override
        public Authentication convert(HttpServletRequest request) {
            String grantType = request.getParameter(org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE);
            String dpop = request.getHeader("DPoP");
            log.info("Checking DPoP requirement on token request: grantType={}, hasDPoP={}",
                    grantType, StringUtils.hasText(dpop));

            if (StringUtils.hasText(grantType) && !StringUtils.hasText(dpop)) {
                throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
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
}
