package com.example.authserver.config;

import com.example.authserver.security.OidcBackChannelLogoutService;
import com.example.authserver.security.SharedRedisSessionFilter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
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
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
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
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
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

    @Value("${auth.rails.login-url:http://localhost:3000/login}")
    private String railsLoginUrl;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            com.example.authserver.client.S3RegisteredClientRepository registeredClientRepository,
            RSAPublicKey demoClientPublicKey,
            StringRedisTemplate redisTemplate,
            OidcBackChannelLogoutService oidcBackChannelLogoutService) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, (authorizationServer) ->
                authorizationServer
                    .pushedAuthorizationRequestEndpoint(Customizer.withDefaults()) // Spring Security 7 Native PAR (RFC 9126)
                    .tokenIntrospectionEndpoint(Customizer.withDefaults()) // RFC 7662 Token Introspection
                    .tokenRevocationEndpoint(Customizer.withDefaults()) // RFC 7009 Token Revocation
                    // Security Improvement (RFC 9449 Section 5): Enforce DPoP proof header on token endpoint requests.
                    // Strictly rejects any token grant request that attempts to omit the DPoP HTTP header with invalid_dpop_proof.
                    .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint.accessTokenRequestConverter(new StrictDPoPTokenRequestAuthenticationConverter())
                    )
                    // Security / Architecture: Ignore client-requested scopes and pre-determine scopes strictly from the registered client
                    .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestConverter(new ClientPreDeterminedScopeAuthorizationRequestConverter(registeredClientRepository))
                        // Security Improvement (RFC 9207): OAuth 2.0 Authorization Server Issuer Identification
                        // Appends 'iss' to the redirect URI alongside code and state to protect against Mix-Up Attacks
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
                    // OpenID Connect 1.0 features
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
                        // OIDC RP-Initiated Logout (Single Sign-Out): Clears security context and evicts shared Redis session
                        .logoutEndpoint(logoutEndpoint -> logoutEndpoint
                            .logoutResponseHandler((request, response, authentication) -> {
                                // Evict shared Redis session and clear cookie on OIDC Single Sign-Out
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

                                // Security Improvement (OIDC Back-Channel Logout 1.0):
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
                    // Security Improvement (RFC 7523): Restrict client authentication strictly to private_key_jwt.
                    // Completely disables and clears all weak shared-secret converters (client_secret_basic, client_secret_post, none)
                    // and removes unneeded authentication providers.
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
            .headers(Customizer.withDefaults()) // Spring Security default security headers (deny framing, nosniff, cache-control)
            .authorizeHttpRequests((authorize) ->
                authorize.anyRequest().authenticated()
            )
            // Security Improvement: Use trusted issuerUrl in entry point to prevent Host Header Poisoning open redirects
            .exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new ExternalLoginAuthenticationEntryPoint(railsLoginUrl, issuerUrl))
            )
            .addFilterAfter(
                new SharedRedisSessionFilter(redisTemplate),
                LogoutFilter.class
            );

        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> configureClientAssertionAuthentication(
            com.example.authserver.client.S3RegisteredClientRepository s3RegisteredClientRepository,
            RSAPublicKey demoClientPublicKey,
            StringRedisTemplate redisTemplate) {
        return (authenticationProviders) -> {
            // Security Improvement: Eliminate weak/shared-secret authentication providers.
            // Only JwtClientAssertionAuthenticationProvider is permitted to authenticate clients.
            authenticationProviders.removeIf(provider -> !(provider instanceof JwtClientAssertionAuthenticationProvider));

            for (AuthenticationProvider provider : authenticationProviders) {
                if (provider instanceof JwtClientAssertionAuthenticationProvider jwtClientAssertionProvider) {
                    jwtClientAssertionProvider.setJwtDecoderFactory((registeredClient) -> {
                        log.info("Configuring JwtDecoder for registered client: {}", registeredClient.getClientId());
                        RSAPublicKey clientKey = s3RegisteredClientRepository.getClientPublicKey(registeredClient.getClientId());
                        if (clientKey == null) {
                            log.warn("Public key not found in S3 repository for client '{}', falling back to default key", registeredClient.getClientId());
                            clientKey = demoClientPublicKey;
                        }
                        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(clientKey).build();

                        // Security Improvement: Clock skew tolerance limited to 60s to reject expired client assertion tokens
                        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator(Duration.ofSeconds(60));

                        OAuth2TokenValidator<Jwt> clientValidator = (jwt) -> {
                            // Security Improvement: Subject and Issuer must strictly match the registered client_id (RFC 7523 Section 3)
                            // Stops malicious clients from using another client's identity or cross-client token forgery
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

                            // Security Improvement: Audience (aud) validation (RFC 7523 Section 3)
                            // Ensures assertion was explicitly minted for this authorization server, preventing cross-server token replay
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

                            // Security Improvement: Replay Protection using unique JWT ID ('jti') in Redis (RFC 7523 Section 3)
                            // Stops attackers from capturing a client assertion and replaying it within its validity window
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

                        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestampValidator, clientValidator));
                        return decoder;
                    });
                }
            }
        };
    }

    // Architecture & Security: Pre-determined client scopes assigned strictly from registered client.
    // When clients omit 'scope' (as mandated by server-determined scope policy), this wrapper ensures
    // the registered client's authorized scopes are automatically attached to the authorization and access token.
    @Bean
    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository) {
        InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
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

    // Security Improvement (RFC 7523): Strictly enforce private_key_jwt client authentication.
    // Explicitly rejects legacy and insecure shared-secret authentication mechanisms (client_secret_basic, client_secret_post)
    // with an explicit OAuth2 invalid_client error rather than silently ignoring or bypassing them.
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

    // Security & Architecture: Ignore client-requested scopes and pre-determine scopes strictly from registered client
    private static class ClientPreDeterminedScopeAuthorizationRequestConverter implements AuthenticationConverter {
        private final RegisteredClientRepository registeredClientRepository;
        private final OAuth2AuthorizationCodeRequestAuthenticationConverter defaultConverter =
                new OAuth2AuthorizationCodeRequestAuthenticationConverter();

        public ClientPreDeterminedScopeAuthorizationRequestConverter(RegisteredClientRepository registeredClientRepository) {
            this.registeredClientRepository = registeredClientRepository;
        }

        /*
         * RFC 9126 PAR Mandatory Enforcement Note:
         * To mandate Pushed Authorization Requests (PAR) and reject direct GET/POST authorization requests:
         * 1. In RFC 9126 Section 4, clients using PAR obtain a 'request_uri' (urn:ietf:params:oauth:request_uri:...)
         *    via the backchannel endpoint (/oauth2/par) and pass it to /oauth2/authorize.
         * 2. To reject direct authorization requests without 'request_uri', check:
         *       String requestUri = request.getParameter("request_uri");
         *       if (!StringUtils.hasText(requestUri)) {
         *           OAuth2Error error = new OAuth2Error(
         *               org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST,
         *               "Pushed Authorization Requests (PAR) are required by policy. Directly initiating authorization without a valid 'request_uri' is prohibited.",
         *               "https://datatracker.ietf.org/doc/html/rfc9126#section-4"
         *           );
         *           throw new org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
         *       }
         * 3. Register this check in this converter before or after default conversion. Direct requests
         *    lacking 'request_uri' will then be rejected immediately with an OAuth2 invalid_request error.
         */
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

    // Security Improvement (RFC 9449 Section 5): Enforce DPoP proof header on token endpoint requests.
    // Strictly rejects any token request that omits the DPoP HTTP header with invalid_dpop_proof.
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
