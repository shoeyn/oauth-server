package com.example.authserver.config;

import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Scope-propagating wrapper around {@link JdbcOAuth2AuthorizationService}.
 *
 * <p>Enforces the server-determined scope policy: when a client intentionally omits the
 * {@code scope} parameter (as mandated by this server's policy), the registered client's full
 * authorized scope set is automatically injected into the {@link OAuth2Authorization}, its
 * embedded {@link OAuth2AuthorizationRequest}, and any attached {@link OAuth2AccessToken}
 * before persisting to PostgreSQL.</p>
 *
 * <p>This keeps scope enforcement centralised in one place rather than scattered across
 * token customizers and converters.</p>
 */
@Slf4j
public class ScopePropagatingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final JdbcOAuth2AuthorizationService delegate;
    private final RegisteredClientRepository registeredClientRepository;

    public ScopePropagatingOAuth2AuthorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        BasicPolymorphicTypeValidator ptv =
                BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Object.class)
                        .allowIfSubType(Object.class)
                        .build();

        JsonMapper jsonMapper = JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(classLoader))
                .polymorphicTypeValidator(ptv)
                .build();

        this.delegate = buildDelegate(jdbcTemplate, registeredClientRepository, jsonMapper);
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(propagateScopes(authorization));
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

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private OAuth2Authorization propagateScopes(OAuth2Authorization authorization) {
        if (authorization == null || authorization.getRegisteredClientId() == null) {
            return authorization;
        }
        RegisteredClient client = registeredClientRepository.findById(authorization.getRegisteredClientId());
        if (client == null || client.getScopes() == null || client.getScopes().isEmpty()) {
            return authorization;
        }

        Set<String> clientScopes = client.getScopes();
        boolean needsUpdate = false;
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

        if (authorization.getAuthorizedScopes() == null || !authorization.getAuthorizedScopes().containsAll(clientScopes)) {
            builder.authorizedScopes(clientScopes);
            needsUpdate = true;
        }

        OAuth2AuthorizationRequest authReq = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (authReq != null && (authReq.getScopes() == null || !authReq.getScopes().containsAll(clientScopes))) {
            builder.attribute(OAuth2AuthorizationRequest.class.getName(),
                    OAuth2AuthorizationRequest.from(authReq).scopes(clientScopes).build());
            needsUpdate = true;
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenHolder = authorization.getAccessToken();
        if (accessTokenHolder != null) {
            OAuth2AccessToken token = accessTokenHolder.getToken();
            if (token.getScopes() == null || !token.getScopes().containsAll(clientScopes)) {
                builder.token(
                        new OAuth2AccessToken(token.getTokenType(), token.getTokenValue(),
                                token.getIssuedAt(), token.getExpiresAt(), clientScopes),
                        metadata -> metadata.putAll(accessTokenHolder.getMetadata()));
                needsUpdate = true;
            }
        }

        return needsUpdate ? builder.build() : authorization;
    }

    private static JdbcOAuth2AuthorizationService buildDelegate(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository,
            JsonMapper jsonMapper) {
        JdbcOAuth2AuthorizationService svc = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(registeredClientRepository, jsonMapper);
        rowMapper.setLobHandler(new DefaultLobHandler());
        svc.setAuthorizationRowMapper(rowMapper);
        svc.setAuthorizationParametersMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper));
        return svc;
    }
}
