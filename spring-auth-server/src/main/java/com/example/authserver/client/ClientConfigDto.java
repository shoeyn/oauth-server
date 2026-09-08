package com.example.authserver.client;

import java.util.List;
import java.util.Set;

public record ClientConfigDto(
        String clientId,
        String clientName,
        List<String> clientAuthenticationMethods,
        List<String> authorizationGrantTypes,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> scopes,
        Boolean requireProofKey,
        Boolean requireAuthorizationConsent,
        Boolean requirePushedAuthorizationRequests,
        Long accessTokenTimeToLiveMinutes,
        Long refreshTokenTimeToLiveDays,
        String publicKeyPem
) {}
