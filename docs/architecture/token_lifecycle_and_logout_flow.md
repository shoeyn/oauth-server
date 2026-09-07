# Token Lifecycle, Revocation & OIDC Back-Channel Logout Flow

This document details the token validation, introspection, revocation, and asynchronous backchannel logout sequences supported by the platform.

---

## 1. RFC 7662 Token Introspection & RFC 7009 Token Revocation

```mermaid
sequenceDiagram
    autonumber
    participant Client as Resource Server / Client App
    participant Spring as Spring Auth Server (9000)
    participant Redis as Redis (6379)

    %% Introspection Before Revocation
    Note over Client, Spring: 1. Real-time Token Introspection (RFC 7662)
    Client->>Spring: POST /oauth2/introspect<br/>(token=ACCESS_TOKEN, client_assertion=JWT)
    activate Spring
    Note over Spring: 1. Authenticate client with private_key_jwt<br/>2. Look up authorization in OAuth2AuthorizationService<br/>3. Verify token has not expired or been revoked
    Spring-->>Client: HTTP 200 OK<br/>{"active": true, "sub": "alice_smith", "scope": "openid profile ...", "cnf": {"jkt": "..."}}
    deactivate Spring

    %% Revocation Flow
    Note over Client, Spring: 2. Token Revocation (RFC 7009)
    Client->>Spring: POST /oauth2/revoke<br/>(token=ACCESS_TOKEN, token_type_hint=access_token, client_assertion=JWT)
    activate Spring
    Note over Spring: 1. Authenticate client with private_key_jwt<br/>2. Mark token and associated refresh token as revoked<br/>3. Invalidate authorization state
    Spring-->>Client: HTTP 200 OK
    deactivate Spring

    %% Introspection After Revocation
    Note over Client, Spring: 3. Introspection After Revocation
    Client->>Spring: POST /oauth2/introspect<br/>(token=ACCESS_TOKEN, client_assertion=JWT)
    activate Spring
    Note over Spring: Token found in revoked state
    Spring-->>Client: HTTP 200 OK<br/>{"active": false}
    deactivate Spring
```

---

## 2. OpenID Connect Back-Channel Logout 1.0

```mermaid
sequenceDiagram
    autonumber
    actor Admin as IdP / Admin
    participant Spring as Spring Auth Server (9000)
    participant Client as Demo Client (8080)
    participant RedisClient as Redis Client Store (DB 1)

    Note over Admin, Spring: Admin or IdP triggers user logout
    Admin->>Spring: Admin session termination / revocation request
    activate Spring

    Note over Spring: OidcBackChannelLogoutService:<br/>1. Find registered client backchannel logout URI<br/>2. Build logout_token JWT payload:<br/>   - iss: http://localhost:9000<br/>   - sub: alice_smith<br/>   - aud: demo-client<br/>   - events: {"http://schemas.openid.net/event/backchannel-logout": {}}<br/>   - sid: session identifier<br/>3. Sign logout_token with AS RSA Private Key (RS256)

    Spring->>Client: POST /oidc/backchannel_logout<br/>Body: logout_token=<signed_jwt>
    activate Client

    Note over Client: 1. Verify logout_token signature against Spring JWKS<br/>2. Validate iss, aud, iat, and backchannel-logout event claim<br/>3. Extract sub / sid
    Client->>RedisClient: Evict cached tokens and user session for 'alice_smith'
    RedisClient-->>Client: OK
    Client-->>Spring: HTTP 200 OK (Session evicted)
    deactivate Client

    Spring-->>Admin: HTTP 200 OK (Revocation complete)
    deactivate Spring

    Note over Client: When user next navigates to Demo Client (/profile), session is gone and user is unauthenticated!
```
