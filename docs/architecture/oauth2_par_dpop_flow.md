# OAuth 2.1 Authorization Code Flow with PAR, DPoP & Rails SSO

This document illustrates the complete end-to-end authorization code exchange combining **RFC 9126 (PAR)**, **RFC 7523 (`private_key_jwt`)**, **RFC 9449 (DPoP)**, **RFC 7636 (PKCE)**, **RFC 9207 (Issuer ID)**, and **Server-Determined Authorization Scopes**.

---

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Client as Demo Client (8080)
    participant Spring as Spring Auth Server (9000)
    participant Redis as Redis (6379)
    participant Rails as Rails IdP (3000)

    %% ------------------------------------------------------------------------
    %% Phase 1: PAR Initiation
    %% ------------------------------------------------------------------------
    Note over User, Client: Phase 1: Pushed Authorization Request (RFC 9126)
    User->>Client: Click "Start Secure Login (PAR + DPoP + PKCE)"
    activate Client
    Note over Client: 1. Generate PKCE code_verifier & S256 code_challenge<br/>2. Generate ephemeral DPoP EC key pair<br/>3. Sign private_key_jwt assertion (RS256)<br/>4. Sign DPoP proof for /oauth2/par (ES256)<br/>5. Omit all client scopes (Zero Client Scopes)
    Client->>Spring: POST /oauth2/par<br/>(DPoP Header, private_key_jwt, PKCE, state, nonce)
    activate Spring
    Note over Spring: Validate private_key_jwt:<br/>- Signature matches client public key<br/>- iss == sub == client_id<br/>- aud == /oauth2/par<br/>- jti not in Redis replay cache
    Spring->>Redis: SETNX oauth2:jti:<jti> (TTL: 5m)
    Note over Spring: Validate DPoP proof (htm=POST, htu=/oauth2/par)
    Spring-->>Client: HTTP 201 Created<br/>{"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60}
    deactivate Spring

    Note over Client: Cache flow state in Redis DB 1<br/>(code_verifier, nonce, dpop_key)
    Client-->>User: HTTP 302 Redirect to:<br/>http://localhost:9000/oauth2/authorize?client_id=demo-client&request_uri=urn:...
    deactivate Client

    %% ------------------------------------------------------------------------
    %% Phase 2: Rails SSO Authentication
    %% ------------------------------------------------------------------------
    Note over User, Rails: Phase 2: External IdP Authentication & Shared Session
    User->>Spring: GET /oauth2/authorize?client_id=demo-client&request_uri=urn:...
    activate Spring
    Note over Spring: SharedRedisSessionFilter checks for SHARED_SESSION_ID cookie.<br/>No active session found!
    Spring-->>User: HTTP 302 Redirect to:<br/>http://localhost:3000/login?return_to=http://localhost:9000/oauth2/authorize...
    deactivate Spring

    User->>Rails: GET /login?return_to=...
    activate Rails
    Rails-->>User: Render Login Form (username, password, return_to, CSRF)
    deactivate Rails

    User->>Rails: POST /login (alice_smith / secret123)
    activate Rails
    Note over Rails: 1. Verify credentials (secure_compare)<br/>2. Whitelist return_to host (localhost:9000)<br/>3. Generate UUIDv4 session id<br/>4. Invalidate prior session keys
    Rails->>Redis: SET session:<uuid> (User claims, TTL: 24h)
    Rails-->>User: HTTP 302 Redirect to sanitized return_to<br/>Set-Cookie: SHARED_SESSION_ID=<uuid>, HttpOnly, SameSite=Lax
    deactivate Rails

    %% ------------------------------------------------------------------------
    %% Phase 3: Authorization Code Grant & RFC 9221 JARM Response
    %% ------------------------------------------------------------------------
    Note over User, Spring: Phase 3: Authorization Grant & RFC 9221 JARM Response (AWS KMS RS256)
    User->>Spring: GET /oauth2/authorize?client_id=demo-client&request_uri=urn:...<br/>Cookie: SHARED_SESSION_ID=<uuid>
    activate Spring
    Spring->>Redis: GET session:<uuid>
    Redis-->>Spring: User JSON (username, roles, sub)
    Note over Spring: SharedRedisSessionFilter establishes SecurityContext<br/>Spring validates request_uri & generates single-use auth code<br/>Signs JARM JWT containing code, iss, state, exp via AWS KMS RS256
    Spring-->>User: HTTP 302 Redirect to Demo Client callback:<br/>http://localhost:8080/callback?response=<JARM_JWT>
    deactivate Spring

    %% ------------------------------------------------------------------------
    %% Phase 4: Token Exchange with DPoP Nonce Challenge & Server-Determined Scopes
    %% ------------------------------------------------------------------------
    Note over User, Client: Phase 4: JARM Verification & Sender-Constrained Token Exchange (RFC 9449)
    User->>Client: GET /callback?response=<JARM_JWT>
    activate Client
    Note over Client: 1. Verify JARM JWT signature against Spring Auth Server JWKS (RFC 9221)<br/>2. Validate iss, aud (demo-client), exp, and state<br/>3. Extract authorization code from validated claims<br/>4. Sign private_key_jwt for /oauth2/token<br/>5. Sign initial DPoP proof for /oauth2/token
    Client->>Spring: POST /oauth2/token (Initial DPoP proof without nonce)
    activate Spring
    Note over Spring: DPoPNonceFilter (RFC 9449 §8):<br/>- Checks for active DPoP nonce in Redis<br/>- Generates fresh server nonce (60s TTL)<br/>- Responds with HTTP 400 use_dpop_nonce
    Spring-->>Client: HTTP 400 Bad Request<br/>Header: DPoP-Nonce: <nonce><br/>Body: {"error": "use_dpop_nonce"}
    deactivate Spring

    Note over Client: Auto-Retry with Server Nonce:<br/>Sign fresh DPoP proof embedding 'nonce: <nonce>'
    Client->>Spring: POST /oauth2/token<br/>Header: DPoP: <dpop_proof_with_nonce><br/>Body: grant_type=authorization_code, code=AUTH_CODE,<br/>code_verifier=VERIFIER, client_assertion=JWT
    activate Spring
    Note over Spring: StrictDPoPTokenRequestAuthenticationConverter & TokenCustomizer:<br/>- Validate DPoP-Nonce from Redis & consume (single-use)<br/>- Validate private_key_jwt assertion<br/>- Verify PKCE code_verifier against stored challenge<br/>- Bind Server-Determined Scopes<br/>- Compute DPoP thumbprint (cnf.jkt) & bind into Access Token<br/>- Compute at_hash (access_token) & c_hash (code) into ID Token
    Spring-->>Client: HTTP 200 OK<br/>{ "token_type": "DPoP", "access_token": "JWT", "id_token": "JWT", "expires_in": 900, "scope": "..." }
    deactivate Spring

    Note over Client: Validate ID Token (RFC 7519 & OIDC Core):<br/>1. Verify signature against cached JWKS<br/>2. Verify at_hash against access_token<br/>3. Verify c_hash against auth code<br/>4. Store tokens in Redis DB 1 session
    Client-->>User: HTTP 302 Redirect to /profile
    deactivate Client

    %% ------------------------------------------------------------------------
    %% Phase 5: Resource Access
    %% ------------------------------------------------------------------------
    Note over User, Spring: Phase 5: Sender-Constrained Resource Access
    User->>Client: GET /profile
    activate Client
    Note over Client: Sign DPoP proof for GET /userinfo
    Client->>Spring: GET /userinfo<br/>Authorization: DPoP <access_token><br/>DPoP: <dpop_proof>
    activate Spring
    Note over Spring: Validate access_token is active & cnf.jkt matches DPoP public key thumbprint
    Spring-->>Client: HTTP 200 OK (User profile claims)
    deactivate Spring
    Client-->>User: Render Profile UI with server-assigned scopes & token metadata
    deactivate Client
```

---

## Security Invariants Enforced in this Flow

1. **RFC 9221 JARM Cryptographic Enforcement**: All authorization responses (both successful code issuances and error responses) are signed as JWS JWTs (`?response=<jwt>`) using AWS KMS RS256 hardware keys. Plaintext query parameters (`?code=...` or `?error=...`) are strictly rejected by clients, completely preventing response parameter tampering, authorization code injection, and phishing/spoofing via forged error messages.
2. **No URL Parameter Leakage**: Sensitive parameters (`code_challenge`, `state`, `nonce`) are never exposed in browser address bars, HTTP referrers, or web server access logs.
3. **Sender-Constrained Tokens (RFC 9449)**: The access token is cryptographically bound to the client's public DPoP key via the `cnf.jkt` claim. If stolen in transit, it is unusable without the matching private DPoP key.
4. **DPoP Server-Provided Nonces (RFC 9449 §8)**: The authorization server enforces server-issued nonces stored in Redis (60-second TTL), preventing proof pre-generation and clock-skew replay attacks.
5. **Cryptographic Token Binding (`at_hash` & `c_hash`)**: The ID token embeds SHA-256 hashes of the access token and authorization code, cryptographically binding them together and preventing code/token substitution attacks.
6. **Mix-Up Attack Immunity (RFC 9207)**: The authorization server returns `iss=http://localhost:9000` (embedded within the KMS-signed JARM token and discovery metadata), and the client verifies this before dispatching authorization codes.
7. **No Static Secrets (RFC 7523)**: Client authenticates using an asymmetric RSA 2048-bit key pair (`private_key_jwt`), completely eliminating shared secret brute-forcing.
8. **Privilege Escalation Defense**: Scopes are entirely server-determined based on client configuration in PostgreSQL.

---

## Architectural Decision: Server-Determined Scopes vs. Rich Authorization Requests (RAR - RFC 9396)

### What RAR (RFC 9396) Does
Rich Authorization Requests (RAR) allows clients to specify fine-grained, structured authorization data using a JSON array (`authorization_details`) during the authorization request (e.g., requesting dynamic per-transaction approval such as `[{"type": "payment_initiation", "amount": 14.23, "currency": "GBP", "recipient": "..."}]`). It is primarily designed for Open Banking / PSD2 dynamic transaction approval where client requests cannot be statically modeled.

### Why We Retain Server-Determined Scopes
1. **Server-Governed Permissions vs. Client-Dictated Requests**: In our platform, permissions (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`) are administrative boundaries defined centrally in PostgreSQL via the Client Manager. Clients are never permitted to dictate or negotiate their own permissions dynamically.
2. **Preventing Access Token Bloat**: RAR embeds arbitrary nested JSON structures directly into JWT access tokens. Access tokens travel over HTTP headers (`Authorization: DPoP <token>`) on every downstream request. Bloated tokens increase network overhead, risk exceeding HTTP proxy header limits (typically 8KB–16KB), and slow down token parsing across downstream services.
3. **Lean Tokens + Rich Userinfo Pattern**: We enforce lean sender-constrained DPoP tokens containing only necessary routing and scope claims (`sub`, `iss`, `aud`, `exp`, `scope`, `cnf.jkt`). Rich user claims, profile metadata, and security clearances are retrieved out-of-band via TLS from the `/userinfo` endpoint or downstream services, providing real-time data freshness without bloating every access token.
