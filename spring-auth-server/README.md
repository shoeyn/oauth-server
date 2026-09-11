# Spring Boot OAuth 2.1 & OIDC Authorization Server

A hardened, enterprise **OAuth 2.1 Authorization Server** built with **Spring Boot 4.0.8** and **Spring Security 7.0.7** under Java 25.

---

## Security Policies & Architectural Design

1. **Hardware-Backed Asymmetric Signing via AWS KMS (FIPS 140-2 Level 3 / FIPS 140-3)**:
   - Private signing keys reside within the AWS KMS Hardware Security Module (HSM) boundary.
   - Access tokens, ID tokens, and logout tokens are signed remotely via [`KmsJwtEncoder`](src/main/java/com/example/authserver/security/KmsJwtEncoder.java) and [`KmsRsaSigner`](src/main/java/com/example/authserver/security/KmsRsaSigner.java) using `RSA_2048` (`RSASSA_PKCS1_V1_5_SHA_256`).
   - Private key material **never enters host or JVM heap memory**, mitigating memory scraping and offline forgery.
   - **Fail-Closed Guarantee:** In production (`aws.kms.enabled: true`), the server aborts startup if KMS is unreachable, preventing cryptographic downgrade attacks.

2. **Graceful Multi-Key JWKS Rotation**:
   - The authorization server resolves both active signing keys (`alias/oauth2-signing-key`) and previous keys (`alias/oauth2-signing-key-previous`).
   - Both keys are published concurrently at `/oauth2/jwks` with unique key IDs (`kms-auth-server-key-1` and `kms-auth-server-key-previous`).
   - In-flight tokens issued before rotation remain verifiable across clients through their time-to-live (TTL) window.
   - Key rotation is operationalized via [`scripts/rotate_kms_keys.sh`](../scripts/rotate_kms_keys.sh) and documented in [`docs/architecture/kms_multi_key_rotation_flow.md`](../docs/architecture/kms_multi_key_rotation_flow.md).

3. **Strict Algorithm Pinning (RFC 8725 Section 3.1)**:
   - Client assertions and resource server tokens enforce strict algorithm pinning (`alg: RS256`).
   - Insecure algorithms (`none`), symmetric HMAC algorithms (`HS256` key confusion attacks), and non-approved asymmetric algorithms are actively rejected with HTTP 400/401.

4. **Strict `private_key_jwt` Client Authentication (RFC 7523)**:
   - Insecure shared-secret methods (`client_secret_basic`, `client_secret_post`, `none`) are **disabled and actively rejected** with HTTP 401 `invalid_client` via `StrictClientAssertionAuthenticationConverter`.
   - Client assertions undergo RS256 signature verification, audience validation (`aud`), issuer/subject matching (`iss == sub == client_id`), and Redis-backed JTI replay protection.
   - Public keys are dynamically resolved per client at request time via `JwtClientAssertionAuthenticationProvider.setJwtDecoderFactory(...)`.

5. **PostgreSQL Persistence & High-Performance Near-Caching**:
   - **ACID Persistence**: Registered clients and public keys are durably stored in PostgreSQL (`oauth2_registered_client`, `oauth2_client_public_key`) via [`PostgresRegisteredClientRepository`](src/main/java/com/example/authserver/client/PostgresRegisteredClientRepository.java).
   - **In-Memory Near-Cache**: Pre-warmed `ConcurrentHashMap` caches serve token validation and signature checks in ~0.001 ms with **zero database round-trips** during steady-state traffic.
   - **Distributed Authorizations**: [`JdbcOAuth2AuthorizationService`](src/main/java/com/example/authserver/config/AuthorizationServerConfig.java) stores active authorization codes, refresh tokens, and consent state in PostgreSQL (`oauth2_authorization`, `oauth2_authorization_consent`), enabling seamless multi-pod horizontal scaling and zero session loss on restarts.
   - **Database Evolution via Flyway**: Automated migrations manage schema versioning and B-tree index creation in `db/migration/`.
   - **Java Admin REST API**: External managers invoke authenticated endpoints (`/api/admin/clients`) on the Java service, preserving zero-trust isolation so **only Java communicates with PostgreSQL**.
   - **Real-Time Cluster Hot-Reloading**: [`ClientReloadRedisSubscriber`](src/main/java/com/example/authserver/client/ClientReloadRedisSubscriber.java) listens to Redis channel `oauth2:clients:reload`. Updates refresh in-memory maps across all nodes instantaneously without restarting Spring Boot.
   - For complete architecture details, see [PostgreSQL Persistence & Performance Architecture](../docs/architecture/postgres_persistence_and_performance.md).

6. **Mandatory DPoP Proofs & Server-Provided Nonces (RFC 9449 Section 5 & 8)**:
   - `StrictDPoPTokenRequestAuthenticationConverter` strictly requires the `DPoP` HTTP header on `/oauth2/token` requests, returning HTTP 400 `invalid_dpop_proof` if missing.
   - Access tokens are sender-constrained by embedding `cnf.jkt` computed from the client's public DPoP key JWK thumbprint.
   - **RFC 9449 Section 8 DPoP Nonces**: Implemented in [`DPoPNonceFilter`](src/main/java/com/example/authserver/security/DPoPNonceFilter.java). Requires DPoP proofs to include single-use server nonces stored in Redis (60-second TTL), responding with `HTTP 400 use_dpop_nonce` and `DPoP-Nonce` header to defeat clock-skew proof replay attacks.

7. **OpenID Connect ID Token Integrity Hashes (`at_hash` & `c_hash`)**:
   - Implemented in [`TokenCustomizerConfig`](src/main/java/com/example/authserver/config/TokenCustomizerConfig.java). Computes SHA-256 left-half base64url-encoded hashes of the Access Token (`at_hash`) and Authorization Code (`c_hash`), cryptographically binding tokens together in compliance with OIDC Core Section 3.1.3.6.

8. **Discovery Metadata Hardening**:
   - Advertises strictly `["private_key_jwt"]` as supported `token_endpoint_auth_methods_supported`, completely purging all insecure shared-secret authentication mechanisms from `/.well-known/openid-configuration`.

9. **Server-Determined Authorization Scopes**:
   - `OAuth2AuthorizationService` wrapper automatically binds the registered client's authorized scopes (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`) when clients omit scopes.
   - Client-requested scopes are ignored or defaulted to registered client configuration.

10. **RFC 9126: Native Pushed Authorization Requests (PAR)**:
    - Built-in Spring Security 7 PAR endpoint at `/oauth2/par`.

11. **RFC 9221: JWT-Secured Authorization Response Mode (JARM)**:
    - Implemented in `AuthorizationServerConfig`: all front-channel authorization responses (`authorizationResponseHandler`) and error responses (`errorResponseHandler`) are cryptographically signed with RS256 using AWS KMS (`KmsJwtEncoder`).
    - Responses are redirected to `redirect_uri?response=<jarmJwt>`, protecting `code`, `iss`, `aud`, `state`, `error`, and `error_description` from URL query parameter manipulation and phishing injection attacks.
    - Advertises `"response_modes_supported": ["jwt", "query.jwt"]` in `/.well-known/openid-configuration`.

12. **RFC 9207: Authorization Server Issuer Identification**:
    - Authorization responses include the `iss` parameter alongside `code` and `state` (encapsulated within the JARM JWT) to mitigate OAuth 2.0 Mix-Up attacks.

13. **RFC 7009 & RFC 7662: Token Revocation & Introspection**:
    - Endpoints `/oauth2/revoke` and `/oauth2/introspect` fully supported with `private_key_jwt`.

14. **OpenID Connect Back-Channel Logout 1.0**:
    - `OidcBackChannelLogoutService` assembles and signs `logout_token` JWS with server's RSA key, dispatching it asynchronously with exponential retries to registered client backchannel endpoints.

15. **Single Sign-On (SSO) with External Rails IdP via Shared Redis**:
    - `SharedRedisSessionFilter` inspects `SHARED_SESSION_ID` cookie, loads user authentication claims from `session:<id>` in Redis DB 0, and establishes a Spring `SecurityContext`.
    - **M2M Performance Bypass (`shouldNotFilter`)**: Bypasses Redis queries on machine-to-machine endpoints (`/oauth2/token`, `/oauth2/par`, `/oauth2/jwks`, `/oauth2/introspect`, `/oauth2/revoke`, `/.well-known/**`).

16. **In-Memory Discovery & JWKS Caching with ETag / HTTP 304**:
    - `DiscoveryAndJwksCacheFilter` caches pre-rendered byte arrays for `/.well-known/openid-configuration` and `/oauth2/jwks` with `Cache-Control: public, max-age=3600`.
    - Returns **HTTP 304 Not Modified with 0 body bytes** on conditional `If-None-Match` requests.

17. **Cached Client Assertion `JwtDecoder`**:
    - Reuses `NimbusJwtDecoder` instances in a `ConcurrentHashMap` keyed by `clientId:keyHash`, eliminating RSA key re-parsing on every client assertion.

18. **Native HTTP/2 Stream Multiplexing (`h2c` / ALPN)**:
    - Enabled via `server.http2.enabled: true` in `application.yml`, allowing multiple concurrent requests over a single TCP socket.

---

## Building and Running

### With Maven & Mise
```bash
cd spring-auth-server
mise exec -- mvn clean package -DskipTests
mise exec -- java -jar target/spring-auth-server-0.0.1-SNAPSHOT.jar
```
Server runs on: **`http://localhost:9000`**

### With Docker Compose
```bash
docker compose up -d spring-auth-server
```

---

## Running the Automated Functional Test Suite

The test suite executes all 6 suites:
1. **OAuth 2.1 & OIDC Advanced Security Features** (PAR, DPoP, PKCE, Issuer ID, Revocation, Introspection, Back-Channel Logout)
2. **Dynamic Client Configuration & Near-Cache Hot-Reload** (Admin REST API, PostgreSQL persistence, real-time reload, dynamic client token exchange, and revocation)
3. **Performance, In-Memory Caching & Resilience** (ETag 304 validation, EC vs RSA DPoP benchmark, in-memory JWKS cache hit, retries)
4. **AWS KMS Cryptographic Signing & Security Verification** (KMS HSM signing, strict algorithm pinning, multi-key JWKS rotation)
5. **Client Error Flow Handling & Per-Error View Overrides** (Spring JARM error signing, custom host template overrides, IdP simulated error flow)
6. **RFC 9221 (JARM) Enforcement & Cryptographic Security** (Strict JARM enforcement, KMS signature verification, negative attacks defense: plaintext rejection, tampering rejection, forgery rejection, client isolation)

```bash
bash functional_tests/run_functional_tests.sh
```

## Performance & Load Testing (k6)
```bash
k6 run ../k6/oauth_load_test.js
```
