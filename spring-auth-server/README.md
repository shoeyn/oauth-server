# Spring Boot OAuth 2.1 & OIDC Authorization Server

A hardened, enterprise **OAuth 2.1 Authorization Server** built with **Spring Boot 4.0.8** and **Spring Security 7.0.7** under Java 25.

---

## Security Policies & Architectural Design

1. **Strict `private_key_jwt` Client Authentication (RFC 7523)**:
   - Insecure methods (`client_secret_basic`, `client_secret_post`, `none`) are **completely disabled and actively rejected** with HTTP 401 `invalid_client` via `StrictClientAssertionAuthenticationConverter`.
   - Client assertions undergo signature verification, audience check (`aud`), issuer/subject matching (`iss == sub == client_id`), and Redis-backed JTI replay protection.
   - Public keys are dynamically resolved per client at request time via `JwtClientAssertionAuthenticationProvider.setJwtDecoderFactory(...)`.

2. **Multi-Tier Client Configuration & Hot-Reloading (L1-L3)**:
   - **L1 In-Memory Cache**: `ConcurrentHashMap` instances in [`S3RegisteredClientRepository`](src/main/java/com/example/authserver/client/S3RegisteredClientRepository.java) satisfy authorization requests and assertion verification in nanoseconds without network overhead.
   - **L2 Redis Cache (`oauth2:clients:configs`)**: Registered client configurations are cached in a Redis hash with a 30-day sliding TTL. On service restarts, Spring boots in **< 5ms directly from Redis without making any S3 network calls**.
   - **L3 S3 Object Store**: Single source of truth in `s3://oauth2-clients/clients/*.json` (LocalStack). If Redis is cold, Spring falls back to S3 and synchronizes Redis.
   - **Real-Time Hot-Reloading**: [`ClientReloadRedisSubscriber`](src/main/java/com/example/authserver/client/ClientReloadRedisSubscriber.java) listens to Redis channel `oauth2:clients:reload`. Updates from Next.js refresh in-memory maps and Redis cache in < 15ms without restarting Spring Boot.
   - For complete sequence flows, see [Multi-Tier Client Configuration & Hot-Reload Flow](../../docs/architecture/client_config_and_caching_flow.md).

3. **Mandatory DPoP Proofs at Token Endpoint (RFC 9449 Section 5)**:
   - `StrictDPoPTokenRequestAuthenticationConverter` strictly requires the `DPoP` HTTP header on `/oauth2/token` requests, returning HTTP 400 `invalid_dpop_proof` if missing.
   - Access tokens are sender-constrained by embedding `cnf.jkt` computed from the client's public DPoP key JWK thumbprint.

4. **Server-Determined Authorization Scopes**:
   - `OAuth2AuthorizationService` wrapper automatically binds the registered client's authorized scopes (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`) when clients omit scopes.
   - Client-requested scopes are ignored or defaulted to registered client configuration.

5. **RFC 9126: Native Pushed Authorization Requests (PAR)**:
   - Built-in Spring Security 7 PAR endpoint at `/oauth2/par`.
   - `ClientPreDeterminedScopeAuthorizationRequestConverter` contains full instructions and implementation details for enforcing mandatory PAR.

6. **RFC 9207: Authorization Server Issuer Identification**:
   - Authorization responses include the `iss` parameter alongside `code` and `state`.

7. **RFC 7009 & RFC 7662: Token Revocation & Introspection**:
   - Endpoints `/oauth2/revoke` and `/oauth2/introspect` fully supported with `private_key_jwt`.

8. **OpenID Connect Back-Channel Logout 1.0**:
   - `OidcBackChannelLogoutService` assembles and signs `logout_token` JWS with server's RSA private key, dispatching it to client backchannel logout endpoints upon session termination.

9. **Single Sign-On (SSO) with External Rails IdP via Shared Redis**:
   - `SharedRedisSessionFilter` inspects `SHARED_SESSION_ID` cookie, fetches user authentication data from `session:<id>` in Redis DB 0, and establishes a Spring `SecurityContext`.
   - **M2M Performance Bypass (`shouldNotFilter`)**: Bypasses Redis queries on machine-to-machine endpoints (`/oauth2/token`, `/oauth2/par`, `/oauth2/jwks`, `/oauth2/introspect`, `/oauth2/revoke`, `/.well-known/**`), eliminating unneeded Redis round-trips.

10. **In-Memory Discovery & JWKS Caching with ETag / HTTP 304**:
    - `DiscoveryAndJwksCacheFilter` caches pre-rendered byte arrays for `/.well-known/openid-configuration` and `/oauth2/jwks` with `Cache-Control: public, max-age=3600, stale-while-revalidate=86400`.
    - Returns **HTTP 304 Not Modified with 0 body bytes** on conditional `If-None-Match` requests, eliminating JSON re-serialization overhead.

11. **Cached Client Assertion `JwtDecoder`**:
    - Reuses `NimbusJwtDecoder` instances in a `ConcurrentHashMap` keyed by `clientId:keyHash`, eliminating RSA key re-parsing and validator chain reconstruction on every client assertion.

12. **Asynchronous Back-Channel Logout Dispatch with Retries**:
    - `OidcBackChannelLogoutService` dispatches signed `logout_token` notifications asynchronously via `CompletableFuture.runAsync` with a 3-attempt exponential backoff retry loop, decoupling user logout response latency from client endpoint response time.

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

The test suite runs all 3 suites:
1. **OAuth 2.1 & OIDC Advanced Security Features** (PAR, DPoP, PKCE, Issuer ID, Revocation, Introspection, Back-Channel Logout)
2. **Dynamic S3 Client Configuration & Redis Hot-Reload** (S3 CRUD, real-time reload, dynamic client token exchange, and revocation)
3. **Performance, In-Memory Caching & Resilience** (ETag 304 validation, EC vs RSA DPoP benchmark, in-memory JWKS cache hit, retries)

```bash
bash functional_tests/run_functional_tests.sh
```

## Performance & Load Testing (k6)
```bash
k6 run ../k6/oauth_load_test.js
```
