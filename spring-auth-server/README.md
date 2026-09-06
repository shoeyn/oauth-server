# Spring Boot OAuth 2.1 & OIDC Authorization Server

A hardened, enterprise **OAuth 2.1 Authorization Server** built with **Spring Boot 4.0.8** and **Spring Security 7.0.7** under Java 25.

---

## Security Policies & Architectural Design

1. **Strict `private_key_jwt` Client Authentication (RFC 7523)**:
   - Insecure methods (`client_secret_basic`, `client_secret_post`, `none`) are **completely disabled and actively rejected** with HTTP 401 `invalid_client` via `StrictClientAssertionAuthenticationConverter`.
   - Client assertions undergo signature verification, audience check (`aud`), issuer/subject matching (`iss == sub == client_id`), and Redis-backed JTI replay protection.
   - Public keys are dynamically resolved per client at request time via `JwtClientAssertionAuthenticationProvider.setJwtDecoderFactory(...)`.

2. **Dynamic S3 Client Repository & Hot-Reloading via Redis**:
   - [`S3RegisteredClientRepository`](src/main/java/com/example/authserver/client/S3RegisteredClientRepository.java) implements Spring Security's `RegisteredClientRepository`.
   - Reads client definitions from `s3://oauth2-clients/clients/*.json` (hosted locally via LocalStack on port 4566) and parses RSA public keys with `RsaKeyConverters.x509()`.
   - [`ClientReloadRedisSubscriber`](src/main/java/com/example/authserver/client/ClientReloadRedisSubscriber.java) listens to Redis channel `oauth2:clients:reload` and refreshes the in-memory cache dynamically in <20ms without restarting Spring Boot.
   - Includes automatic seeder fallback for `demo-client`.

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

The test suite runs both:
1. **OAuth 2.1 & OIDC Advanced Security Features** (PAR, DPoP, PKCE, Issuer ID, Revocation, Introspection, Back-Channel Logout)
2. **Dynamic S3 Client Configuration & Redis Hot-Reload** (S3 CRUD, real-time reload, dynamic client token exchange, and revocation)

```bash
bash functional_tests/run_functional_tests.sh
```
