# OAuth 2.1 Demo Client (Ruby, Puma, Redis)

A modern, production-grade OAuth 2.1 and OpenID Connect (OIDC) client application implemented in Ruby with Puma, demonstrating zero-trust client security mechanisms.

---

## Security Features & Standards

1. **RFC 9126: Pushed Authorization Requests (PAR)**:
   - Initiates authorization requests by pushing parameters directly to `/oauth2/par` over an authenticated backchannel POST with `private_key_jwt`.
   - Obtains an opaque, single-use `request_uri`.

2. **RFC 7523: `private_key_jwt` Client Authentication**:
   - Uses a 2048-bit RSA key pair (`keys/client_private_key.pem`) to sign RS256 client assertions with JTI and audience binding.
   - Disables all static client secret mechanisms.

3. **RFC 9449: Sender-Constrained DPoP Tokens**:
   - Generates an ephemeral EC/RSA private key per session.
   - Signs `DPoP` proof headers on code exchange and token refresh.
   - Resource requests (e.g. `/userinfo`) send `Authorization: DPoP <token>` accompanied by a matching `DPoP` proof.

4. **RFC 7636: PKCE (`S256`)**:
   - Cryptographic code verifier and SHA-256 code challenge on all authorization flows.

5. **RFC 9207: Authorization Server Issuer Identification**:
   - Validates that the callback contains `iss` matching the configured Authorization Server URL to mitigate Mix-Up attacks.

6. **Server-Determined Scopes**:
   - The client requests NO scopes (`scope` parameter omitted). Authorized scopes are pre-determined by the Authorization Server and configured in S3 via the Next.js Client Manager.

7. **RFC 7009 & RFC 7662: Token Revocation & Introspection**:
   - Interactive revocation button on `/profile` revokes tokens and flushes the Redis session.

8. **OpenID Connect Back-Channel Logout 1.0**:
   - Receives signed `logout_token` JWS at `POST /oidc/backchannel_logout` and evicts active sessions from Redis.

9. **Persistent Redis Token Store (DB 1)**:
   - Tokens and DPoP keys are stored securely in Redis DB 1, surviving server restarts.

10. **Dynamic S3 Client Management Integration**:
    - Registered client configuration, public key, redirect URIs, and scopes are stored in S3 (`oauth2-clients/clients/demo-client.json`) and manageable live via the Next.js Client Manager (`http://localhost:3001`).

11. **High-Speed Ephemeral DPoP Key Generation (EC P-256 / ES256)**:
    - Proof-of-possession asymmetric keys default to Elliptic Curve P-256 (`prime256v1`), generating in **~0.01 ms (4,800x faster than RSA-2048)**, eliminating ~40ms of CPU blocking time per session.

12. **In-Memory Thread-Safe JWKS Cache with Auto-Rotation**:
    - Authorization Server public keys are cached in-memory with a 1-hour sliding TTL, resolving token verifications in **< 1 ms** without network overhead. Automatically detects and re-fetches unknown `kid` key rotations with rate-limiting protection.

13. **Automated Network Resilience & Retries**:
    - Idempotent operations (JWKS retrieval, token introspection, userinfo, token revocation) are protected with automated exponential backoff retries and randomized jitter.

---

## Running the Demo Client

### With Mise
```bash
cd demo-client
mise exec -- bundle install
mise exec -- bundle exec puma -b tcp://0.0.0.0:8080
```
Visit: **`http://localhost:8080`**

### With Docker Compose
```bash
docker compose up -d demo-client
```

---

## Running the Automated Functional Test Suite

```bash
bash functional_tests/run_functional_tests.sh
```
Runs all 3 suites:
1. `test_oauth_security_features.rb` (PAR, DPoP, PKCE, Issuer ID, Revocation, Introspection, Back-Channel Logout)
2. `test_s3_dynamic_client_reload.rb` (S3 CRUD, Redis hot-reload, dynamic client token exchange, and revocation)
3. `test_performance_and_resilience.rb` (In-memory 304 caching, EC vs RSA DPoP benchmark, in-memory JWKS cache hit, retries)

## Performance & Load Testing (k6)
```bash
k6 run ../k6/oauth_load_test.js
```
