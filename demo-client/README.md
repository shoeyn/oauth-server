# OAuth 2.1 Demo Client (Ruby, Puma, Redis)

A modern, production-grade Rails client application demonstrating zero-trust client security mechanisms. All underlying OAuth 2.1, OIDC, and cryptographic protocol logic is packaged and consumed from the reusable **[`oauth2_client_kit`](../oauth2_client_kit)** library. This client application consists solely of user-facing views (landing page, authenticated profile) and calls to library methods.

```
┌───────────────────────────────────────────────┐
│     Demo Client Application (This Repo)       │
│  • Landing Page (app/views/pages/index)       │
│  • User Profile (app/views/pages/profile)     │
│  • Client Redis Session (DB 1, namespace)     │
│  • Sensitive Action trigger (identity check)  │
└───────────────────────┬───────────────────────┘
                        │ mounts & calls
                        ▼
┌───────────────────────────────────────────────┐
│       oauth2_client_kit Standalone Gem        │
│  • RFC 9221 JARM Verifier & Enforcement       │
│  • Pushed Authorization Requests (RFC 9126)   │
│  • Asymmetric Client Auth (RFC 7523)          │
│  • DPoP Sender Constraints (RFC 9449)         │
│  • Pre-flight Introspection Checkpoints       │
│  • Backchannel Logout Receiver (OIDC BCL 1.0) │
└───────────────────────────────────────────────┘
```

---

## Security Features & Standards (Handled by `oauth2_client_kit`)

1. **RFC 9221: JWT-Secured Authorization Response Mode (JARM)**:
   - Enforces cryptographic JWS signing (RS256) of all front-channel authorization responses (codes, issuer identity, state, and error responses).
   - Plaintext callback parameters (`?code=...`, `?error=...`) are strictly rejected, preventing authorization code injection, parameter tampering, and phishing via forged error descriptions.

2. **RFC 9126: Pushed Authorization Requests (PAR)**:
   - Initiates authorization requests by pushing parameters directly to `/oauth2/par` over an authenticated backchannel POST with `private_key_jwt`.
   - Obtains an opaque, single-use `request_uri`, keeping scopes, state, and code challenges out of browser history and proxy access logs.

2. **RFC 7523: `private_key_jwt` Client Authentication**:
   - Uses a 2048-bit RSA key pair (`keys/client_private_key.pem`) to sign RS256 client assertions with JTI and audience binding.
   - Disables all static client secret mechanisms.

3. **Strict Algorithm Pinning (RFC 8725 Section 3.1)**:
   - Evaluates the unverified JWT header before cryptographic decoding and enforces `alg == "RS256"`.
   - Strictly rejects `alg: none` and symmetric HMAC algorithms (`HS256`), eliminating algorithm confusion vulnerabilities.

4. **RFC 9449: Sender-Constrained DPoP Tokens & Server Nonce Support**:
   - Generates an ephemeral EC/RSA private key per session.
   - Signs `DPoP` proof headers on code exchange and token refresh.
   - Resource requests (e.g. `/userinfo`) send `Authorization: DPoP <token>` accompanied by a matching `DPoP` proof.
   - **RFC 9449 Section 8 Server-Provided Nonces**: Transparently captures `use_dpop_nonce` error responses from Spring Auth Server and automatically retries requests using the server-issued `DPoP-Nonce` header.

5. **OpenID Connect ID Token Hash Validation (`at_hash` & `c_hash`)**:
   - Cryptographically computes SHA-256 left-half hashes against the Access Token (`at_hash`) and Authorization Code (`c_hash`).
   - Ensures cryptographic binding and detects token/code substitution attacks in transit.

6. **RFC 7636: PKCE (`S256`)**:
   - Cryptographic code verifier and SHA-256 code challenge on all authorization flows.

7. **RFC 9207: Authorization Server Issuer Identification**:
   - Validates that the callback contains `iss` matching the configured Authorization Server URL to mitigate Mix-Up attacks.

8. **Server-Determined Scopes**:
   - The client requests NO scopes (`scope` parameter omitted). Authorized scopes are pre-determined by the Authorization Server and persisted in PostgreSQL via the Next.js Client Manager and Spring Admin REST API.

9. **RFC 7009 & RFC 7662: Token Revocation & Introspection**:
   - Interactive revocation on `/profile` revokes tokens at the authorization server and flushes the local Redis session.

10. **OpenID Connect Back-Channel Logout 1.0**:
    - Receives signed `logout_token` JWS at `POST /oidc/backchannel_logout` and evicts active sessions from Redis.

11. **Persistent Redis Token Store (DB 1)**:
    - Tokens and DPoP keys are stored securely in Redis DB 1, surviving server restarts.

12. **High-Speed Ephemeral DPoP Key Generation (EC P-256 / ES256)**:
    - Proof-of-possession asymmetric keys default to Elliptic Curve P-256 (`prime256v1`), generating in **~0.01 ms (4,800x faster than RSA-2048)**, eliminating ~40ms of CPU blocking time per session.

13. **In-Memory Thread-Safe JWKS Cache with Auto-Rotation**:
    - Authorization Server public keys are cached in-memory with a 1-hour sliding TTL, resolving token verifications in **< 1 ms** without network overhead. Automatically detects unknown `kid` values and re-fetches `/oauth2/jwks` with rate-limiting protection to support zero-downtime key rotation.

14. **Automated Network Resilience & Retries**:
    - Idempotent operations (JWKS retrieval, token introspection, userinfo, token revocation) are protected with automated exponential backoff retries and randomized jitter.

15. **Production Clustered Puma Concurrency Model**:
    - Configured via [`config/puma.rb`](config/puma.rb) with clustered workers (`WEB_CONCURRENCY=2`) and **8..16 threads per worker**, enabling high-throughput concurrent auth flows.

---

## Running the Demo Client

### With Mise
```bash
cd demo-client
mise exec -- bundle install
mise exec -- bundle exec puma -C config/puma.rb
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
Runs all 4 suites:
1. `test_oauth_security_features.rb` (PAR, DPoP, PKCE, Issuer ID, Revocation, Introspection, Back-Channel Logout)
2. `test_s3_dynamic_client_reload.rb` (Dynamic PostgreSQL client CRUD via Spring Admin API, Redis hot-reload, dynamic client token exchange, and revocation)
3. `test_performance_and_resilience.rb` (In-memory 304 caching, EC vs RSA DPoP benchmark, in-memory JWKS cache hit, retries)
4. `test_kms_signing.rb` (AWS KMS HSM signing, strict algorithm pinning rejection of `none` and `HS256`, multi-key JWKS rotation)

## Performance & Load Testing (k6)
```bash
k6 run ../k6/oauth_load_test.js
```
