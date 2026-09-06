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
   - The client requests NO scopes (`scope` parameter omitted). Authorized scopes are pre-determined by the Authorization Server.

7. **RFC 7009 & RFC 7662: Token Revocation & Introspection**:
   - Interactive revocation button on `/profile` revokes tokens and flushes the Redis session.

8. **OIDC Back-Channel Logout 1.0**:
   - Receives signed `logout_token` JWS at `POST /oidc/backchannel_logout` and evicts active sessions from Redis.

9. **Persistent Redis Token Store (DB 1)**:
   - Tokens and DPoP keys are stored securely in Redis DB 1, surviving server restarts.

---

## Running the Demo Client

### With Mise
```bash
cd demo-client
mise exec -- bundle install
mise exec -- bundle exec puma -b tcp://0.0.0.0:8080
```
Visit: `http://localhost:8080`

### Running the Functional Test Suite
```bash
bash functional_tests/run_functional_tests.sh
```
