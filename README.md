# Enterprise OAuth 2.1 & OpenID Connect (OIDC) Platform

A production-grade, hardened **OAuth 2.1 Authorization Server** and **OpenID Connect (OIDC)** ecosystem built with **Spring Boot 4 / Spring Security 7**, an external **Ruby on Rails** Identity Provider (IdP) with a **shared Redis session**, and a modern **Ruby/Puma Demo Client** featuring sender-constrained tokens, cryptographic client assertions, and real-time session management.

---

## High-Level Architecture & Standards Compliance

```
                                  Browser / User-Agent
                 ┌──────────────────────────────────────────────────────┐
                 │  - Visits Demo Client (http://localhost:8080)         │
                 │  - Redirected via PAR request_uri to /oauth2/authorize│
                 │  - Authenticates at Rails IdP (http://localhost:3000) │
                 │  - Returns with code & iss to Demo Client callback    │
                 └──────────────────────────┬───────────────────────────┘
                                            │
               Direct Browser Redirects     │     Direct Browser Redirects
                                            ▼
┌───────────────────────────────┐               ┌─────────────────────────────────┐
│     Ruby Demo Client          │               │       Rails Identity Provider   │
│   (http://localhost:8080)     │               │     (http://localhost:3000)     │
├───────────────────────────────┤               ├─────────────────────────────────┤
│ • Zero Client Scopes          │               │ • User Authentication UI        │
│ • Ephemeral DPoP Key Pair     │               │ • Sets SHARED_SESSION_ID cookie │
│ • Local Redis Session (DB 1)  │               │ • Writes user details to Redis  │
│ • Back-Channel Logout Receiver│               └───────────────┬─────────────────┘
└───────────────┬───────────────┘                               │
                │                                               │
   Backchannel  │ Backchannel PAR, Code Exchange,               │ Shared Session
   Logout Push  │ Introspection & Revocation                    │ Context
   (/oidc/...)  │ (DPoP + private_key_jwt)                      │ (session:<id>)
                ▼                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Spring Authorization Server (http://localhost:9000)           │
├─────────────────────────────────────────────────────────────────────────────────┤
│ • RFC 9126: Native Pushed Authorization Requests (PAR)                           │
│ • RFC 7523: Strict private_key_jwt Authentication (weak methods rejected)        │
│ • RFC 9449: Strictly Enforced DPoP Tokens (Sender-Constrained cnf.jkt binding)   │
│ • RFC 7636: Proof Key for Code Exchange (PKCE S256) strictly enforced            │
│ • RFC 9207: Authorization Server Issuer Identification (Mix-Up Attack defense)  │
│ • Server-Determined Authorization Scopes (zero client scope tampering)           │
│ • RFC 7009: Token Revocation & RFC 7662: Token Introspection                     │
│ • OpenID Connect Back-Channel Logout 1.0 (asynchronous signed logout_token)     │
│ • SharedRedisSessionFilter: SSO bridge with Rails IdP via Redis                  │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
                        ┌──────────────────────────────┐
                        │         Redis Server         │
                        │    (localhost:6379)          │
                        ├──────────────────────────────┤
                        │ DB 0: Rails SSO & Spring JTI │
                        │ DB 1: Demo Client Sessions   │
                        └──────────────────────────────┘
```

---

## Implemented Security Standards & Specifications

| Standard / RFC | Specification Name | How It Is Implemented & Enforced |
|---|---|---|
| **RFC 9126** | **Pushed Authorization Requests (PAR)** | All authorization parameters (`client_id`, `state`, `nonce`, `code_challenge`) are pushed directly to `/oauth2/par` over TLS via an authenticated backchannel POST. The browser only receives an opaque, single-use `request_uri`. Stops query leakage and URL manipulation. |
| **RFC 7523** | **`private_key_jwt` Client Authentication** | Clients authenticate exclusively using RS256-signed JWT assertions (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`). Static client secrets (`client_secret_basic`, `client_secret_post`) and insecure `none` authentication are **strictly rejected with HTTP 401**. Includes JTI replay cache in Redis and strict `iss`, `sub`, `aud` validation. |
| **RFC 9449** | **Demonstrating Proof-of-Possession (DPoP)** | The `/oauth2/token` endpoint strictly enforces the `DPoP` HTTP header (requests lacking DPoP are rejected with HTTP 400 `invalid_dpop_proof`). Issued access tokens are sender-constrained by embedding the DPoP key thumbprint in the `cnf.jkt` claim. The token cannot be used without the private DPoP key. |
| **RFC 7636** | **PKCE (`S256`)** | Proof Key for Code Exchange is enforced on all authorization requests (`requireProofKey(true)`). Intercepted authorization codes cannot be exchanged without the client's `code_verifier`. |
| **RFC 9207** | **Authorization Server Issuer Identification** | The authorization response appends `iss=http://localhost:9000` to the callback URL. The client strictly validates the issuer before exchanging the code, completely mitigating OAuth 2.0 Mix-Up Attacks. |
| **Architecture** | **Server-Determined Scopes** | The demo client omits the `scope` parameter entirely. The Authorization Server predetermines and binds authorized scopes strictly based on registered client configuration (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`), preventing privilege escalation and client-side scope tampering. |
| **RFC 7009** | **Token Revocation** | Clients revoke tokens via `/oauth2/revoke` authenticated with `private_key_jwt`. Revocation invalidates the authorization and immediately flushes local and distributed sessions. |
| **RFC 7662** | **Token Introspection** | Resource servers and clients check token validity in real time at `/oauth2/introspect` using `private_key_jwt`. Useful for immediate fraud checks prior to executing sensitive actions. |
| **OIDC BCL 1.0** | **Back-Channel Logout 1.0** | Spring Authorization Server dispatches a signed JWT `logout_token` asynchronously to the client's backchannel endpoint (`/oidc/backchannel_logout`), terminating the user's session without relying on user-agent redirection. |

---

## Services & Ports

| Service | Port | Description | Technology Stack |
|---|---|---|---|
| **`demo-client`** | `8080` | Interactive OAuth 2.1 client & UI | Ruby 4.0, Puma, Rack, Redis DB 1 |
| **`rails-app`** | `3000` | External Identity Provider (IdP) | Ruby on Rails 7, Redis DB 0 |
| **`spring-auth-server`**| `9000` | OAuth 2.1 & OIDC Authorization Server | Spring Boot 4.0.8, Spring Security 7.0.7, Java 25 |
| **`poc-redis`** | `6379` | Shared Redis session & token cache | Redis 7 Alpine |

---

## Quick Start & Running Services

### Prerequisites
- **mise** (or Java 25 + Ruby 4.0.6 installed locally), or **Docker & Docker Compose**.
- Running Redis instance on `localhost:6379`.

### Option A: Running with Docker Compose
To run the full stack in Docker containers:
```bash
docker compose up --build -d redis rails-app spring-auth-server demo-client
```
Access the Demo Client at: **`http://localhost:8080`**

### Option B: Running Locally with Mise / Native CLI

1. **Start Redis**:
   ```bash
   docker run -d --name poc-redis -p 6379:6379 redis:alpine
   ```

2. **Start Rails Login App (Port 3000)**:
   ```bash
   cd rails-app
   mise exec -- bundle exec rails server -p 3000 -b 0.0.0.0
   ```

3. **Start Spring Authorization Server (Port 9000)**:
   ```bash
   cd spring-auth-server
   mise exec -- mvn clean package -DskipTests
   mise exec -- java -jar target/spring-auth-server-0.0.1-SNAPSHOT.jar
   ```

4. **Start Demo Client (Port 8080)**:
   ```bash
   cd demo-client
   mise exec -- bundle exec puma -b tcp://0.0.0.0:8080
   ```

---

## Running the Automated Functional Test Suite

A complete, multi-step functional test suite verifying all OAuth 2.1 security features, bypass prevention, DPoP binding, issuer identification, revocation, introspection, and back-channel logout is provided in both projects:

### Run from `spring-auth-server`:
```bash
bash spring-auth-server/functional_tests/run_functional_tests.sh
```

### Run from `demo-client`:
```bash
bash demo-client/functional_tests/run_functional_tests.sh
```

---

## Project Structure

```
.
├── docker-compose.yml              # Multi-container orchestration
├── README.md                       # Complete platform documentation
├── spring-auth-server/             # Spring Boot 4 / Spring Security 7 Authorization Server
│   ├── functional_tests/           # Automated security test suite & shell runner
│   │   ├── run_functional_tests.sh
│   │   └── test_oauth_security_features.rb
│   ├── pom.xml
│   └── src/main/java/com/example/authserver/
│       ├── config/
│       │   ├── AuthorizationServerConfig.java   # Strict converters, PAR, DPoP, revocation
│       │   ├── KeyConfig.java                   # RSA signing keys & JWK Source
│       │   ├── TokenCustomizerConfig.java       # DPoP cnf.jkt binding & custom claims
│       │   └── ExternalLoginAuthenticationEntryPoint.java # SSO redirect to Rails
│       └── security/
│           ├── OidcBackChannelLogoutService.java# Dispatches signed logout_token JWS
│           └── SharedRedisSessionFilter.java    # Bridges Rails shared session to Spring context
├── rails-app/                      # Ruby on Rails 7 Identity Provider
│   ├── app/controllers/sessions_controller.rb  # Writes session:<uuid> to Redis
│   └── app/views/sessions/new.html.erb         # User login form
└── demo-client/                    # Modern Ruby OAuth 2.1 Demo Client (Puma + Redis)
    ├── app/
    │   ├── controllers/auth_controller.rb       # PAR, DPoP, token exchange, refresh, logout
    │   ├── services/par_oauth2_client.rb        # DPoP proofs, private_key_jwt assertions
    │   └── views/auth/                          # Index UI with feature checklist, Profile UI
    └── functional_tests/           # Client copy of functional test suite
        ├── run_functional_tests.sh
        └── test_oauth_security_features.rb
```
