# Enterprise OAuth 2.1 & OpenID Connect (OIDC) Platform

A production-grade, hardened **OAuth 2.1 Authorization Server** and **OpenID Connect (OIDC)** ecosystem built with **Spring Boot 4 / Spring Security 7**, an external **Ruby on Rails** Identity Provider (IdP) with a **shared Redis session**, and a modern **Ruby/Puma Demo Client** featuring sender-constrained tokens, cryptographic client assertions, and real-time session management.

---

## High-Level Architecture & Standards Compliance

```
                                  Browser / User-Agent / Administrator
                 ┌──────────────────────────────────────────────────────────────────┐
                 │  - Visits Demo Client (http://localhost:8080)                    │
                 │  - Redirected via PAR request_uri to /oauth2/authorize           │
                 │  - Authenticates at Rails IdP (http://localhost:3000)            │
                 │  - Returns with code & iss to Demo Client callback               │
                 │  - Configures clients via Next.js Manager (http://localhost:3001)│
                 └──────────────┬───────────────────┬───────────────────┬───────────┘
                                │                   │                   │
             Direct Browser     │    Direct Browser │    Client Admin   │
             Redirects          ▼    Redirects      ▼    UI & WebCrypto ▼
┌───────────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────────────┐
│     Ruby Demo Client          │ │ Rails Identity Provider │ │   Next.js Client Manager        │
│   (http://localhost:8080)     │ │ (http://localhost:3000) │ │   (http://localhost:3001)       │
├───────────────────────────────┤ ├─────────────────────────┤ ├─────────────────────────────────┤
│ • Zero Client Scopes          │ │ • User Login UI         │ │ • In-Browser RSA Key Generator  │
│ • Ephemeral DPoP Key Pair     │ │ • SHARED_SESSION_ID     │ │ • Server-Determined Scopes Config│
│ • Local Redis Session (DB 1)  │ │ • Writes user to Redis  │ │ • REST API (/api/clients)       │
│ • Back-Channel Logout Receiver│ └────────────┬────────────┘ └────────┬───────────────┬─────────┘
└───────────────┬───────────────┘              │                       │ S3 JSON Put   │
                │                              │                       ▼               │
   Backchannel  │ Backchannel PAR & Token      │ Shared Session  ┌─────────────┐       │ Redis Pub/Sub
   Logout Push  │ (DPoP + private_key_jwt)     │ Context         │ LocalStack  │       │ (Channel:
   (/oidc/...)  │                              │ (session:<id>)  │ S3 (4566)   │       │ oauth2:clients:reload)
                ▼                              ▼                 └──────┬──────┘       │
┌───────────────────────────────────────────────────────────────────────┼──────────────┼─────────┐
│                    Spring Authorization Server (http://localhost:9000)│              │         │
├───────────────────────────────────────────────────────────────────────┼──────────────┼─────────┤
│ • RFC 9126: Native Pushed Authorization Requests (PAR)                │ S3Client     │         │
│ • RFC 7523: Strict private_key_jwt Authentication (weak methods off)  │ GetObject    │         │
│ • RFC 9449: Strictly Enforced DPoP Tokens (Sender-Constrained cnf.jkt)│              │         │
│ • RFC 7636: Proof Key for Code Exchange (PKCE S256) strictly enforced │              │         │
│ • RFC 9207: Authorization Server Issuer Identification (Mix-Up defense)              │         │
│ • Server-Determined Authorization Scopes (zero client scope tampering)               │         │
│ • RFC 7009: Token Revocation & RFC 7662: Token Introspection                         │         │
│ • OpenID Connect Back-Channel Logout 1.0 (asynchronous signed logout_token)         │         │
│ • S3RegisteredClientRepository: Dynamic S3 client loader & in-memory cache <─────────┘         │
│ • ClientReloadRedisSubscriber: Real-time hot-reloading on Redis signal <───────────────────────┘
│ • SharedRedisSessionFilter: SSO bridge with Rails IdP via Redis DB 0                           │
└──────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                               │
                                               ▼
                                ┌──────────────────────────────┐
                                │         Redis Server         │
                                │    (localhost:6379)          │
                                ├──────────────────────────────┤
                                │ DB 0: Rails SSO & Spring JTI │
                                │ DB 1: Demo Client Sessions   │
                                │ Pub/Sub: Hot-Reload Channel  │
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
| **Config Mgmt** | **Multi-Tier Client Cache (L1-L3)** | Next.js writes client JSON to S3 (`oauth2-clients/clients/*.json`) and synchronizes Redis Hash `oauth2:clients:configs` with 30-day TTL. Spring loads registered clients from Redis on boot in < 5ms (zero S3 calls on warm restarts), with real-time hot-reloading via Redis Pub/Sub (`oauth2:clients:reload`). |

---

## Architectural Diagrams & Communication Flows

Comprehensive sequence diagrams, topology graphs, and communication flows are documented in [`docs/architecture/`](docs/architecture/README.md):

- [**System Topology & Component Communication**](docs/architecture/README.md): Full component interaction graph, communication channels, and port allocations.
- [**OAuth 2.1 Code Flow with PAR, DPoP & Rails SSO**](docs/architecture/oauth2_par_dpop_flow.md): Step-by-step sequence diagram from initial browser click to DPoP-protected UserInfo query.
- [**Multi-Tier Client Configuration & Hot-Reload Flow**](docs/architecture/client_config_and_caching_flow.md): Sequence diagrams covering warm reboots (< 5ms zero-S3 boot), cold start fallback, dynamic client creation, and immediate deletion/revocation.
- [**Token Lifecycle, Revocation & OIDC Back-Channel Logout**](docs/architecture/token_lifecycle_and_logout_flow.md): Sequence diagrams for RFC 7009 token revocation, RFC 7662 introspection, and OIDC Back-Channel Logout 1.0 push.

---

## Services & Ports

| Service | Port | Description | Technology Stack |
|---|---|---|---|
| **`client-manager`**| `3001` | OAuth 2.1 Client Config Manager UI | Next.js 15, React 19, Tailwind CSS, S3, Redis |
| **`demo-client`** | `8080` | Interactive OAuth 2.1 client & UI | Ruby 4.0, Puma, Rack, Redis DB 1 |
| **`rails-app`** | `3000` | External Identity Provider (IdP) | Ruby on Rails 7, Redis DB 0 |
| **`spring-auth-server`**| `9000` | OAuth 2.1 & OIDC Authorization Server | Spring Boot 4.0.8, Spring Security 7.0.7, Java 25 |
| **`localstack`** | `4566` | Local AWS S3 service emulation | LocalStack 3.8 (S3: `oauth2-clients`) |
| **`poc-redis`** | `6379` | Shared Redis session, cache & pub/sub | Redis 7 Alpine |

---

## Quick Start & Running Services

### Prerequisites
- **mise** (or Java 25 + Ruby 4.0.6 installed locally), or **Docker & Docker Compose**.
- Running Redis instance on `localhost:6379` and LocalStack on `localhost:4566`.

### Option A: Running with Docker Compose
To run the full stack in Docker containers:
```bash
docker compose up --build -d redis localstack rails-app spring-auth-server client-manager demo-client
```
- Access the **Client Config Manager** at: **`http://localhost:3001`**
- Access the **Demo Client** at: **`http://localhost:8080`**

### Option B: Running Locally with Mise / Native CLI

1. **Start Redis & LocalStack**:
   ```bash
   docker compose up -d redis localstack
   bash localstack/seed-demo-client.sh
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

5. **Start Client Config Manager (Port 3001)**:
   ```bash
   cd client-manager
   pnpm install
   pnpm start -p 3001
   ```

---

## Running the Automated Functional Test Suites

A comprehensive, multi-step automated test harness is provided across all subprojects, verifying both core OAuth 2.1 security features and real-time S3 dynamic configuration:

1. **Suite 1: OAuth 2.1 & OIDC Advanced Security Features (`test_oauth_security_features.rb`)**
   - Zero-scope client authorization & server-determined scope assignment
   - RFC 9126 Pushed Authorization Requests (PAR)
   - RFC 9207 Authorization Server Issuer Identification (Mix-Up attack defense)
   - Rejection of weak client authentication (`client_secret_basic`, `client_secret_post`)
   - Mandatory RFC 9449 DPoP proof enforcement & `cnf.jkt` sender-constraint verification
   - RFC 7009 token revocation & RFC 7662 token introspection
   - OpenID Connect Back-Channel Logout 1.0 (signed `logout_token` JWS delivery & session eviction)

2. **Suite 2: Dynamic S3 Client Config & Redis Hot-Reload (`test_s3_dynamic_client_reload.rb`)**
   - Next.js REST API & LocalStack S3 bucket connectivity
   - On-the-fly 2048-bit RSA key pair generation & client creation via `POST /api/clients`
   - Real-time Redis Pub/Sub notification (`oauth2:clients:reload`) & Spring dynamic reload
   - Dynamic client authentication (PAR + PKCE + `private_key_jwt` + DPoP token exchange)
   - Dynamic client deletion via `DELETE /api/clients/:id` & immediate HTTP 401 revocation

### Run from any component directory:

```bash
# From Spring Authorization Server:
bash spring-auth-server/functional_tests/run_functional_tests.sh

# From Demo Client:
bash demo-client/functional_tests/run_functional_tests.sh

# From Client Manager:
bash client-manager/functional_tests/run_functional_tests.sh
```

---

## Project Structure

```
.
├── docker-compose.yml              # Multi-container orchestration (LocalStack, Redis, Spring, Rails, Demo, Manager)
├── README.md                       # Comprehensive platform documentation
├── docs/                           # Architecture diagrams and detailed sequence flows
│   └── architecture/
│       ├── README.md               # Topology, communication matrix, and architecture index
│       ├── oauth2_par_dpop_flow.md # End-to-end PAR + DPoP + PKCE + Rails SSO sequence diagram
│       ├── client_config_and_caching_flow.md # Multi-tier L1-L3 cache & hot-reload sequence diagrams
│       └── token_lifecycle_and_logout_flow.md# Revocation, Introspection, and Backchannel Logout flows
├── localstack/                     # LocalStack S3 initialization & seeding
│   ├── init/01-init-s3.sh          # Auto-creates oauth2-clients bucket and seeds demo-client.json
│   └── seed-demo-client.sh         # Standalone S3 seeder script
├── client-manager/                 # Next.js 15 OAuth 2.1 Client Configuration Manager
│   ├── app/                        # Dashboard UI, client modals, raw JSON viewer
│   ├── app/api/clients/            # S3 client CRUD endpoints & Redis reload notifier
│   ├── functional_tests/           # Client manager copy of functional test suite
│   │   ├── run_functional_tests.sh
│   │   ├── test_oauth_security_features.rb
│   │   └── test_s3_dynamic_client_reload.rb
│   └── lib/s3.ts                   # AWS SDK v2 client, S3 bucket operations, Redis Pub/Sub
├── spring-auth-server/             # Spring Boot 4 / Spring Security 7 Authorization Server
│   ├── functional_tests/           # Automated security test suite & shell runner
│   │   ├── run_functional_tests.sh
│   │   ├── test_oauth_security_features.rb
│   │   └── test_s3_dynamic_client_reload.rb
│   ├── pom.xml
│   └── src/main/java/com/example/authserver/
│       ├── client/
│       │   ├── S3RegisteredClientRepository.java    # S3 client loader & in-memory cache
│       │   ├── ClientReloadRedisSubscriber.java    # Listens to oauth2:clients:reload
│       │   └── ClientConfigDto.java                 # Jackson DTO mapping S3 JSON schema
│       ├── config/
│       │   ├── AuthorizationServerConfig.java       # Strict converters, PAR, DPoP, revocation
│       │   ├── S3ClientConfig.java                  # AWS SDK v2 S3Client bean with LocalStack endpoint
│       │   ├── KeyConfig.java                       # RSA signing keys & JWK Source
│       │   ├── TokenCustomizerConfig.java           # DPoP cnf.jkt binding & custom claims
│       │   └── ExternalLoginAuthenticationEntryPoint.java # SSO redirect to Rails IdP
│       └── security/
│           ├── OidcBackChannelLogoutService.java    # Dispatches signed logout_token JWS
│           └── SharedRedisSessionFilter.java        # Bridges Rails shared session to Spring context
├── rails-app/                      # Ruby on Rails 7 Identity Provider
│   ├── app/controllers/sessions_controller.rb      # Writes session:<uuid> to Redis
│   ├── app/views/sessions/new.html.erb             # User login form
│   └── README.md                                   # Rails IdP architecture & security documentation
└── demo-client/                    # Modern Ruby OAuth 2.1 Demo Client (Puma + Redis)
    ├── app/
    │   ├── controllers/auth_controller.rb           # PAR, DPoP, token exchange, refresh, logout
    │   ├── services/par_oauth2_client.rb            # DPoP proofs, private_key_jwt assertions
    │   └── views/auth/                              # Index UI with feature checklist, Profile UI
    ├── functional_tests/                            # Client copy of functional test suite
    │   ├── run_functional_tests.sh
    │   ├── test_oauth_security_features.rb
    │   └── test_s3_dynamic_client_reload.rb
    └── README.md                                   # Demo client architecture & security features
```
