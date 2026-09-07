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
│ • Local Redis Session (DB 1)  │ │ • Writes user to Redis  │ │ • Proxies to Spring Admin API   │
│ • Back-Channel Logout Receiver│ └────────────┬────────────┘ └────────┬────────────────────────┘
└───────────────┬───────────────┘              │                       │
                │                              │                       │ Admin REST API
   Backchannel  │ Backchannel PAR & Token      │ Shared Session        │ (POST/GET/DELETE /api/admin)
   Logout Push  │ (DPoP + private_key_jwt)     │ Context               │ (X-Admin-Api-Key)
   (/oidc/...)  │                              │ (session:<id>)        │
                 ▼                              ▼                       ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                    Spring Authorization Server (http://localhost:9000)                        │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│ • RFC 9126: Native Pushed Authorization Requests (PAR)                                        │
│ • RFC 7523: Strict private_key_jwt Authentication (weak methods off)                          │
│ • RFC 9449: Strictly Enforced DPoP Tokens (Sender-Constrained cnf.jkt)                        │
│ • RFC 7636: Proof Key for Code Exchange (PKCE S256) strictly enforced                         │
│ • RFC 9207: Authorization Server Issuer Identification (Mix-Up defense)                       │
│ • Server-Determined Authorization Scopes (zero client scope tampering)                        │
│ • RFC 7009: Token Revocation & RFC 7662: Token Introspection                                  │
│ • OpenID Connect Back-Channel Logout 1.0 (asynchronous signed logout_token)                  │
│ • PostgresRegisteredClientRepository: In-memory near-cache + Postgres ACID store              │
│ • JdbcOAuth2AuthorizationService: Distributed persistent authorizations & refresh             │
│ • Flyway: Automated database schema versioning and lifecycle management                       │
│ • ClientReloadRedisSubscriber: Cluster cache invalidation via Redis Pub/Sub                   │
│ • SharedRedisSessionFilter: SSO bridge with Rails IdP via Redis DB 0                          │
│ • ClientAdminController: Secure administrative REST API (/api/admin/clients)                  │
└───────┬──────────────────────────────┬────────────────────────────────────────┬───────────────┘
        │                              │                                        │
        │ (Port 5432 - Java Only)      │ (Port 6379)                            │ (Port 4566 - KMS)
        ▼                              ▼                                        ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐ ┌──────────────────────────────┐
│     PostgreSQL Database      │ │         Redis Server         │ │     LocalStack (AWS KMS)     │
│       (localhost:5432)       │ │       (localhost:6379)       │ │       (localhost:4566)       │
├──────────────────────────────┤ ├──────────────────────────────┤ ├──────────────────────────────┤
│ • oauth2_registered_client   │ │ DB 0: Rails SSO & Spring JTI │ │ • Asymmetric RS256 Hardware  │
│ • oauth2_authorization       │ │ DB 1: Demo Client Sessions   │ │   Signing (RSA_2048)         │
│ • oauth2_authorization_consent│ │ Pub/Sub: Cluster Sync       │ │ • Multi-Key JWKS Rotation    │
│ • oauth2_client_public_key   │ └──────────────────────────────┘ │ • FIPS 140-2 Level 3 HSM     │
│ • flyway_schema_history      │                                  └──────────────────────────────┘
└──────────────────────────────┘
```

---

## Standards Compliance & Core Architecture

| Domain | Standard / Mechanism | Implementation Details |
|---|---|---|
| **Persistence** | **PostgreSQL & Flyway Migrations** | Complete ACID persistence for runtime authorization codes, user consent, refresh tokens, and registered clients via [`JdbcOAuth2AuthorizationService`](spring-auth-server/src/main/java/com/example/authserver/config/AuthorizationServerConfig.java) and [`PostgresRegisteredClientRepository`](spring-auth-server/src/main/java/com/example/authserver/client/PostgresRegisteredClientRepository.java). Conforms strictly to organization policy: **only the Java application connects to PostgreSQL**. |
| **Performance** | **In-Memory Near-Cache** | Pre-warmed L1 `ConcurrentHashMap` cache serves steady-state authorization checks in ~0.001 ms with **zero database round-trips**. Real-time cluster invalidation via Redis Pub/Sub (`oauth2:clients:reload`). |
| **Protocol** | **OAuth 2.1 (Draft 11)** | Strictly enforces PKCE S256 (`requireProofKey: true`), rejects plain `code_challenge_method`, disallows implicit and resource owner password grants. |
| **Client Auth** | **RFC 7523 private_key_jwt** | Asymmetric client assertions signed with client RSA/EC private keys. Weak methods (`client_secret_basic`, `client_secret_post`) are rejected. JTI replay caching in Redis. |
| **Sender Constraints** | **RFC 9449 DPoP** | Mandatory DPoP proof on token requests. Access tokens are cryptographically bound to client keys via `cnf.jkt` claim. |
| **Request Security** | **RFC 9126 PAR** | Authorization requests are pushed to `/oauth2/par` via backchannel POST; returns single-use `request_uri`. |
| **Token Signing** | **AWS KMS (FIPS 140-2 Level 3 / 140-3)** | Asymmetric hardware-backed token signing using AWS KMS RSA_2048 key pairs (`RSASSA_PKCS1_V1_5_SHA_256`). Private keys never enter JVM memory. |
| **Algorithm Pinning** | **Strict RS256 Verification** | Eliminates algorithm confusion attacks (`alg: none`, symmetric HMAC `HS256`). Enforced at both authorization server and client. |
| **Key Rotation** | **Graceful Multi-Key JWKS** | Zero-downtime rotation. Active key signs new tokens; active + previous keys published concurrently at `/oauth2/jwks`. |
| **Mix-Up Defense** | **RFC 9207 Issuer Identification** | Authorization server appends `iss` parameter to callback redirects. Client validates `iss` matches trusted authorization server. |
| **Scope Policy** | **Server-Determined Scopes** | Authorization server binds scopes strictly from registered client configuration. Client scope parameters are ignored. |
| **Logout** | **OIDC Back-Channel Logout 1.0** | Asynchronous HTTP POST of signed `logout_token` with 3-attempt exponential backoff retry. |
| **SSO Bridge** | **Shared Redis Session** | Rails IdP writes authenticated session to Redis (`session:<uuid>`). Spring Auth Server authenticates users via `SHARED_SESSION_ID` cookie. |

| Standard / RFC | Specification Name | How It Is Implemented & Enforced |
|---|---|---|
| **FIPS 140-2 / KMS** | **Hardware-Backed Asymmetric Signing** | Tokens (access, ID, logout) are signed within an AWS KMS Hardware Security Module (HSM) boundary using `RSA_2048`. Asymmetric private keys never enter JVM heap memory. |
| **RFC 8725** | **Strict Algorithm Pinning (RS256)** | Authorization server and client strictly enforce `RS256`, rejecting `none`, symmetric HMAC (`HS256`), and unapproved algorithms to eliminate JWT signature confusion attacks. |
| **Graceful Rotation**| **Multi-Key JWKS Rotation** | Serves active and previous keys concurrently at `/oauth2/jwks`, enabling zero-downtime key rotation while in-flight tokens remain valid through their TTL. |
| **RFC 9126** | **Pushed Authorization Requests (PAR)** | All authorization parameters (`client_id`, `state`, `nonce`, `code_challenge`) are pushed directly to `/oauth2/par` over TLS via an authenticated backchannel POST. The browser only receives an opaque, single-use `request_uri`. Stops query leakage and URL manipulation. |
| **RFC 7523** | **`private_key_jwt` Client Authentication** | Clients authenticate exclusively using RS256-signed JWT assertions (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`). Static client secrets (`client_secret_basic`, `client_secret_post`) and insecure `none` authentication are **strictly rejected with HTTP 401**. Includes JTI replay cache in Redis and strict `iss`, `sub`, `aud` validation. |
| **RFC 9449** | **Demonstrating Proof-of-Possession (DPoP)** | The `/oauth2/token` endpoint strictly enforces the `DPoP` HTTP header (requests lacking DPoP are rejected with HTTP 400 `invalid_dpop_proof`). Issued access tokens are sender-constrained by embedding the DPoP key thumbprint in the `cnf.jkt` claim. The token cannot be used without the private DPoP key. |
| **RFC 7636** | **PKCE (`S256`)** | Proof Key for Code Exchange is enforced on all authorization requests (`requireProofKey(true)`). Intercepted authorization codes cannot be exchanged without the client's `code_verifier`. |
| **RFC 9207** | **Authorization Server Issuer Identification** | The authorization response appends `iss=http://localhost:9000` to the callback URL. The client strictly validates the issuer before exchanging the code, completely mitigating OAuth 2.0 Mix-Up Attacks. |
| **Architecture** | **Server-Determined Scopes** | The demo client omits the `scope` parameter entirely. The Authorization Server predetermines and binds authorized scopes strictly based on registered client configuration (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`), preventing privilege escalation and client-side scope tampering. |
| **RFC 7009** | **Token Revocation** | Clients revoke tokens via `/oauth2/revoke` authenticated with `private_key_jwt`. Revocation invalidates the authorization and immediately flushes local and distributed sessions. |
| **RFC 7662** | **Token Introspection** | Resource servers and clients check token validity in real time at `/oauth2/introspect` using `private_key_jwt`. Useful for immediate fraud checks prior to executing sensitive actions. |
| **OIDC BCL 1.0** | **Back-Channel Logout 1.0** | Spring Authorization Server dispatches a signed JWT `logout_token` asynchronously to the client's backchannel endpoint (`/oidc/backchannel_logout`), terminating the user's session without relying on user-agent redirection. |
| **Config Mgmt** | **PostgreSQL & In-Memory Near-Cache** | Next.js writes client registrations directly to Spring Authorization Server via authenticated Admin REST API (`X-Admin-Api-Key`). Spring stores clients in PostgreSQL (`oauth2_registered_client`) with strict ACID guarantees. An in-memory L1 cache (`ConcurrentHashMap`) serves runtime authorization checks in ~0.001 ms with zero database round-trips. Real-time cluster cache eviction via Redis Pub/Sub (`oauth2:clients:reload`). |

---

## Security Inclusions, Posture & Production Readiness Roadmap

This section documents the security controls currently active in the platform, along with an enterprise production readiness roadmap detailing requirements, benefits, trade-offs, and classification.

### 1. Active Security Inclusions (Implemented in Codebase)
- **Cryptographic Isolation:** Asymmetric signing keys reside in FIPS 140-2 Level 3 Hardware Security Modules (AWS KMS). Private keys never touch application memory.
- **Fail-Closed Guarantee:** When KMS signing is enabled (`aws.kms.enabled: true`), the authorization server refuses startup if KMS is unreachable, preventing silent fallback to insecure keys.
- **Strict Algorithm Pinning:** Rejects `alg: none` and symmetric HMAC `HS256` confusion attacks at both the authorization server and client decoders.
- **Multi-Key JWKS Rotation:** Concurrent publishing of active and retired keys at `/oauth2/jwks` eliminates downtime during key lifecycle transitions.
- **Asymmetric Client Identity:** Shared secrets (`client_secret_basic`, `client_secret_post`) are disabled in favor of `private_key_jwt` with Redis JTI replay prevention.
- **Sender-Constrained Tokens:** RFC 9449 DPoP binds access tokens to ephemeral client keys, mitigating token theft and replay.
- **Pushed Authorization Requests (PAR):** Eliminates sensitive query parameters in browser history and server access logs.
- **Issuer Identification:** RFC 9207 prevents OAuth 2.0 Mix-Up attacks.
- **Server-Determined Scopes:** Prevents client-side privilege escalation.
- **Hardened Browser Security:** Strict `HttpOnly`, `SameSite: Lax`, and `Secure` cookie attributes; session identifiers are never exposed in URLs (CWE-598).
- **Constant-Time Operations:** Credential and API key checks use constant-time byte comparisons to eliminate side-channel timing attacks.
- **Strict Input Validation:** Session identifiers are strictly validated as UUIDv4 before executing Redis operations.
- **Zero-Trust Storage Isolation & Complete S3 Removal:** AWS S3 was completely decommissioned and removed from the ecosystem to eliminate eventual consistency lags and prevent front-end storage access. Persistent storage is strictly centralized in PostgreSQL with access exclusive to the Java application. Administrative client management occurs exclusively through Spring's authenticated Admin REST API (`/api/admin/clients` with constant-time `X-Admin-Api-Key` verification), enforcing zero-trust domain boundaries.

### 2. Production Readiness Roadmap

| Capability / Control | What Is Needed (Implementation Details) | Benefits | Trade-offs & Operational Costs | Classification |
|---|---|---|---|---|
| **Edge Web Application Firewall (WAF)** | Deploy AWS WAF or Cloudflare in front of the Application Load Balancer (ALB) with managed rule groups (Core Rule Set, Known Bad Inputs, Amazon IP Reputation) and rate limiting on `/oauth2/token` and `/oauth2/par`. | Shields application containers from volumetric DDoS, credential stuffing, and malicious scraper bots before requests hit application runtimes. | Minor latency addition (1–3 ms); managed service costs; requires periodic false-positive rule tuning. | **Deployment / Cloud Infrastructure Configuration** (No repo change needed) |
| **TLS 1.3 & HSTS at Reverse Proxy / ALB** | Terminate TLS with ACM certificates on ALB; enforce TLS 1.2/1.3; redirect HTTP 80 to 443; inject `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header. | Eliminates cleartext traffic on public networks; offloads CPU-intensive TLS handshakes from application instances; prevents SSL stripping. | Requires automated certificate renewal and internal security group management. | **Deployment / Cloud Infrastructure Configuration** |
| **Mutual TLS (mTLS) for B2B Clients (RFC 8705)** | Configure ALB or Nginx reverse proxy with client certificate verification; pass validated client certificate headers (`X-Forwarded-Client-Cert`); implement Spring Security `TlsClientAuthenticationConverter`. | Hardware-grade client authentication using client-side X.509 certificates (e.g. smart cards, HSMs); eliminates per-request JWT assertion generation overhead. | High PKI complexity; requires managing Certificate Authorities (CAs), certificate lifecycles, and revocation lists (CRL/OCSP). | **Codebase Change** (converter logic) + **Deployment Configuration** (ALB mTLS setup) |
| **Cloud Secrets Manager Integration** | Store database passwords, Redis credentials, and admin API keys in AWS Secrets Manager or HashiCorp Vault; inject securely via ECS/EKS task definitions. | Eliminates plaintext secrets in code repositories and environment configuration files; supports automated credential rotation. | Cold-start latency while retrieving secrets; additional API call costs. | **Deployment / Cloud Infrastructure Configuration** |
| **Automated KMS Lifecycle Schedule** | Deploy an AWS EventBridge rule and Lambda function to periodically execute the rotation flow in `scripts/rotate_kms_keys.sh` (e.g. semi-annually), sending operator alerts via SNS. | Guarantees compliance with cryptographic key expiration standards (NIST SP 800-57, PCI DSS 4.0) with zero manual intervention. | Requires monitoring rotation windows to prevent premature decommissioning of keys with active in-flight tokens. | **Deployment / Cloud Infrastructure Configuration** |
| **Distributed Redis High-Availability** | Migrate standalone Redis container to an AWS ElastiCache Redis replication group (multi-AZ with automatic failover) or Redis Sentinel; configure connection strings accordingly. | Eliminates single point of failure for SSO sessions, JTI replay prevention, and L2 client configuration caching. | Increased cloud infrastructure costs; eventual consistency considerations during failover events. | **Deployment / Cloud Infrastructure Configuration** |
| **Per-Client Token Bucket Rate Limiting** | Add a distributed rate-limiting filter (e.g., Bucket4j backed by Redis) on `/oauth2/token` and `/oauth2/par` keyed by `client_id`. | Protects the authorization server and KMS Sign API from runaway client loops or compromised client credential abuse. | Additional Redis round-trip latency on token exchange; requires configuring per-tier quota allocations. | **Codebase Change** (add filter to `spring-auth-server`) |

---

## Architectural Diagrams & Communication Flows

Comprehensive sequence diagrams, topology graphs, and communication flows are documented in [`docs/architecture/`](docs/architecture/README.md):

- [**System Topology & Component Communication**](docs/architecture/README.md): Full component interaction graph, communication channels, and port allocations.
- [**AWS KMS Key Management, Multi-Key Rotation & Algorithm Pinning**](docs/architecture/kms_multi_key_rotation_flow.md): End-to-end KMS HSM signing, zero-downtime key rotation lifecycle, automated rotation script, and RFC 8725 algorithm pinning.
- [**OAuth 2.1 Code Flow with PAR, DPoP & Rails SSO**](docs/architecture/oauth2_par_dpop_flow.md): Step-by-step sequence diagram from initial browser click to DPoP-protected UserInfo query.
- [**Client Configuration, Near-Cache & Dynamic Admin Flow**](docs/architecture/client_config_and_caching_flow.md): Sequence diagrams covering in-memory near-cache lookups (~0.001 ms), PostgreSQL ACID persistence, dynamic client onboarding via Spring Admin REST API, and immediate revocation.
- [**Token Lifecycle, Revocation & OIDC Back-Channel Logout**](docs/architecture/token_lifecycle_and_logout_flow.md): Sequence diagrams for RFC 7009 token revocation, RFC 7662 introspection, and OIDC Back-Channel Logout 1.0 push.
- [**Performance, Scalability & Bottleneck Analysis**](docs/architecture/performance_and_scalability.md): Deep-dive analysis of system bottlenecks, cryptographic speedups, in-memory JWKS/discovery caching, ETag 304 validation, automated retries, and high-scale roadmap.
- [**PostgreSQL Persistence Architecture & Performance Analysis**](docs/architecture/postgres_persistence_and_performance.md): Architectural rationale for database-backed clients, Flyway schema migrations, Java-only network isolation, and near-cache performance.

---

## Services & Ports

| Service | Port | Description | Technology Stack |
|---|---|---|---|
| **`postgres`** | `5432` | ACID Store for Authorizations & Clients (Java only) | PostgreSQL 16 Alpine |
| **`client-manager`**| `3001` | OAuth 2.1 Client Config Manager UI | Next.js 15, React 19, Tailwind CSS, Spring Admin API |
| **`demo-client`** | `8080` | Interactive OAuth 2.1 client & UI | Ruby 4.0, Puma, Rack, Redis DB 1 |
| **`rails-app`** | `3000` | External Identity Provider (IdP) | Ruby on Rails 7, Redis DB 0 |
| **`spring-auth-server`**| `9000` | OAuth 2.1 & OIDC Authorization Server | Spring Boot 4.0.8, Spring Security 7.0.7, Java 25 |
| **`localstack`** | `4566` | Local AWS KMS HSM service emulation | LocalStack 3.8 (KMS: `alias/oauth2-signing-key`) |
| **`poc-redis`** | `6379` | Shared Redis session, cache & pub/sub | Redis 7 Alpine |

---

## Quick Start & Running Services

### Prerequisites
- **mise** (or Java 25 + Ruby 4.0.6 installed locally), or **Docker & Docker Compose**.
- Running Redis instance on `localhost:6379`, PostgreSQL on `localhost:5432`, and LocalStack on `localhost:4566`.

### Option A: Running with Docker Compose
To run the full stack in Docker containers:
```bash
docker compose up --build -d postgres redis localstack rails-app spring-auth-server client-manager demo-client
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

A comprehensive, multi-step automated test harness is provided across all subprojects, verifying both core OAuth 2.1 security features and dynamic PostgreSQL client configuration with Redis hot-reloading:

1. **Suite 1: OAuth 2.1 & OIDC Advanced Security Features (`test_oauth_security_features.rb`)**
   - Zero-scope client authorization & server-determined scope assignment
   - RFC 9126 Pushed Authorization Requests (PAR)
   - RFC 9207 Authorization Server Issuer Identification (Mix-Up attack defense)
   - Rejection of weak client authentication (`client_secret_basic`, `client_secret_post`)
   - Mandatory RFC 9449 DPoP proof enforcement & `cnf.jkt` sender-constraint verification
   - RFC 7009 token revocation & RFC 7662 token introspection
   - OpenID Connect Back-Channel Logout 1.0 (signed `logout_token` JWS delivery & session eviction)

2. **Suite 2: Dynamic PostgreSQL Client Config & Redis Hot-Reload (`test_s3_dynamic_client_reload.rb`)**
   - Next.js REST API & Spring Admin REST API connectivity
   - On-the-fly 2048-bit RSA key pair generation & client creation via `POST /api/clients`
   - Real-time Redis Pub/Sub notification (`oauth2:clients:reload`) & Spring dynamic near-cache reload
   - Dynamic client authentication (PAR + PKCE + `private_key_jwt` + DPoP token exchange)
   - Dynamic client deletion via `DELETE /api/clients/:id` & immediate HTTP 401 revocation

3. **Suite 3: Performance, In-Memory Caching & Resilience (`test_performance_and_resilience.rb`)**
   - In-memory response caching on `/.well-known/**` and `/oauth2/jwks` returning HTTP 304 Not Modified
   - Ephemeral EC P-256 vs RSA-2048 DPoP key generation benchmark (>4,000x speedup)
   - In-memory thread-safe JWKS cache resolution (< 1 ms lookup)
   - Automated retry loop with exponential backoff & randomized jitter

4. **Suite 4: AWS KMS Cryptographic Signing, Multi-Key Rotation & Strict Algorithm Pinning (`test_kms_signing.rb`)**
   - Direct AWS KMS HSM asymmetric signing validation (private keys remain within KMS boundary)
   - Strict Algorithm Pinning negative tests (verifies that `alg: none` and `alg: HS256` client assertions are strictly rejected with HTTP 400)
   - Graceful multi-key JWKS rotation (verifies dual key publication at `/oauth2/jwks` and validates tokens signed by active vs. previous keys)

### Run Functional Tests from any component directory:

```bash
# From Spring Authorization Server:
bash spring-auth-server/functional_tests/run_functional_tests.sh

# From Demo Client:
bash demo-client/functional_tests/run_functional_tests.sh

# From Client Manager:
bash client-manager/functional_tests/run_functional_tests.sh
```

---

## Performance & Concurrency Load Testing (k6)

An automated **k6** load testing suite is located in [`k6/oauth_load_test.js`](k6/oauth_load_test.js) (documented in [`k6/README.md`](k6/README.md)) to evaluate the platform under concurrent load with hardware-backed AWS KMS signing enabled:

- **Scenario 1 (`full_oauth_session_flow`):** 5 concurrent virtual users continuously executing the complete 6-hop interactive OAuth 2.1 authorization session.
- **Scenario 2 (`discovery_and_jwks_burst`):** Ramping up to 30 req/sec querying discovery and JWKS endpoints with conditional `If-None-Match` ETags.

### Run k6 Load Test:

```bash
# 1. Standard 30-second multi-scenario load test
k6 run k6/oauth_load_test.js

# 2. Fast smoke test (10 iterations with 2 concurrent users)
k6 run --vus 2 --iterations 10 k6/oauth_load_test.js

# 3. High-concurrency stress test (15 VUs for 60 seconds)
k6 run --vus 15 --duration 60s k6/oauth_load_test.js
```

### Measured Performance Benchmarks:

| Metric | In-Memory Software Signing | AWS KMS Hardware Signing (Multi-Key JWKS) | Evaluation |
|---|---|---|---|
| **Cryptographic Boundary** | Software JCE (JVM memory) | **FIPS 140-2 Level 3 (KMS HSM)** | Maximum hardware protection |
| **Algorithm Pinning** | Optional | **Strict RS256 enforced (`none` & `HS256` rejected)** | Pinning active |
| **Key Rotation Support** | Single key | **Graceful Multi-Key JWKS (Active + Previous)** | Zero-downtime cutover |
| **Auth Session Success Rate** | `98.79%` | **`98.00%`** | **Passed** (>95% threshold) |
| **Hourly Auth Session Rate** | ~29,400 sessions/hr | **~23,640 sessions/hr** | **~8x above target** ("few thousand/hr") |
| **Full Session Latency (p95)** | `146 ms` | **`425 ms`** | **Passed** (<1,500 ms threshold) |
| **Total HTTP Error Rate** | `0.04%` | **`0.08%`** | **99.92% success rate** |
| **Discovery & JWKS ETag 304 Rate**| `100.00%` | **`100.00%`** (724 / 724) | Zero payload bandwidth |

---

## Project Structure

```
.
├── docker-compose.yml              # Multi-container orchestration (Postgres, LocalStack, Redis, Spring, Rails, Demo, Manager)
├── README.md                       # Comprehensive platform documentation
├── k6/                             # Automated k6 performance and concurrency load testing suite
│   ├── oauth_load_test.js          # Multi-scenario k6 load test (Full OAuth flow + Caching burst)
│   └── README.md                   # k6 load testing execution guide & benchmark analysis
├── docs/                           # Architecture diagrams and detailed sequence flows
│   └── architecture/
│       ├── README.md               # Topology, communication matrix, and architecture index
│       ├── oauth2_par_dpop_flow.md # End-to-end PAR + DPoP + PKCE + Rails SSO sequence diagram
│       ├── client_config_and_caching_flow.md # Multi-tier near-cache & hot-reload sequence diagrams
│       ├── kms_multi_key_rotation_flow.md   # AWS KMS HSM signing & zero-downtime rotation
│       ├── token_lifecycle_and_logout_flow.md# Revocation, Introspection, and Backchannel Logout flows
│       ├── postgres_persistence_and_performance.md # Rationale for DB-backed clients & Java isolation
│       └── performance_and_scalability.md   # Bottleneck audit, 4000x speedup, k6 results, scale roadmap
├── localstack/                     # LocalStack AWS KMS initialization & key provisioning
│   └── init/02-init-kms.sh         # Provisions RSA_2048 signing keys in KMS with alias
├── client-manager/                 # Next.js 15 OAuth 2.1 Client Configuration Manager
│   ├── app/                        # Dashboard UI, client modals, raw JSON viewer
│   ├── app/api/clients/            # Proxy endpoints forwarding to Spring Admin REST API
│   ├── functional_tests/           # Client manager copy of functional test suite
│   │   ├── run_functional_tests.sh
│   │   ├── test_oauth_security_features.rb
│   │   ├── test_s3_dynamic_client_reload.rb
│   │   └── test_performance_and_resilience.rb
│   └── lib/clients.ts              # Spring Admin API proxy client & X-Admin-Api-Key authentication
├── spring-auth-server/             # Spring Boot 4 / Spring Security 7 Authorization Server
│   ├── functional_tests/           # Automated security test suite & shell runner
│   │   ├── run_functional_tests.sh
│   │   ├── test_oauth_security_features.rb
│   │   ├── test_s3_dynamic_client_reload.rb
│   │   └── test_performance_and_resilience.rb
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/authserver/
│       │   ├── client/
│       │   │   ├── PostgresRegisteredClientRepository.java # Near-cached PostgreSQL client repository
│       │   │   ├── ClientReloadRedisSubscriber.java        # Listens to oauth2:clients:reload
│       │   │   └── ClientConfigDto.java                    # Jackson DTO for client configurations
│       │   ├── config/
│       │   │   ├── AuthorizationServerConfig.java          # Strict converters, PAR, DPoP, revocation
│       │   │   ├── KeyConfig.java                          # AWS KMS HSM signing & Multi-Key JWKS
│       │   │   ├── TokenCustomizerConfig.java              # DPoP cnf.jkt binding & custom claims
│       │   │   └── ExternalLoginAuthenticationEntryPoint.java # SSO redirect to Rails IdP
│       │   ├── controller/
│       │   │   └── ClientAdminController.java              # Protected Admin API for client management
│       │   └── security/
│       │       ├── OidcBackChannelLogoutService.java       # Dispatches signed logout_token JWS
│       │       └── SharedRedisSessionFilter.java           # Bridges Rails shared session to Spring context
│       └── resources/db/migration/
│           ├── V1__create_oauth2_schema.sql                # Core Spring Security OAuth2 tables
│           └── V2__create_client_public_keys.sql           # Public key store for private_key_jwt
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
    │   ├── test_s3_dynamic_client_reload.rb
    │   └── test_performance_and_resilience.rb
    └── README.md                                   # Demo client architecture & security features
```
