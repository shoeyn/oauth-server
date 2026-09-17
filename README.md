# Enterprise OAuth 2.1 & OpenID Connect (OIDC) Platform

A production-grade, hardened **OAuth 2.1 Authorization Server** and **OpenID Connect (OIDC)** ecosystem built with **Spring Boot 4 / Spring Security 7**, an external **Ruby on Rails** Identity Provider (IdP) with a **shared Redis session**, and a modern **Ruby/Puma Demo Client** featuring sender-constrained tokens, cryptographic client assertions, and real-time session management.

---

## Table of Contents

- [Executive Architecture Comparison: Basic OAuth 2.0 vs. Hardened Enterprise Platform](#executive-architecture-comparison-basic-oauth-20-vs-hardened-enterprise-platform)
- [Visual Architectural Blueprints (6 Diagram Dimensions)](#visual-architectural-blueprints-6-diagram-dimensions)
  - [1. Component Topology & Network Perimeter Architecture (Flowchart)](#1-component-topology--network-perimeter-architecture-flowchart)
  - [2. End-to-End Interactive Protocol Exchange (Sequence Diagram)](#2-end-to-end-interactive-protocol-exchange-sequence-diagram)
  - [3. Token & Session Lifecycle State Machine (State Diagram)](#3-token--session-lifecycle-state-machine-state-diagram)
  - [4. AWS KMS Multi-Key Rotation State Machine (State Diagram)](#4-aws-kms-multi-key-rotation-state-machine-state-diagram)
  - [5. PostgreSQL Relational Entity-Relationship Diagram (ERD)](#5-postgresql-relational-entity-relationship-diagram-erd)
  - [6. Two-Stage Defense-in-Depth Password Pipeline (Flowchart)](#6-two-stage-defense-in-depth-password-pipeline-flowchart)
- [Protocol Wire Formats & Cryptographic Payloads (HTTP Wire Reference)](#protocol-wire-formats--cryptographic-payloads-http-wire-reference)
  - [Hop 1: Pushed Authorization Request (RFC 9126 PAR)](#hop-1-pushed-authorization-request-rfc-9126-par)
  - [Hop 2: Cryptographically Signed Authorization Response (RFC 9221 JARM)](#hop-2-cryptographically-signed-authorization-response-rfc-9221-jarm)
  - [Hop 3: Sender-Constrained Token Exchange & Nonce Handshake (RFC 9449 DPoP)](#hop-3-sender-constrained-token-exchange--nonce-handshake-rfc-9449-dpop)
  - [Hop 4: Real-Time Token Introspection (RFC 7662) & Revocation (RFC 7009)](#hop-4-real-time-token-introspection-rfc-7662--revocation-rfc-7009)
  - [Hop 5: OpenID Connect Back-Channel Logout 1.0 (Signed logout_token JWS)](#hop-5-openid-connect-back-channel-logout-10-signed-logout_token-jws)
  - [Hop 6: Internal Authentication & Shared Redis SSO Session Contract](#hop-6-internal-authentication--shared-redis-sso-session-contract)
- [Standards Compliance & Core Architecture Matrix](#standards-compliance--core-architecture-matrix)
- [Security Inclusions, Posture & Production Readiness Roadmap](#security-inclusions-posture-production-readiness-roadmap)
  - [1. Active Security Inclusions (Implemented in Codebase)](#1-active-security-inclusions-implemented-in-codebase)
  - [2. Production Readiness Roadmap](#2-production-readiness-roadmap)
- [Architectural Deep Dives & Subsystem Index](#architectural-deep-dives--subsystem-index)
  - [Developer & Tester Guides](#developer--tester-guides)
- [Services & Ports](#services-ports)
- [Quick Start & Running Services](#quick-start-running-services)
  - [Prerequisites](#prerequisites)
  - [Option A: Running with Docker Compose (Recommended)](#option-a-running-with-docker-compose-recommended)
  - [Option B: Running Locally with Mise / Native CLI](#option-b-running-locally-with-mise-native-cli)
- [Connecting a New Client Application](#connecting-a-new-client-application)
- [Running the Automated Test Suites](#running-the-automated-test-suites)
  - [1. End-to-End Functional Test Suite (Cucumber)](#1-end-to-end-functional-test-suite-cucumber)
  - [2. Component Unit Test Suites & Code Coverage (100% Enforced)](#2-component-unit-test-suites--code-coverage-100-enforced)
  - [3. Static Analysis & Linting (RuboCop, Checkstyle, Spotless, Oxlint)](#3-static-analysis--linting-rubocop-checkstyle-spotless-oxlint)
- [Performance & Concurrency Load Testing (k6)](#performance-concurrency-load-testing-k6)
  - [Run k6 Load Test:](#run-k6-load-test)
  - [Measured Performance Benchmarks:](#measured-performance-benchmarks)
- [Project Structure](#project-structure)

---

## Executive Architecture Comparison: Basic OAuth 2.0 vs. Hardened Enterprise Platform

The table below contrasts standard **OAuth 2.0 (RFC 6749)** with this platform's hardened **OAuth 2.1 & FAPI-aligned Enterprise Profile**, detailing the specific threat vectors, architectural flaws, and enforced countermeasures implemented in code:

| Architectural Domain | Baseline OAuth 2.0 (RFC 6749) | Baseline Threat / Vulnerability | This Platform's Enforced Implementation | Governing Standard & Policy |
|---|---|---|---|---|
| **Authorization Request Transport** | Parameters (`client_id`, `scope`, `redirect_uri`, `state`) passed in front-channel browser URL query string. | **Query String Leakage (CWE-598)**: Parameters logged in browser history, HTTP referrers, proxy logs, and vulnerable to URL truncation or length limits. | **RFC 9126 PAR**: All authorization parameters pushed over TLS via authenticated back-channel `POST /oauth2/par`. Browser receives only an opaque, single-use `request_uri` (60s TTL). | **RFC 9126 (PAR)**<br/>`OAuth2AuthorizationServerConfigurer` |
| **Client Authentication** | Shared static secrets (`client_secret_basic`, `client_secret_post`) or unauthenticated public clients. | **Credential Exfiltration & Replay**: Static secrets checked into git, leaked in logs, or brute-forced. Vulnerable to credential stuffing without non-repudiation. | **RFC 7523 `private_key_jwt`**: Asymmetric client assertions signed with client RSA-2048 private key. Redis JTI cache (5m TTL) stops replay. Static secrets strictly rejected with `HTTP 401`. | **RFC 7523**<br/>`JwtClientAssertionAuthenticationProvider` |
| **Authorization Code Exchange** | Code sent in front-channel URL query string (`?code=XYZ`). | **Authorization Code Interception (CWE-200)**: Malicious apps or browser extensions intercept authorization codes before exchange. | **RFC 7636 PKCE S256**: Enforced on all requests (`requireProofKey: true`). Plain `code_challenge_method` rejected. Intercepted code cannot be exchanged without `code_verifier`. | **OAuth 2.1 Draft 11**<br/>**RFC 7636** |
| **Front-Channel Response Security** | Cleartext URL query parameters (`?code=...` or `?error=...&error_description=...`). | **Parameter Tampering & Phishing**: Response parameters modified in flight; attackers forge error responses or inject authorization codes. | **RFC 9221 JARM**: All authorization responses (codes and errors) signed into an RS256 JWS JWT by AWS KMS (`?response=<jwt>`). Plaintext query responses strictly rejected. | **RFC 9221 (JARM)**<br/>`JarmAuthorizationResponseHandler` |
| **Token Theft & Replay (Bearer Tokens)** | Bearer tokens (RFC 6750). Any party possessing the token can access protected resources. | **Token Exfiltration & Replay**: Leaked access tokens (via memory dumps, TLS termination proxies, or logs) allow arbitrary unauthorized impersonation. | **RFC 9449 DPoP**: Access tokens cryptographically sender-constrained to client public key thumbprint (`cnf.jkt`). Server-issued 60s Redis nonces enforce freshness via `HTTP 400 use_dpop_nonce`. | **RFC 9449 (DPoP)**<br/>`StrictDPoPTokenRequestConverter`<br/>`DPoPNonceFilter` |
| **Token & Code Substitution** | ID Token has no cryptographic binding to the issued access token or authorization code. | **Token Substitution Attack**: Attacker replaces access token in response with another valid token. | **OIDC Core Hashes**: Embedded SHA-256 left-half hashes `at_hash` (access token) and `c_hash` (auth code) in ID Token, cryptographically verified by client prior to session creation. | **OpenID Connect Core 1.0 §3.1.3.6** |
| **Authorization Server Mix-Up** | Clients interacting with multiple IdPs cannot verify which server generated the code. | **OAuth 2.0 Mix-Up Attack**: Attacker tricks client into sending authorization code to an attacker-controlled authorization server. | **RFC 9207 Issuer Identification**: AS returns explicit `iss` parameter and signs `iss` within JARM JWT. Client strictly asserts issuer identity match before code exchange. | **RFC 9207** |
| **Scope Governance & Privileges** | Client dictates requested scopes in authorization request. | **Client Privilege Escalation**: Malicious or misconfigured clients request unauthorized administrative scopes. | **Server-Determined Scopes**: Client scope parameter is completely ignored. Scopes are centrally governed and bound exclusively from PostgreSQL registered client config. | **Enterprise Security Policy**<br/>`ClientPreDeterminedScopeConverter` |
| **Cryptographic Signing Boundary** | Private RSA signing keys loaded into JVM heap memory from local filesystem `.pem` or `.jks`. | **Key Exfiltration via Heap Inspection**: Memory dumps, profilers, core dumps, or RCE vulnerabilities expose private signing keys. | **AWS KMS HSM Signing**: Asymmetric RSA-2048 private keys never leave AWS KMS Hardware Security Module (FIPS 140-2 Level 3 in real AWS). Token digest signing occurs via KMS RPC. | **FIPS 140-2 Level 3**<br/>`KmsRsaSigner` & `KmsJwtEncoder` |
| **Key Lifecycle & Rotation** | Hard cutover: replacing keys immediately breaks validation of in-flight active tokens. | **Service Downtime & Token Rejection**: In-flight access tokens rejected during rotation windows. | **Graceful Multi-Key JWKS Rotation**: Dual publication of active (`alias/oauth2-signing-key`) and previous (`alias/oauth2-signing-key-previous`) keys at `/oauth2/jwks` during overlap window. | **NIST SP 800-57**<br/>`KeyConfig` Multi-Key JWKS |
| **Algorithm Confusion Defense** | Decoders accept `alg: none` or symmetric HMAC `HS256` using public RSA keys. | **Signature Verification Bypass**: Well-known critical CVEs (CVE-2015-9235, etc.) where attacker signs arbitrary tokens with the server's public key. | **RFC 8725 Strict Algorithm Pinning**: Both Authorization Server and Client library enforce `alg == 'RS256'` strictly; all symmetric or unapproved algorithms rejected with fail-closed exception. | **RFC 8725 §3.1** |
| **Session Termination & Logout** | Front-channel redirect-based logout (`post_logout_redirect_uri` via browser). | **Incomplete Session Invalidation**: Fails if user closes browser, network drops, or third-party cookies are blocked by browser privacy controls. | **OIDC Back-Channel Logout 1.0**: AS asynchronously dispatches an RS256-signed `logout_token` JWS directly to client backchannel endpoints with 3-attempt exponential backoff. | **OpenID Connect Back-Channel Logout 1.0**<br/>`OidcBackChannelLogoutService` |
| **Credential Transport & Storage** | Raw plaintext passwords transmitted over network; stored with single unsalted or legacy hash. | **Network Credential Sniffing & Database Breach**: Interception on internal networks; offline GPU rainbow table attacks on database dumps. | **Two-Stage Password Pipeline**: Client tier SHA-256 pre-hash (raw password never crosses wire) $\rightarrow$ Server tier `BCrypt(cost=10)` adaptive salted storage. | **Defense-in-Depth**<br/>`UserAdminController` |
| **Perimeter & Administrative Isolation** | Administrative APIs co-located on public ports; protected only by web framework filters. | **SSRF & Accidental Exposure**: Direct exposure of administrative or debugging endpoints (`/actuator/*`, `/api/admin/*`) to the public internet. | **Dual-Zone Perimeter Isolation**: Nginx edge proxy exposes public OAuth routes on port 9000, blocking `/api/admin/*` and `/actuator/*` with `403 Forbidden`. Secondary `AdminApiKeyFilter` inside Spring. | **Zero-Trust Perimeter**<br/>`poc-nginx` & `AdminApiKeyFilter` |

---

## Visual Architectural Blueprints (6 Diagram Dimensions)

### 1. Component Topology & Network Perimeter Architecture (Flowchart)

```mermaid
flowchart TD
    subgraph Internet ["Public Network / Untrusted Zone"]
        UserBrowser["User Browser / Client Agent"]
        AdminBrowser["Admin Browser (Port 3001)"]
    end

    subgraph DMZ ["Edge Perimeter DMZ (Port 9000)"]
        Nginx["Nginx Reverse Proxy (poc-nginx :9000)<br/>• Public Path Routing: /oauth2/*, /.well-known/*, /connect/*<br/>• Edge Defense: Blocks /api/admin/* & /actuator/* (403 Forbidden)<br/>• Header Sanitization & Tracing"]
    end

    subgraph AppNet ["Private Application Network (Docker Internal)"]
        direction TB
        SpringAS["Spring Authorization Server (poc-spring-auth-server :9000 internal / :9001 bastion)<br/>• OAuth 2.1 Engine (PAR, DPoP, PKCE, JARM)<br/>• Admin REST API (Protected by AdminApiKeyFilter)<br/>• In-Memory L1 Near-Cache (ConcurrentHashMap)<br/>• OIDC Back-Channel Logout Service"]
        RailsIdp["Rails Identity Provider (poc-rails-app :3000)<br/>• User Authentication Form & Session Management<br/>• SHA-256 Client Password Pre-Hash<br/>• Writes session:UUID to Redis"]
        DemoClient["Demo Client Application (poc-demo-client :8080)<br/>• Thin UI Layer + oauth2_client_kit Gem<br/>• Back-Channel Logout Receiver (/oidc/backchannel_logout)<br/>• DPoP Key Generation & Nonce Management"]
        ClientManager["Client Manager UI (poc-client-manager :3001)<br/>• Next.js 16 + React 19 Admin Dashboard<br/>• WebCrypto 2048-bit RSA Key Pair Generator<br/>• Calls Spring Admin API with X-Admin-Api-Key"]
    end

    subgraph DataNet ["Isolated Infrastructure & Data Layer"]
        Postgres[("PostgreSQL 16 (poc-postgres :5432)<br/>• Strict Java-Only Access Policy<br/>• ACID Authorizations & Client Registrations<br/>• app_users Table with BCrypt Hashes<br/>• Flyway Versioned Migrations (V1-V4)")]
        Redis[("Redis 7 (poc-redis :6379)<br/>• DB 0: Rails SSO Sessions (session:UUID, 2h TTL)<br/>• DB 0: DPoP Single-Use Nonces (60s TTL)<br/>• DB 0: JTI Assertion Replay Prevention (5m TTL)<br/>• DB 0: Pub/Sub Cluster Invalidation (oauth2as:clients:reload)<br/>• DB 1: Demo Client Token Store")]
        KMS["AWS KMS / LocalStack (poc-localstack :4566)<br/>• RSA_2048 Asymmetric Signing Boundary<br/>• Key Aliases: alias/oauth2-signing-key & -previous<br/>• Private Keys NEVER Leave KMS HSM Boundary"]
    end

    %% External traffic
    UserBrowser -->|"HTTPS (Port 9000)"| Nginx
    UserBrowser -->|"HTTP (Port 8080)"| DemoClient
    AdminBrowser -->|"HTTP (Port 3001)"| ClientManager

    %% Edge Proxy forwards
    Nginx -->|"Proxy Pass (Public Endpoints)"| SpringAS

    %% App Interactions
    DemoClient -->|"1. Backchannel PAR / Token / Introspect (DPoP + private_key_jwt)"| Nginx
    UserBrowser -.->|"2. Frontchannel Authorize & Rails Login Redirect"| RailsIdp
    RailsIdp -->|"3. Pre-Hashed SHA-256 Auth (/api/admin/users/authenticate)"| SpringAS
    RailsIdp -->|"4. Writes Shared SSO Session (session:UUID)"| Redis
    SpringAS -->|"5. Reads SSO Session Context via SHARED_SESSION_ID Cookie"| Redis
    SpringAS -->|"6. Signed Back-Channel Logout Push (logout_token)"| DemoClient
    ClientManager -->|"Internal Admin REST API (X-Admin-Api-Key)"| SpringAS

    %% Persistence
    SpringAS -->|"ACID Client & Authz State (HikariCP)"| Postgres
    SpringAS -->|"JTI, DPoP Nonces, Pub/Sub Invalidation"| Redis
    SpringAS -->|"Asymmetric RS256 Digest Signing (RPC)"| KMS
    DemoClient -->|"Token Cache (DB 1)"| Redis
```

---

### 2. End-to-End Interactive Protocol Exchange (Sequence Diagram)

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Client as Demo Client (:8080)
    participant Nginx as Perimeter Proxy (:9000)
    participant Spring as Spring Auth Server (:9000/9001)
    participant Redis as Redis DB 0 (:6379)
    participant Rails as Rails IdP (:3000)
    participant KMS as AWS KMS HSM (:4566)

    %% ------------------------------------------------------------------------
    %% Phase 1: PAR Initiation
    %% ------------------------------------------------------------------------
    rect rgb(240, 248, 255)
    Note over User, KMS: Phase 1: Pushed Authorization Request (RFC 9126 PAR + RFC 7523 private_key_jwt)
    User->>Client: Click "Start Secure Login"
    activate Client
    Note over Client: 1. Generate PKCE code_verifier & S256 code_challenge<br/>2. Generate ephemeral DPoP EC key pair<br/>3. Sign private_key_jwt client assertion (RS256)<br/>4. Sign initial DPoP proof for /oauth2/par (ES256)<br/>5. Server-Determined Scopes: Omit client scope parameter
    Client->>Nginx: POST /oauth2/par (DPoP Header, private_key_jwt, PKCE, state, nonce)
    Nginx->>Spring: Proxy pass to backend /oauth2/par
    activate Spring
    Note over Spring: Validate private_key_jwt:<br/>• Match client public key from L1 near-cache (PostgreSQL)<br/>• Check iss == sub == client_id & aud == /oauth2/par<br/>• SETNX oauth2:jti:<jti> in Redis (5m TTL replay defense)
    Spring->>Redis: SETNX oauth2:jti:<jti>
    Note over Spring: Validate DPoP proof (htm=POST, htu=/oauth2/par)
    Spring-->>Client: HTTP 201 Created {"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60}
    deactivate Spring
    Note over Client: Cache flow state in Redis DB 1 (verifier, nonce, dpop_key)
    Client-->>User: HTTP 302 Redirect to /oauth2/authorize?client_id=demo-client&request_uri=urn:...
    deactivate Client
    end

    %% ------------------------------------------------------------------------
    %% Phase 2: Rails SSO Authentication
    %% ------------------------------------------------------------------------
    rect rgb(255, 250, 240)
    Note over User, KMS: Phase 2: Rails SSO Authentication & Two-Stage Password Pipeline
    User->>Nginx: GET /oauth2/authorize?client_id=demo-client&request_uri=urn:...
    Nginx->>Spring: Proxy pass /oauth2/authorize
    activate Spring
    Note over Spring: SharedRedisSessionFilter checks SHARED_SESSION_ID cookie.<br/>No session cookie present!
    Spring-->>User: HTTP 302 Redirect to http://localhost:3000/login?return_to=...
    deactivate Spring
    User->>Rails: GET /login?return_to=...
    Rails-->>User: Render Login Form
    User->>Rails: POST /login (email, password)
    activate Rails
    Note over Rails: Stage 1 Password Pre-Hash:<br/>digest = SHA-256(password)<br/>Plaintext NEVER crosses network boundary!
    Rails->>Spring: POST /api/admin/users/authenticate {email, password: digest} (X-Admin-Api-Key)
    activate Spring
    Note over Spring: Stage 2 Password Verification:<br/>1. Check is_fraud == false in app_users<br/>2. BCrypt.matches(digest, password_hash) (cost=10)
    Spring-->>Rails: HTTP 200 OK {id, email, status: "authenticated"}
    deactivate Spring
    Note over Rails: Mint session:UUID in Redis DB 0 (2h TTL)<br/>Set HttpOnly, SameSite=Lax SHARED_SESSION_ID cookie
    Rails->>Redis: SET session:<uuid> (user JSON payload, EX 7200)
    Rails-->>User: HTTP 302 Redirect to return_to with Set-Cookie: SHARED_SESSION_ID=<uuid>
    deactivate Rails
    end

    %% ------------------------------------------------------------------------
    %% Phase 3: JARM Authorization Grant
    %% ------------------------------------------------------------------------
    rect rgb(240, 255, 240)
    Note over User, KMS: Phase 3: Authorization Grant & RFC 9221 JARM Signed Response
    User->>Nginx: GET /oauth2/authorize?client_id=demo-client&request_uri=urn:... (Cookie: SHARED_SESSION_ID=<uuid>)
    Nginx->>Spring: Proxy pass /oauth2/authorize
    activate Spring
    Spring->>Redis: GET session:<uuid>
    Redis-->>Spring: User JSON (username, roles, sub)
    Note over Spring: SharedRedisSessionFilter authenticates SecurityContext.<br/>Consume single-use request_uri, generate authorization code.<br/>Construct JARM response payload (code, iss, aud, exp, state).
    Spring->>KMS: kms:Sign(JARM payload digest, RSASSA_PKCS1_V1_5_SHA_256)
    KMS-->>Spring: JARM RS256 Signature
    Note over Spring: Assemble signed JWS (?response=<JARM_JWT>)
    Spring-->>User: HTTP 302 Redirect to Demo Client callback: ?response=<JARM_JWT>
    deactivate Spring
    end

    %% ------------------------------------------------------------------------
    %% Phase 4: DPoP Token Exchange & Nonce Handshake
    %% ------------------------------------------------------------------------
    rect rgb(255, 245, 255)
    Note over User, KMS: Phase 4: JARM Verification & RFC 9449 DPoP Token Exchange
    User->>Client: GET /callback?response=<JARM_JWT>
    activate Client
    Note over Client: 1. Verify JARM JWT signature against Spring Auth Server JWKS<br/>2. Validate iss, aud (demo-client), exp, and state<br/>3. Extract authorization code from validated claims<br/>4. Sign private_key_jwt client assertion<br/>5. Attempt initial code exchange
    Client->>Nginx: POST /oauth2/token (Initial DPoP proof without nonce)
    Nginx->>Spring: Proxy pass /oauth2/token
    activate Spring
    Note over Spring: DPoPNonceFilter (RFC 9449 §8):<br/>• Client proof missing server nonce<br/>• Generate fresh server nonce in Redis (60s TTL)<br/>• Respond with HTTP 400 use_dpop_nonce challenge
    Spring-->>Client: HTTP 400 Bad Request (DPoP-Nonce: <nonce>, {"error": "use_dpop_nonce"})
    deactivate Spring
    Note over Client: Automatic Handshake Retry:<br/>Sign fresh DPoP proof embedding captured server nonce
    Client->>Nginx: POST /oauth2/token (DPoP proof with nonce, code, verifier, client_assertion)
    Nginx->>Spring: Proxy pass /oauth2/token
    activate Spring
    Note over Spring: 1. Validate & consume DPoP-Nonce from Redis (single-use)<br/>2. Validate private_key_jwt assertion<br/>3. Verify PKCE code_verifier against stored challenge<br/>4. Bind Server-Determined Scopes from PostgreSQL<br/>5. Embed DPoP thumbprint (cnf.jkt) in Access Token<br/>6. Embed at_hash & c_hash in ID Token
    Spring->>KMS: kms:Sign(Access Token & ID Token digests)
    KMS-->>Spring: RS256 Signatures
    Spring-->>Client: HTTP 200 OK {"token_type": "DPoP", "access_token": "...", "id_token": "...", "expires_in": 900}
    deactivate Spring
    Note over Client: Validate ID Token (signature, at_hash, c_hash)<br/>Store sender-constrained tokens in Redis DB 1
    Client-->>User: HTTP 302 Redirect to /profile
    deactivate Client
    end

    %% ------------------------------------------------------------------------
    %% Phase 5: Sender-Constrained Resource Access
    %% ------------------------------------------------------------------------
    rect rgb(245, 245, 245)
    Note over User, KMS: Phase 5: Sender-Constrained Resource Access (/userinfo)
    User->>Client: GET /profile
    activate Client
    Note over Client: Sign fresh DPoP proof for GET /userinfo
    Client->>Nginx: GET /userinfo (Authorization: DPoP <access_token>, DPoP: <proof>)
    Nginx->>Spring: Proxy pass /userinfo
    activate Spring
    Note over Spring: Validate token active & cnf.jkt matches client DPoP public key thumbprint
    Spring-->>Client: HTTP 200 OK (User Profile JSON)
    deactivate Spring
    Client-->>User: Render Profile UI with server-bound scopes & token claims
    deactivate Client
    end
```

---

### 3. Token & Session Lifecycle State Machine (State Diagram)

```mermaid
stateDiagram-v2
    [*] --> Code_Issued: User Authenticated at Rails IdP via SHA-256 + BCrypt
    Code_Issued --> Exchanged_DPoP: POST /oauth2/token with PKCE verifier + DPoP nonce + private_key_jwt
    
    state Exchanged_DPoP {
        [*] --> Active_Token: Bound via cnf.jkt thumbprint in Access Token
        Active_Token --> Introspected: RFC 7662 Real-time Query (/oauth2/introspect)
        Introspected --> Active_Token: active: true (SLA: sub-millisecond near-cache)
        Active_Token --> Refresh_Rotated: POST /oauth2/token (grant_type=refresh_token + DPoP)
        Refresh_Rotated --> Active_Token: Old refresh token invalidated; fresh pair minted
    }

    Active_Token --> Revoked_Client: RFC 7009 Token Revocation (/oauth2/revoke)
    Active_Token --> Fraud_Terminated: Admin flags is_fraud=true via UserAdminController
    Active_Token --> Natural_Expiry: TTL Expired (Access: 15m, Refresh: 24h, Session: 2h)

    state Fraud_Revocation_Pipeline {
        Fraud_Terminated --> Purge_Database: DELETE FROM oauth2_authorization WHERE principal_name = ?
        Purge_Database --> Evict_Redis_SSO: SCAN & DEL session:* matching user
        Evict_Redis_SSO --> Blacklist_Client_Store: Evict client Redis tokens
    }

    Revoked_Client --> Terminal_State: Database marked revoked=true; Introspection returns active: false
    Blacklist_Client_Store --> Terminal_State: User kicked to login screen on next request
    Natural_Expiry --> Nightly_Pruning: Cleaned up via B-tree composite index (idx_oauth2_authorization_cleanup)
    Nightly_Pruning --> Terminal_State

    Terminal_State --> [*]
```

---

### 4. AWS KMS Multi-Key Rotation State Machine (State Diagram)

```mermaid
stateDiagram-v2
    [*] --> Active_Key: Created in AWS KMS (RSA_2048, SIGN_VERIFY)<br/>Assigned alias/oauth2-signing-key
    
    state Active_Key {
        [*] --> Token_Signing: Signs JARM responses, Access Tokens, ID Tokens
        Token_Signing --> JWKS_Publishing: Published in /oauth2/jwks with kid: active
    }

    Active_Key --> Retiring_Key: Rotation Initiated (rotate_kms_keys.sh)<br/>New key created -> assigned alias/oauth2-signing-key<br/>Old key reassigned alias/oauth2-signing-key-previous

    state Retiring_Key {
        [*] --> Grace_Window: Concurrent Overlap Period (24 Hours >= max token TTL)
        Grace_Window --> Verification_Only: NO new tokens signed with this key
        Verification_Only --> JWKS_Dual_Publish: Both keys concurrently served in /oauth2/jwks
    }

    Retiring_Key --> Disabled_Key: Grace Period Expires<br/>alias/oauth2-signing-key-previous deleted<br/>Key disabled in AWS KMS
    
    Disabled_Key --> Deleted_Key: KMS Scheduled Deletion Window (7 to 30 days)
    Deleted_Key --> [*]
```

---

### 5. PostgreSQL Relational Entity-Relationship Diagram (ERD)

```mermaid
erDiagram
    oauth2_registered_client ||--o| oauth2_client_public_key : "binds asymmetric public key"
    oauth2_registered_client ||--o{ oauth2_authorization : "issues runtime grants"
    oauth2_registered_client ||--o{ oauth2_authorization_consent : "tracks scope consent"
    app_users ||--o{ oauth2_authorization : "owns as principal_name"

    oauth2_registered_client {
        varchar(100) id PK "UUID"
        varchar(100) client_id UK "Unique Client Identifier"
        timestamptz client_id_issued_at
        varchar(200) client_name
        varchar(1000) client_authentication_methods "private_key_jwt"
        varchar(1000) authorization_grant_types "authorization_code, refresh_token"
        varchar(1000) redirect_uris "Whitelisted callback URIs"
        varchar(1000) post_logout_redirect_uris "Whitelisted post-logout destinations"
        varchar(1000) scopes "Server-determined scopes"
        text client_settings "JSON settings (requireProofKey: true)"
        text token_settings "JSON token settings (TTL, DPoP thumbprint)"
    }

    oauth2_client_public_key {
        varchar(100) client_id PK, FK "References oauth2_registered_client"
        text public_key_pem "2048-bit RSA Public Key (PEM)"
        timestamptz created_at
        timestamptz updated_at
    }

    oauth2_authorization {
        varchar(100) id PK "UUID"
        varchar(100) registered_client_id FK "References oauth2_registered_client"
        varchar(200) principal_name FK "References app_users(email/id)"
        varchar(100) authorization_grant_type
        varchar(1000) authorized_scopes "Bound server scopes"
        text state "Flow state identifier"
        text authorization_code_value "Indexed by idx_oauth2_auth_code"
        timestamptz authorization_code_expires_at
        text access_token_value "Indexed by idx_oauth2_access_token"
        timestamptz access_token_expires_at
        text oidc_id_token_value
        timestamptz oidc_id_token_expires_at
        text refresh_token_value "Indexed by idx_oauth2_refresh_token"
        timestamptz refresh_token_expires_at
    }

    oauth2_authorization_consent {
        varchar(100) registered_client_id PK "References registered client"
        varchar(200) principal_name PK "User identifier"
        varchar(1000) authorities "Granted Spring authorities"
    }

    app_users {
        UUID id PK "DEFAULT gen_random_uuid()"
        varchar(255) email UK "User login identifier"
        varchar(255) password_hash "BCrypt(cost=10, SHA-256(password))"
        boolean is_fraud "DEFAULT FALSE (triggers instant global purge)"
    }
```

---

### 6. Two-Stage Defense-in-Depth Password Pipeline (Flowchart)

```mermaid
flowchart LR
    User["User Types Password<br/>('secret123')"] --> ClientTier["Client Tier (Rails IdP / Manager)<br/>• Computes SHA-256(plaintext)<br/>• Never stores or logs plaintext"]
    ClientTier -->|"TLS Network Transport<br/>(Fixed 64-char Hex Digest)<br/>Plaintext NEVER crosses wire!"| Boundary["Spring Auth Server Boundary<br/>(/api/admin/users/authenticate)<br/>Protected by X-Admin-Api-Key"]
    Boundary --> ServerTier["Server Tier (Spring Security)<br/>• Evaluates is_fraud flag first<br/>• Verifies via BCryptPasswordEncoder(10)<br/>• Salted, adaptive GPU-resistant hashing"]
    ServerTier --> Storage[("PostgreSQL app_users<br/>password_hash = $2b$10$...<br/>Safe against offline brute force")]
```

---

## Protocol Wire Formats & Cryptographic Payloads (HTTP Wire Reference)

### Hop 1: Pushed Authorization Request (RFC 9126 PAR)

The client authenticates using an asymmetric **`private_key_jwt`** assertion and provides an ephemeral **DPoP proof** directly to `/oauth2/par` over a back-channel TLS POST:

```http
POST /oauth2/par HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid3RLU2F...",...}

response_type=code
&client_id=demo-client
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback
&code_challenge=E9Melhoa2OwvFrGMTJguCH5rtx64Etu6QMtPm_ed35U
&code_challenge_method=S256
&state=af0ifjsldkj
&nonce=n-0S6_WzA2Mj
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6ImNsaWVudC1rZXktMSJ9.eyJpc3MiOiJkZW1vLWNsaWVudCIsInN1YiI6ImRlbW8tY2xpZW50IiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwL29hdXRoMi9wYXIiLCJqdGkiOiI0NDM1MjM0OS0xMmEzLTRjOTktODFlMS0zOTQ4MmFjOTBkMTIiLCJleHAiOjE3NTgxMzAzMjAsImlhdCI6MTc1ODEzMDIwMH0.KjS...
```

**Decoded `client_assertion` (RFC 7523 JWT):**
```json
{
  "header": { "alg": "RS256", "kid": "client-key-1" },
  "payload": {
    "iss": "demo-client",
    "sub": "demo-client",
    "aud": "http://localhost:9000/oauth2/par",
    "jti": "44352349-12a3-4c99-81e1-39482ac90d12",
    "iat": 1758130200,
    "exp": 1758130320
  }
}
```

**Decoded DPoP Proof Header (`DPoP` HTTP Header):**
```json
{
  "header": {
    "typ": "dpop+jwt",
    "alg": "ES256",
    "jwk": { "kty": "EC", "crv": "P-256", "x": "wtKSa...", "y": "m9N2z..." }
  },
  "payload": {
    "jti": "8b9a11e4-39f2-4e6a-bc01-9876543210ab",
    "htm": "POST",
    "htu": "http://localhost:9000/oauth2/par",
    "iat": 1758130200
  }
}
```

**Authorization Server Response (`201 Created`):**
```http
HTTP/1.1 201 Created
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store

{
  "request_uri": "urn:ietf:params:oauth:request_uri:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "expires_in": 60
}
```

---

### Hop 2: Cryptographically Signed Authorization Response (RFC 9221 JARM)

Upon user authentication at the Rails IdP, the Spring Authorization Server computes an RS256 signature via AWS KMS and redirects the browser with the signed JWT in the `response` query parameter:

```http
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?response=eyJhbGciOiJSUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJhdWQiOlsiZGVtby1jbGllbnQiXSwiaWF0IjoxNzU4MTMwMjAwLCJleHAiOjE3NTgxMzAzMjAsImNvZGUiOiJhdXRoLWNvZGUtZGIzOTRhYzktOWEzOS00ZjExLWExMGEtMzQ1Njg5YWJjZGVmIiwic3RhdGUiOiJhZjBpZmpzbGRraiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c...
```

**Decoded JARM JWS Header:**
```json
{
  "alg": "RS256",
  "kid": "kms-auth-server-key-1"
}
```

**Decoded JARM Payload (Tamper-Proof Authorization Code & State):**
```json
{
  "iss": "http://localhost:9000",
  "aud": ["demo-client"],
  "iat": 1758130200,
  "exp": 1758130320,
  "code": "auth-code-db394ac9-9a39-4f11-a10a-345689abcdef",
  "state": "af0ifjsldkj"
}
```

---

### Hop 3: Sender-Constrained Token Exchange & Nonce Handshake (RFC 9449 DPoP)

#### Step A: Initial Token Exchange (Missing Server Nonce)

```http
POST /oauth2/token HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...}

grant_type=authorization_code
&code=auth-code-db394ac9-9a39-4f11-a10a-345689abcdef
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6ImNsaWVudC1rZXktMSJ9...
```

**Server Nonce Challenge Response (`HTTP 400 use_dpop_nonce`):**
```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: dpop-nonce-9fa3148e-6701-447a-8bd1-b1e612f0e014
Content-Type: application/json;charset=UTF-8

{
  "error": "use_dpop_nonce",
  "error_description": "Use DPoP Nonce"
}
```

#### Step B: Retried Exchange with Server Nonce Bound

The client automatically rebuilds the DPoP proof embedding `"nonce": "dpop-nonce-9fa3148e-6701-447a-8bd1-b1e612f0e014"`:

```http
POST /oauth2/token HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...<proof embedding nonce>...}

grant_type=authorization_code
&code=auth-code-db394ac9-9a39-4f11-a10a-345689abcdef
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIs...
```

**Successful Token Response (`HTTP 200 OK`):**
```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6WyJkZW1vLWNsaWVudCJdLCJleHAiOjE3NTgxMzExMDAsImlhdCI6MTc1ODEzMDIwMCwianRpIjoiYTgyNGViMTItZTkxNy00YmU3LWJjOTAtY2QwNzhlZTAxMmEyIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCB1c2VyLnJlYWQgZGVtby5zZWNyZXRfYWNjZXNzIiwiY25mIjp7ImprdCI6InExWmdvblp2WmpjSmJ3Nlp3Z011bVlYbF93MVgweExnY2V0Wl92SWI0S1EifX0.H7...",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "rt_87b92f4c9ae2438b97d1b324",
  "scope": "openid profile email user.read demo.secret_access",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6WyJkZW1vLWNsaWVudCJdLCJleHAiOjE3NTgxMzExMDAsImlhdCI6MTc1ODEzMDIwMCwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJhdF9oYXNoIjoiN3FYcVp2WmpjSmJ3Nlp3Z011bVlYQSIsImNfaGFzaCI6IjNSbVlYS2J2WmpjSmJ3Nlp3Z011bVEifQ.P0..."
}
```

**Decoded Access Token Claims (`cnf.jkt` Sender-Constraint Binding):**
```json
{
  "iss": "http://localhost:9000",
  "sub": "alice_smith",
  "aud": ["demo-client"],
  "exp": 1758131100,
  "iat": 1758130200,
  "jti": "a824eb12-e917-4be7-bc90-cd078ee012a2",
  "scope": "openid profile email user.read demo.secret_access",
  "cnf": {
    "jkt": "q1ZgonZvZjcJbw6ZwgMumYXl_w1X0xLgcetZ_vIb4KQ"
  }
}
```

**Decoded ID Token Claims (`at_hash` & `c_hash` Cryptographic Binding):**
```json
{
  "iss": "http://localhost:9000",
  "sub": "alice_smith",
  "aud": ["demo-client"],
  "exp": 1758131100,
  "iat": 1758130200,
  "nonce": "n-0S6_WzA2Mj",
  "at_hash": "7qXqZvZjcJbw6ZwgMumYXA",
  "c_hash": "3RmYXKbvZjcJbw6ZwgMumQ"
}
```

---

### Hop 4: Real-Time Token Introspection (RFC 7662) & Revocation (RFC 7009)

#### Real-Time Token Introspection (`POST /oauth2/introspect`):
```http
POST /oauth2/introspect HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1Ni...<access_token>
&token_type_hint=access_token
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIs...
```

**Active Token Response (`HTTP 200 OK`):**
```json
{
  "active": true,
  "sub": "alice_smith",
  "aud": ["demo-client"],
  "iss": "http://localhost:9000",
  "exp": 1758131100,
  "iat": 1758130200,
  "client_id": "demo-client",
  "token_type": "DPoP",
  "scope": "openid profile email user.read demo.secret_access",
  "cnf": {
    "jkt": "q1ZgonZvZjcJbw6ZwgMumYXl_w1X0xLgcetZ_vIb4KQ"
  }
}
```

#### Token Revocation (`POST /oauth2/revoke`):
```http
POST /oauth2/revoke HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

token=rt_87b92f4c9ae2438b97d1b324
&token_type_hint=refresh_token
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIs...
```

**Revocation Response (`HTTP 200 OK`):**
```http
HTTP/1.1 200 OK
```
*(Any subsequent introspection query returns `{"active": false}` instantly).*

---

### Hop 5: OpenID Connect Back-Channel Logout 1.0 (Signed `logout_token` JWS)

When session revocation occurs, Spring Authorization Server dispatches a server-to-server POST to registered client backchannel endpoints:

```http
POST /oidc/backchannel_logout HTTP/1.1
Host: demo-client:8080
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6ImRlbW8tY2xpZW50IiwiaWF0IjoxNzU4MTMwMjUwLCJqdGkiOiJkM2E1ZjAxOC02NTY2LTQ5NWEtOGI3Zi1mZmYxMzk1ZjBlMzQiLCJzaWQiOiI3YTg5YzgxZi1lMzU3LTRjOTQtYjZhMC1hMzg1ZWVlYTRiN2YiLCJldmVudHMiOnsiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9ldmVudC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fX0.Kx...
```

**Decoded `logout_token` Payload:**
```json
{
  "iss": "http://localhost:9000",
  "sub": "alice_smith",
  "aud": "demo-client",
  "iat": 1758130250,
  "jti": "d3a5f018-6566-495a-8b7f-fff1395f0e34",
  "sid": "7a89c81f-e357-4c94-b6a0-a385eeea4b7f",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  }
}
```
> [!IMPORTANT]
> In accordance with OIDC Back-Channel Logout 1.0 §2.4, the `logout_token` **MUST NOT** contain a `nonce` claim. The demo client validates the signature against the AS JWKS, extracts `sub` or `sid`, and purges all cached user tokens from Redis.

---

### Hop 6: Internal Authentication & Shared Redis SSO Session Contract

#### Internal Rails IdP $\rightarrow$ Spring User Authentication:
```http
POST /api/admin/users/authenticate HTTP/1.1
Host: spring-auth-server:9000
X-Admin-Api-Key: admin-secret-key-change-me
Content-Type: application/json

{
  "email": "alice_smith@example.com",
  "password": "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4"
}
```

**Authentication Success (`HTTP 200 OK`):**
```json
{
  "id": "e8d47b6a-9b12-4c22-8399-5ef86134b220",
  "email": "alice_smith@example.com",
  "status": "authenticated"
}
```

#### Shared Redis Session Structure (`session:<uuid>` in Redis DB 0):
```json
{
  "username": "alice_smith@example.com",
  "email": "alice_smith@example.com",
  "name": "Alice Smith",
  "roles": ["ROLE_USER"],
  "authenticated_at": "2026-09-17T18:30:00Z"
}
```

---

## Standards Compliance & Core Architecture Matrix

| Standard / RFC | Specification Name | How It Is Implemented & Enforced in Codebase |
|---|---|---|
| **FIPS 140-2 / KMS** | **Hardware-Backed Asymmetric Signing** | Tokens (access, ID, logout, JARM) are signed via the AWS KMS `Sign` API using `RSA_2048`; asymmetric private keys never enter JVM heap memory. When deployed against real AWS KMS, signing occurs in FIPS 140-2 Level 3 validated HSMs. |
| **RFC 8725** | **Strict Algorithm Pinning (RS256)** | Authorization server and client library strictly enforce `RS256`, rejecting `none`, symmetric HMAC (`HS256`), and unapproved algorithms to eliminate JWT signature confusion attacks. |
| **Graceful Rotation**| **Multi-Key JWKS Rotation** | Serves active and retiring keys concurrently at `/oauth2/jwks`, enabling zero-downtime key rotation while in-flight tokens remain valid through their TTL. |
| **RFC 9126** | **Pushed Authorization Requests (PAR)** | All authorization parameters are pushed directly to `/oauth2/par` over TLS via an authenticated backchannel POST. The browser only receives an opaque, single-use `request_uri`. Stops query leakage and URL manipulation. |
| **RFC 9221** | **JWT-Secured Authorization Response Mode (JARM)** | Strictly enforced on all front-channel authorization callbacks. The authorization server signs response payloads (`code`, `iss`, `aud`, `state`, or `error`) into an RS256 JWS JWT signed by AWS KMS. Plaintext query parameters are strictly rejected. |
| **RFC 7523** | **`private_key_jwt` Client Authentication** | Clients authenticate exclusively using RS256-signed JWT assertions (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`). Static client secrets (`client_secret_basic`, `client_secret_post`) and insecure `none` authentication are **strictly rejected with HTTP 401**. Includes JTI replay cache in Redis. |
| **RFC 9449** | **Demonstrating Proof-of-Possession (DPoP) & Server Nonces** | The `/oauth2/token` endpoint strictly enforces the `DPoP` HTTP header (requests lacking DPoP are rejected with HTTP 400 `invalid_dpop_proof`). Issued access tokens are sender-constrained by embedding the DPoP key thumbprint in the `cnf.jkt` claim. The server enforces single-use 60s Redis nonces (RFC 9449 Section 8) with `HTTP 400 use_dpop_nonce` challenge-response. |
| **OIDC Core 1.0** | **ID Token Cryptographic Hashes (`at_hash` & `c_hash`)** | The authorization server computes and embeds SHA-256 left-half base64url hashes in the ID Token matching the access token (`at_hash`) and authorization code (`c_hash`). The client cryptographically validates both hashes upon code exchange, stopping code and token substitution attacks. |
| **RFC 7636** | **PKCE (`S256`)** | Proof Key for Code Exchange is enforced on all authorization requests (`requireProofKey(true)`). Intercepted authorization codes cannot be exchanged without the client's `code_verifier`. |
| **RFC 9207** | **Authorization Server Issuer Identification** | The authorization response appends `iss=http://localhost:9000` to callback URLs and embeds it inside JARM tokens. The client strictly validates the issuer before exchanging the code, completely mitigating OAuth 2.0 Mix-Up Attacks. |
| **Architecture** | **Server-Determined Scopes** | The demo client omits the `scope` parameter entirely. The Authorization Server predetermines and binds authorized scopes strictly based on registered client configuration (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`), preventing privilege escalation and client-side scope tampering. |
| **RFC 7009** | **Token Revocation** | Clients revoke tokens via `/oauth2/revoke` authenticated with `private_key_jwt`. Revocation invalidates the authorization in PostgreSQL and immediately flushes sessions. |
| **RFC 7662** | **Token Introspection** | Resource servers and clients check token validity in real time at `/oauth2/introspect` using `private_key_jwt`. Supported by an in-memory near-cache for sub-millisecond evaluation. |
| **OIDC BCL 1.0** | **Back-Channel Logout 1.0** | Spring Authorization Server dispatches a signed JWT `logout_token` asynchronously to the client's backchannel endpoint (`/oidc/backchannel_logout`), terminating the user's session without relying on user-agent redirection. |
| **Config Mgmt** | **PostgreSQL & In-Memory Near-Cache** | Next.js writes client registrations directly to Spring Authorization Server via authenticated Admin REST API (`X-Admin-Api-Key`). Spring stores clients in PostgreSQL (`oauth2_registered_client`) with strict ACID guarantees. An in-memory L1 cache (`ConcurrentHashMap`) serves runtime authorization checks in ~0.001 ms with zero database round-trips. Real-time cluster cache eviction via Redis Pub/Sub (`oauth2as:clients:reload`). |

---

## Security Inclusions, Posture & Production Readiness Roadmap

This section documents the security controls currently active in the platform, along with an enterprise production readiness roadmap detailing requirements, benefits, trade-offs, and classification.

### 1. Active Security Inclusions (Implemented in Codebase)
- **Cryptographic Isolation:** Asymmetric signing keys are managed by AWS KMS and never touch application memory. **When deployed against real AWS KMS** the keys reside in FIPS 140-2 Level 3 validated Hardware Security Modules; **the bundled local stack uses LocalStack, a software KMS emulation with no HSM and no FIPS validation** (dev only).
- **Fail-Closed Guarantee:** When KMS signing is enabled (`aws.kms.enabled: true`), the authorization server refuses startup if KMS is unreachable, preventing silent fallback to insecure keys.
- **Strict Algorithm Pinning:** Rejects `alg: none` and symmetric HMAC `HS256` confusion attacks at both the authorization server and client decoders.
- **Multi-Key JWKS Rotation:** Concurrent publishing of active and retired keys at `/oauth2/jwks` eliminates downtime during key lifecycle transitions.
- **Asymmetric Client Identity:** Shared secrets (`client_secret_basic`, `client_secret_post`) are disabled in favor of `private_key_jwt` with Redis JTI replay prevention.
- **Sender-Constrained Tokens:** RFC 9449 DPoP binds access tokens to ephemeral client keys, mitigating token theft and replay.
- **Server-Provided DPoP Nonces (RFC 9449 §8):** Redis-backed single-use nonces (60s TTL) with `HTTP 400 use_dpop_nonce` challenge-response to eliminate clock-skew proof replay attacks.
- **Cryptographic Token Binding (`at_hash` & `c_hash`):** ID token contains SHA-256 left-half hashes cryptographically bound to access tokens and authorization codes (OIDC Core Section 3.1.3.6).
- **Discovery Metadata Hardening:** Public OIDC discovery restricts `token_endpoint_auth_methods_supported` strictly to `["private_key_jwt"]`, preventing confusion around shared secrets.
- **Pushed Authorization Requests (PAR):** Eliminates sensitive query parameters in browser history and server access logs.
- **Strict RFC 9221 JARM Enforcement:** All front-channel authorization responses and error responses are cryptographically signed with RS256 by AWS KMS. Plaintext callback parameters are strictly rejected, preventing authorization code injection, state tampering, and forged phishing error messages.
- **Issuer Identification:** RFC 9207 prevents OAuth 2.0 Mix-Up attacks.
- **Server-Determined Scopes:** Prevents client-side privilege escalation.
- **Hardened Browser Security:** Strict `HttpOnly`, `SameSite: Lax`, and `Secure` cookie attributes; session identifiers are never exposed in URLs (CWE-598).
- **Constant-Time Operations:** Credential and API key checks use constant-time byte comparisons to eliminate side-channel timing attacks.
- **Strict Input Validation:** Session identifiers are strictly validated as UUIDv4 before executing Redis operations.
- **Zero-Trust Storage Isolation & Complete S3 Removal:** AWS S3 was completely decommissioned and removed from the ecosystem to eliminate eventual consistency lags and prevent front-end storage access. Persistent storage is strictly centralized in PostgreSQL with access exclusive to the Java application. Administrative client management occurs exclusively through Spring's authenticated Admin REST API (`/api/admin/clients` with constant-time `X-Admin-Api-Key` verification), enforcing zero-trust domain boundaries.
- **OWASP Security Response Headers:** Strict defense-in-depth headers applied across all endpoints: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Standardized OAuth 2.1 CORS Policy:** Strict cross-origin resource sharing configuration allowing preflight `OPTIONS` for browser-based clients on token endpoints with exposed `DPoP-Nonce` headers.
- **Dual-Zone Perimeter Isolation & Edge Reverse Proxy:** Deployed an Nginx edge perimeter proxy (`poc-nginx`) on port `9000` exposing public OAuth 2.1 / OIDC endpoints while blocking `/api/admin/*` and `/actuator/*` with `HTTP 403 Forbidden` before requests reach application runtimes. Preserves and passes all upstream tracing and client headers (`underscores_in_headers on`, `proxy_pass_request_headers on`). Spring Auth Server is shielded behind internal network port `9000` and private localhost bastion `127.0.0.1:9001:9000`.
- **Spring Security Defense-in-Depth Filter:** Implemented [`AdminApiKeyFilter`](spring-auth-server/src/main/java/com/example/authserver/security/AdminApiKeyFilter.java) registered in the Spring Security filter chain before `AuthorizationFilter`, enforcing constant-time `MessageDigest.isEqual` authentication on `X-Admin-Api-Key` across all `/api/admin/**` routes even if accessed internally.
- **Reverse Proxy Header Normalization:** Enforces `server.forward-headers-strategy: framework` to securely reconstruct public origin URLs from standard proxy headers (`X-Forwarded-*`).
- **Native Graceful Shutdown:** Configured with a 30-second drain window to ensure zero in-flight authorization request drops during deployments and rolling updates.
- **Automated Authorization Pruning:** Flyway V2 migration with B-tree indices on authorization expiry timestamps, queried by a nightly scheduled cleanup service to purge expired authorization records and prevent unbounded database growth.

### 2. Production Readiness Roadmap

| Capability / Control | What Is Needed (Implementation Details) | Benefits | Trade-offs & Operational Costs | Classification |
|---|---|---|---|---|
| **Edge Web Application Firewall (WAF)** | Deploy AWS WAF or Cloudflare in front of the Application Load Balancer (ALB) or Nginx proxy with managed rule groups (Core Rule Set, Known Bad Inputs, Amazon IP Reputation) and rate limiting on `/oauth2/token` and `/oauth2/par`. | Shields application containers from volumetric DDoS, credential stuffing, and malicious scraper bots before requests hit application runtimes. | Minor latency addition (1–3 ms); managed service costs; requires periodic false-positive rule tuning. | **Deployment / Cloud Infrastructure Configuration** (No repo change needed) |
| **TLS 1.3 & HSTS at Reverse Proxy / ALB** | Terminate TLS with ACM certificates on ALB / Nginx; enforce TLS 1.2/1.3; redirect HTTP 80 to 443; inject `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header. | Eliminates cleartext traffic on public networks; offloads CPU-intensive TLS handshakes from application instances; prevents SSL stripping. | Requires automated certificate renewal and internal security group management. | **Deployment / Cloud Infrastructure Configuration** |
| **Per-Client & Edge Rate Limiting** | **Edge Layer**: Configure Nginx `limit_req_zone` for IP-based throttling on `/oauth2/token` and `/oauth2/par`.<br/>**App Layer**: Add distributed per-client rate-limiting filter (e.g. Bucket4j backed by Redis) keyed by authenticated `client_id`. | Protects the authorization server and KMS Sign API from runaway client loops, credential stuffing, or compromised client abuse. | Additional Redis round-trip latency on token exchange; requires configuring per-tier quota allocations. | **Deployment Config** (Nginx `limit_req`) + **Codebase Change** (Bucket4j in Spring) |
| **Mutual TLS (mTLS) for B2B Clients (RFC 8705)** | Configure ALB or Nginx reverse proxy with client certificate verification; pass validated client certificate headers (`X-Forwarded-Client-Cert`); implement Spring Security `TlsClientAuthenticationConverter`. | Hardware-grade client authentication using client-side X.509 certificates (e.g. smart cards, HSMs); eliminates per-request JWT assertion generation overhead. | High PKI complexity; requires managing Certificate Authorities (CAs), certificate lifecycles, and revocation lists (CRL/OCSP). | **Codebase Change** (converter logic) + **Deployment Configuration** (ALB mTLS setup) |
| **Cloud Secrets Manager Integration** | Store database passwords, Redis credentials, and admin API keys in AWS Secrets Manager or HashiCorp Vault; inject securely via ECS/EKS task definitions. | Eliminates plaintext secrets in code repositories and environment configuration files; supports automated credential rotation. | Cold-start latency while retrieving secrets; additional API call costs. | **Deployment / Cloud Infrastructure Configuration** |
| **Automated KMS Lifecycle Schedule** | Deploy an AWS EventBridge rule and Lambda function to periodically execute the rotation flow in `scripts/rotate_kms_keys.sh` (e.g. semi-annually), sending operator alerts via SNS. | Guarantees compliance with cryptographic key expiration standards (NIST SP 800-57, PCI DSS 4.0) with zero manual intervention. | Requires monitoring rotation windows to prevent premature decommissioning of keys with active in-flight tokens. | **Deployment / Cloud Infrastructure Configuration** |
| **Distributed Redis High-Availability** | Migrate standalone Redis container to an AWS ElastiCache Redis replication group (multi-AZ with automatic failover) or Redis Sentinel; configure connection strings accordingly. | Eliminates single point of failure for SSO sessions, JTI replay prevention, and L2 client configuration caching. | Increased cloud infrastructure costs; eventual consistency considerations during failover events. | **Deployment / Cloud Infrastructure Configuration** |

---

## Architectural Deep Dives & Subsystem Index

For deep cryptographic rationale, schema dictionaries, and implementation contracts, refer to the architecture specifications in [`docs/architecture/`](docs/architecture/README.md):

- [**System Topology & Component Communication**](docs/architecture/README.md): Full component interaction graph, communication channels, and port allocations.
- [**Network Perimeter & Reverse Proxy Routing Architecture**](docs/architecture/network_perimeter_and_proxy_routing.md): Edge reverse proxy / ALB path routing specification, public vs. internal endpoint access matrix, and configuration templates for AWS ALB, Nginx, Kubernetes Ingress, and Cloudflare WAF.
- [**AWS KMS Key Management, Multi-Key Rotation & Algorithm Pinning**](docs/architecture/kms_multi_key_rotation_flow.md): End-to-end KMS HSM signing, zero-downtime key rotation lifecycle, automated rotation script, and RFC 8725 algorithm pinning.
- [**OAuth 2.1 Code Flow with PAR, DPoP & Rails SSO**](docs/architecture/oauth2_par_dpop_flow.md): Step-by-step sequence diagram from initial browser click to DPoP-protected UserInfo query.
- [**Client Configuration, Near-Cache & Dynamic Admin Flow**](docs/architecture/client_config_and_caching_flow.md): Sequence diagrams covering in-memory near-cache lookups (~0.001 ms), PostgreSQL ACID persistence, dynamic client onboarding via Spring Admin REST API, and immediate revocation.
- [**Token Lifecycle, Revocation & OIDC Back-Channel Logout**](docs/architecture/token_lifecycle_and_logout_flow.md): Sequence diagrams for RFC 7009 token revocation, RFC 7662 introspection, and OIDC Back-Channel Logout 1.0 push.
- [**Performance, Scalability & Bottleneck Analysis**](docs/architecture/performance_and_scalability.md): Deep-dive analysis of system bottlenecks, cryptographic speedups, in-memory JWKS resolution, multi-session concurrency, automated retries, and high-scale roadmap.
- [**PostgreSQL Persistence Architecture & Performance Analysis**](docs/architecture/postgres_persistence_and_performance.md): Architectural rationale for database-backed clients, Flyway schema migrations, Java-only network isolation, and near-cache performance.
- [**Interface Contracts & Unified Data Dictionary**](docs/architecture/contracts_and_data_dictionary.md): Formal JSON schema for the Rails $\leftrightarrow$ Spring Redis SSO session, unified Redis key taxonomy and TTL matrix, and PostgreSQL DDL/ERD schema reference.
- [**User Management, Authentication & Fraud Revocation**](docs/architecture/user_management_and_authentication.md): The `app_users` store, `/api/admin/users` admin API, two-stage SHA-256 → BCrypt password pipeline, Rails IdP `/authenticate` integration, and fraud-flag → global session revocation.
- [**Higher Key & Cryptographic Standards (Design Options)**](docs/architecture/higher_key_and_crypto_standards.md): Pros/cons of stronger signing algorithms, Argon2id password hashing, and accurate FIPS 140-2/140-3 scoping. Decision aid — not implemented.
- [**JAR (RFC 9101) — Design Option**](docs/architecture/jar_rfc9101_design_option.md): JWT-Secured Authorization Requests evaluated against the implemented PAR flow, with pros/cons and a recommended PAR + JAR shape. Documented, not implemented.

### Developer & Tester Guides
- [**Developer Cookbook & Iteration Guide**](docs/guides/developer_cookbook.md): Dual-mode execution (Docker vs. local IDE debugging), Admin API `curl` client registration examples, custom JWT claim recipes, and hot-cache reload commands.
- [**Testing & Troubleshooting Guide**](docs/guides/testing_and_troubleshooting.md): Test fixture & credential matrix, automated test execution, failure diagnostic workflows, and boilerplate for writing new functional test scenarios.

---

## Services & Ports

| Service | Port | Description | Technology Stack |
|---|---|---|---|
| **`nginx`** | `9000` | Edge Perimeter Reverse Proxy (Public Gateway) | Nginx 1.27 Alpine, HTTP/1.1 keepalive, Header Passthrough |
| **`spring-auth-server`**| `9001` (internal) | Backend OAuth 2.1 & OIDC Server (Docker `:9000`) | Spring Boot 4.0.8, Spring Security 7.0.7, Java 25 |
| **`postgres`** | `5432` | ACID Store for Authorizations & Clients (Java only) | PostgreSQL 16 Alpine |
| **`client-manager`**| `3001` | OAuth 2.1 Client Config Manager UI | Next.js 16, Turbopack, React 19, Tailwind CSS 4, Spring Admin API |
| **`demo-client`** | `8080` | Interactive OAuth 2.1 client & UI | Ruby 4.0, Puma, Rack, Redis DB 1 |
| **`rails-app`** | `3000` | External Identity Provider (IdP) | Ruby on Rails 7, Redis DB 0 |
| **`localstack`** | `4566` | Local AWS KMS HSM service emulation | LocalStack 3.8 (KMS: `alias/oauth2-signing-key`) |
| **`poc-redis`** | `6379` | Shared Redis session, cache & pub/sub | Redis 7 Alpine |

---

## Quick Start & Running Services

### Prerequisites
- **mise** (or Java 25 + Ruby 4.0.6 installed locally), or **Docker & Docker Compose**.
- Running Redis instance on `localhost:6379`, PostgreSQL on `localhost:5432`, and LocalStack on `localhost:4566`.

### Option A: Running with Docker Compose (Recommended)
To build from source and run the full stack in Docker containers:
```bash
docker compose up --build -d
```
- Access the **Perimeter Reverse Proxy (Public OAuth Gateway)** at: **`http://localhost:9000`**
- Access the **Client Config Manager** at: **`http://localhost:3001`**
- Access the **Demo Client** at: **`http://localhost:8080`**

### Option B: Running Locally with Mise / Native CLI

1. **Start Supporting Infrastructure Containers (PostgreSQL, Redis, LocalStack)**:
   ```bash
   docker compose up -d postgres redis localstack
   ```

2. **Start Rails Login App (Port 3000)**:
   ```bash
   cd rails-app
   mise exec -- bundle install
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
   mise exec -- bundle install
   mise exec -- bundle exec puma -b tcp://0.0.0.0:8080
   ```

5. **Start Client Config Manager (Port 3001)**:
   ```bash
   cd client-manager
   pnpm install
   pnpm dev -p 3001
   ```

---

## Connecting a New Client Application

To onboard a new application or service (e.g. Rails web app or backend microservice) with this authorization service:

1. **Generate RSA Key Pair**: Create a dedicated 2048-bit RSA key pair (`config/keys/client_private_key.pem`).
2. **Register in Client Manager**: Provide your Client ID, Redirect URIs, and Public Key PEM via the [Client Manager UI](http://localhost:3001) or Admin REST API (`POST /api/admin/clients`).
3. **Install Client Library**: Add `gem "oauth2_client_kit"` to your `Gemfile` and run `bundle install`.
4. **Configure Initializer**: Set up `config/initializers/oauth2_client_kit.rb` with your `client_id`, private key, and issuer URL.
5. **Mount Routes & Protect Controllers**: Add `mount_oauth2_client_kit` to `config/routes.rb` and `require_authentication!` to your controllers.

> 📖 **Full Step-by-Step Guide:** Read the [New Client Onboarding & Integration Guide](docs/guides/new_client_onboarding_guide.md) for complete copy-paste code snippets, environment variable reference tables, sensitive action checkpoints (`identity_checkpoint!`), and troubleshooting tips.

---

## Running the Automated Test Suites

The platform employs a rigorous, multi-layered testing strategy combining end-to-end browser journeys, comprehensive unit suites with 100% enforced code coverage across all services, and zero-tolerance static analysis.

### 1. End-to-End Functional Test Suite (Cucumber)

The `e2e-tests` directory contains automated **Cucumber** / **Capybara** / **Cuprite** (headless Chrome) end-to-end scenarios executing against the live services (`demo-client :8080`, `rails-app :3000`, `nginx :9000`, `spring-auth-server :9001`):

- **`oauth_authorization.feature`**: Full interactive authorization code flow (PAR, PKCE S256, DPoP, Rails SSO redirect, `private_key_jwt` token exchange, and authenticated profile render).
- **`token_lifecycle.feature`**: Refresh token rotation with DPoP sender constraint, sensitive action authorization via real-time token introspection (`RFC 7662`), and explicit token revocation (`RFC 7009`).
- **`error_journeys.feature`**: JARM error response mode validation, simulating Account Locked (client custom view override) and Account Suspended (OAuth2ClientKit default error view).
- **`invalid_login.feature`**: Credential validation failure handling at the Rails IdP with flash error feedback.
- **`fraud_revocation.feature`**: Admin fraud flag activation via Spring Admin API immediately terminating the user's active session and revoking authorizations across Redis and PostgreSQL.

> **Dynamic Test User Lifecycle:** Test users are dynamically created before each scenario via Spring's authenticated Admin API (`POST /api/admin/users`) using the two-stage SHA-256 $\rightarrow$ BCrypt password pipeline, and cleaned up automatically in the Cucumber `After` hook.

```bash
# Run all 8 Cucumber end-to-end scenarios (requires Docker containers running)
cd e2e-tests
mise exec -- bundle install
mise exec -- bundle exec cucumber

# Dry-run validation (validates steps under --strict without browser execution)
mise exec -- bundle exec cucumber --dry-run
```

### 2. Component Unit Test Suites & Code Coverage (100% Enforced)

Strict 100% test coverage is enforced by CI across every component:

| Component | Test Framework | Coverage Tool | Target | Execution Command |
|---|---|---|---|---|
| **`oauth2_client_kit`** | RSpec + WebMock | SimpleCov | **100.0% Lines** (115/115 specs) | `cd oauth2_client_kit && mise exec -- bundle exec rspec` |
| **`rails-app`** | RSpec-Rails | SimpleCov | **100.0% Lines** (26/26 specs) | `cd rails-app && mise exec -- bundle exec rspec` |
| **`demo-client`** | RSpec-Rails | SimpleCov | **100.0% Lines** (8/8 specs) | `cd demo-client && mise exec -- bundle exec rspec` |
| **`client-manager`** | Vitest + React Testing Library | `@vitest/coverage-v8` | **100% All** (47/47 tests) | `cd client-manager && pnpm test` |
| **`spring-auth-server`** | JUnit 5 + Mockito | JaCoCo | **100% Branches/Lines** (182/182 tests) | `cd spring-auth-server && mise exec -- mvn test` |

### 3. Static Analysis & Linting (RuboCop, Checkstyle, Spotless, Oxlint)

Zero linter offenses or formatting deviations are tolerated across all repositories:

```bash
# Ruby linting (TargetRubyVersion: 4.0 across all gems, apps, and e2e suites):
cd oauth2_client_kit && mise exec -- rubocop
cd rails-app && mise exec -- rubocop
cd demo-client && mise exec -- rubocop
cd e2e-tests && mise exec -- rubocop

# Java formatting and style checks (Spotless Google Java Format + Checkstyle):
cd spring-auth-server && mise exec -- mvn spotless:check checkstyle:check
# To automatically apply Spotless formatting:
cd spring-auth-server && mise exec -- mvn spotless:apply

# TypeScript / Next.js linting & formatting (Oxlint + Oxfmt):
cd client-manager && pnpm lint && pnpm format:check
```

---

## Performance & Concurrency Load Testing (k6)

An automated **k6** load testing suite is located in [`k6/oauth_load_test.js`](k6/oauth_load_test.js) (documented in [`k6/README.md`](k6/README.md)) to evaluate the platform under concurrent load with hardware-backed AWS KMS signing enabled:

- **Scenario 1 (`full_oauth_session_flow`):** 5 concurrent virtual users continuously executing the complete 6-hop interactive OAuth 2.1 authorization session. Each VU authenticates with an isolated user account dynamically provisioned from a dedicated test pool via Spring's internal Admin API, verifying true multi-session concurrency across PostgreSQL and Redis.
- **Scenario 2 (`discovery_and_jwks_burst`):** Ramping up to 30 req/sec querying discovery and JWKS endpoints, asserting 100% 200 OK responses with sub-millisecond response times under burst load.

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

| Metric | In-Memory Software Signing | AWS KMS Hardware Signing (Multi-Key JWKS + JARM + Multi-Session Pool) | Evaluation |
|---|---|---|---|
| **Cryptographic Boundary** | Software JCE (JVM memory) | **FIPS 140-2 Level 3 KMS HSM in real AWS** (LocalStack software emulation locally) | Hardware protection in production; emulated in dev |
| **Algorithm Pinning** | Optional | **Strict RS256 enforced (`none` & `HS256` rejected)** | Pinning active |
| **Key Rotation Support** | Single key | **Graceful Multi-Key JWKS (Active + Previous)** | Zero-downtime cutover |
| **KMS Signatures / Flow** | 0 (Local CPU) | **3 (JARM Auth Code + Access Token + ID Token)** | Full cryptographic auditability |
| **User & Session Isolation** | Single shared user | **Dynamic Multi-User Pool (`setup`/`teardown`)** | True concurrent sessions across DB & Redis |
| **Auth Session Success Rate** | `98.79%` | **`100.00%`** (152 / 152 completed) | **Flawless (Zero Failures)** |
| **Hourly Auth Session Rate** | ~29,400 sessions/hr | **~18,240 sessions/hr** | **~3.6x–5x above target** ("few thousand/hr") |
| **Full Session Latency (median)** | `112 ms` | **`519 ms`** (6 hops + 3 KMS calls + DB + Redis + BCrypt) | Sub-550ms median latency |
| **Full Session Latency (p95)** | `146 ms` | **`686.0 ms`** | **Passed** (<1,500 ms SLA threshold) |
| **Total HTTP Error Rate** | `0.04%` | **`0.00%`** (0 / 2,694 requests failed) | **100.00% success rate** |
| **Public Metadata Check Rate** | `100.00%` | **`100.00%`** (1,448 / 1,448 returned 200 OK) | Zero latency impact on auth sessions |

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
│   └── guides/
│       ├── new_client_onboarding_guide.md   # Step-by-step onboarding for new client applications
│       ├── developer_cookbook.md            # Dual-mode execution, custom claims, and cache invalidation
│       └── testing_and_troubleshooting.md   # Security testing and debugging runbooks
├── localstack/                     # LocalStack AWS KMS initialization & key provisioning
│   └── init/02-init-kms.sh         # Provisions RSA_2048 signing keys in KMS with alias
├── e2e-tests/                      # End-to-End Cucumber & Capybara/Cuprite test suite
│   ├── cucumber.yml                # Strict mode Cucumber runner profile
│   ├── Gemfile                     # Cucumber, Capybara, Cuprite, RSpec expectations
│   ├── features/                   # 5 Gherkin feature files (8 scenarios)
│   │   ├── oauth_authorization.feature # PAR + DPoP + PKCE + Rails SSO login flow
│   │   ├── token_lifecycle.feature     # Refresh rotation, introspection guard, RFC 7009 revocation
│   │   ├── error_journeys.feature      # Account locked/suspended JARM error flows
│   │   ├── invalid_login.feature       # Credential rejection at Rails IdP
│   │   ├── fraud_revocation.feature    # Admin fraud flag -> distributed session & token purge
│   │   ├── step_definitions/           # Capybara browser interaction steps
│   │   └── support/                    # Driver setup (Cuprite) & dynamic test user hooks
│   └── README.md                   # E2E test execution documentation
├── client-manager/                 # Next.js 16 OAuth 2.1 Client Configuration Manager
│   ├── app/                        # Dashboard UI, client modals, raw JSON viewer
│   ├── app/api/clients/            # Proxy endpoints forwarding to Spring Admin REST API
│   ├── lib/clients.ts              # Spring Admin API proxy client & X-Admin-Api-Key authentication
│   ├── __tests__/                  # Vitest unit tests (100% coverage enforced)
│   └── README.md                   # Client manager documentation & script reference
├── spring-auth-server/             # Spring Boot 4 / Spring Security 7 Authorization Server
│   ├── pom.xml                     # Maven dependencies, Checkstyle, Spotless, and JaCoCo gates
│   ├── src/test/                   # JUnit 5 + Mockito unit tests (100% coverage enforced)
│   └── src/main/
│       ├── java/com/example/authserver/
│       │   ├── client/
│       │   │   ├── PostgresRegisteredClientRepository.java # Near-cached PostgreSQL client repository
│       │   │   ├── ClientReloadRedisSubscriber.java        # Listens to oauth2as:clients:reload
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
│           ├── V1__create_oauth2_authorization_tables.sql  # Core Spring Security OAuth2 authorization tables
│           ├── V2__create_authorization_expiry_indices.sql # B-tree indices on authorization expiry timestamps
│           ├── V3__seed_default_demo_client.sql            # Seeds default demo-client & its RSA public key
│           └── V4__create_users_table.sql                  # app_users store (email, BCrypt hash, fraud flag)
├── rails-app/                      # Ruby on Rails 7 Identity Provider
│   ├── app/controllers/sessions_controller.rb      # Writes session:<uuid> to Redis
│   ├── app/views/sessions/new.html.erb             # User login form
│   └── README.md                                   # Rails IdP architecture & security documentation
├── oauth2_client_kit/              # Standalone Reusable OAuth 2.1 & OIDC Client Gem
│   ├── lib/
│   │   ├── oauth2_client_kit.rb                    # Top-level gem entrypoint & configuration
│   │   ├── oauth2_client_kit/client.rb             # Core protocol client (PAR, DPoP, private_key_jwt, OIDC)
│   │   ├── oauth2_client_kit/token_store.rb        # Redis token & session store with BCL eviction
│   │   └── oauth2_client_kit/rails/                # Rails integration (Engine, Routes, ControllerMethods, AuthController)
│   └── README.md                                   # Gem documentation & quickstart
└── demo-client/                    # Thin Demo Rails App (Pure UI & Action Calls to Gem)
    ├── app/
    │   ├── controllers/pages_controller.rb         # Thin pages controller (landing, profile, identity_checkpoint!)
    │   └── views/pages/                            # Clean landing and profile view templates
    ├── config/initializers/oauth2_client_kit.rb    # Gem configuration initializer
    ├── config/routes.rb                            # mount_oauth2_client_kit
    └── README.md                                   # Demo client documentation
```
