# Enterprise OAuth 2.1 & OpenID Connect (OIDC) Platform

A production-grade, hardened **OAuth 2.1 Authorization Server** and **OpenID Connect (OIDC)** ecosystem built with **Spring Boot 4 / Spring Security 7**, an external **Ruby on Rails** Identity Provider (IdP) with a **shared Redis session**, and a **Ruby/Puma Demo Client** featuring sender-constrained tokens, cryptographic client assertions, and real-time session management.

---

## Table of Contents

1. [System Architecture & Blueprints](#system-architecture--blueprints)
   - [1. Component Topology & Network Perimeter Architecture](#1-component-topology--network-perimeter-architecture)
   - [2. End-to-End Interactive Protocol Exchange](#2-end-to-end-interactive-protocol-exchange)
   - [3. Token & Session Lifecycle State Machine](#3-token--session-lifecycle-state-machine)
   - [4. AWS KMS Multi-Key Rotation State Machine](#4-aws-kms-multi-key-rotation-state-machine)
   - [5. PostgreSQL Relational Entity-Relationship Diagram (ERD)](#5-postgresql-relational-entity-relationship-diagram-erd)
   - [6. Two-Stage Defense-in-Depth Password Pipeline](#6-two-stage-defense-in-depth-password-pipeline)
2. [Enterprise Standards & Security Controls Reference Matrix](#enterprise-standards--security-controls-reference-matrix)
3. [Cryptographic Architecture & FIPS 140-3 Posture](#cryptographic-architecture--fips-140-3-posture)
   - [Algorithmic Baseline: ECDSA NIST P-256 (ES256)](#algorithmic-baseline-ecdsa-nist-p-256-es256)
   - [Signature Transcoding: ASN.1 DER to Raw IEEE P1363](#signature-transcoding-asn1-der-to-raw-ieee-p1363)
   - [Cryptographic Boundary Definition](#cryptographic-boundary-definition)
   - [System-Wide FIPS 140-3 Compliance Roadmap](#system-wide-fips-140-3-compliance-roadmap)
4. [OpenID Connect (OIDC) Conformance & Profile Alignment](#openid-connect-oidc-conformance--profile-alignment)
5. [Protocol Wire Formats & Cryptographic Payloads (HTTP Wire Reference)](#protocol-wire-formats--cryptographic-payloads-http-wire-reference)
   - [Hop 1: Pushed Authorization Request (RFC 9126 PAR)](#hop-1-pushed-authorization-request-rfc-9126-par)
   - [Hop 2: Cryptographically Signed Authorization Response (RFC 9221 JARM)](#hop-2-cryptographically-signed-authorization-response-rfc-9221-jarm)
   - [Hop 3: Sender-Constrained Token Exchange & Nonce Handshake (RFC 9449 DPoP)](#hop-3-sender-constrained-token-exchange--nonce-handshake-rfc-9449-dpop)
   - [Hop 4: Real-Time Token Introspection (RFC 7662) & Revocation (RFC 7009)](#hop-4-real-time-token-introspection-rfc-7662--revocation-rfc-7009)
   - [Hop 5: OpenID Connect Back-Channel Logout 1.0 (Signed logout_token JWS)](#hop-5-openid-connect-back-channel-logout-10-signed-logout_token-jws)
   - [Hop 6: Internal Authentication & Shared Redis SSO Session Contract](#hop-6-internal-authentication--shared-redis-sso-session-contract)
6. [Performance & Concurrency Benchmarks](#performance--concurrency-benchmarks)
7. [Production Hardening & Deployment Roadmap](#production-hardening--deployment-roadmap)
8. [Services & Ports](#services--ports)
9. [Quick Start & Running Services](#quick-start--running-services)
   - [Prerequisites](#prerequisites)
   - [Option A: Running with Docker Compose (Recommended)](#option-a-running-with-docker-compose-recommended)
   - [Option B: Running Locally with Mise / Native CLI](#option-b-running-locally-with-mise--native-cli)
10. [Connecting a New Client Application](#connecting-a-new-client-application)
11. [Running the Automated Test Suites](#running-the-automated-test-suites)
   - [1. End-to-End Functional Test Suite (Cucumber)](#1-end-to-end-functional-test-suite-cucumber)
   - [2. Component Unit Test Suites & Code Coverage (100% Enforced)](#2-component-unit-test-suites--code-coverage-100-enforced)
   - [3. Static Analysis & Linting (RuboCop, Checkstyle, Spotless, Oxlint)](#3-static-analysis--linting-rubocop-checkstyle-spotless-oxlint)
   - [4. Automated OWASP ZAP Security Scanning (DAST)](#4-automated-owasp-zap-security-scanning-dast)
12. [Repository Structure & Subsystem Index](#repository-structure--subsystem-index)

---

## System Architecture & Blueprints

### 1. Component Topology & Network Perimeter Architecture

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
        ClientManager["Client Manager UI (poc-client-manager :3001)<br/>• Next.js 16 + React 19 Admin Dashboard<br/>• WebCrypto ECDSA P-256 Key Pair Generator<br/>• Calls Spring Admin API with X-Admin-Api-Key"]
    end

    subgraph DataNet ["Isolated Infrastructure & Data Layer"]
        Postgres[("PostgreSQL 16 (poc-postgres :5432)<br/>• Strict Java-Only Access Policy<br/>• ACID Authorizations & Client Registrations<br/>• app_users Table with BCrypt Hashes<br/>• Flyway Versioned Migrations (V1-V4)")]
        Redis[("Redis 7 (poc-redis :6379)<br/>• DB 0: Rails SSO Sessions (session:UUID, 2h TTL)<br/>• DB 0: DPoP Single-Use Nonces (60s TTL)<br/>• DB 0: JTI Assertion Replay Prevention (5m TTL)<br/>• DB 0: Pub/Sub Cluster Invalidation (oauth2as:clients:reload)<br/>• DB 1: Demo Client Token Store")]
        KMS["AWS KMS / LocalStack (poc-localstack :4566)<br/>• ECC_NIST_P256 Asymmetric Signing Boundary<br/>• Key Aliases: alias/oauth2-signing-key & -previous<br/>• Private Keys NEVER Leave KMS HSM Boundary"]
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
    SpringAS -->|"Asymmetric ES256 Digest Signing (RPC)"| KMS
    DemoClient -->|"Token Cache (DB 1)"| Redis
```

---

### 2. End-to-End Interactive Protocol Exchange

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
    Note over Client: 1. Generate PKCE code_verifier & S256 code_challenge<br/>2. Generate ephemeral DPoP EC key pair<br/>3. Sign private_key_jwt client assertion (ES256)<br/>4. Sign initial DPoP proof for /oauth2/par (ES256)<br/>5. Server-Determined Scopes: Omit client scope parameter
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
    Spring->>KMS: kms:Sign(JARM payload digest, ECDSA_SHA_256)
    KMS-->>Spring: JARM ES256 Signature (DER -> raw IEEE P1363)
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
    Note over Client: 1. Verify JARM JWT signature against Spring Auth Server JWKS<br/>2. Validate iss, aud (demo-client), exp, and state<br/>3. Extract authorization code from validated claims<br/>4. Sign private_key_jwt client assertion (ES256)<br/>5. Attempt initial code exchange
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
    Note over Spring: 1. Validate & consume DPoP-Nonce from Redis (single-use)<br/>2. Validate private_key_jwt assertion (ES256)<br/>3. Verify PKCE code_verifier against stored challenge<br/>4. Bind Server-Determined Scopes from PostgreSQL<br/>5. Embed DPoP thumbprint (cnf.jkt) in Access Token<br/>6. Embed at_hash & c_hash in ID Token
    Spring->>KMS: kms:Sign(Access Token & ID Token digests, ECDSA_SHA_256)
    KMS-->>Spring: ES256 Signatures
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

### 3. Token & Session Lifecycle State Machine

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

### 4. AWS KMS Multi-Key Rotation State Machine

```mermaid
stateDiagram-v2
    [*] --> Active_Key: Created in AWS KMS (ECC_NIST_P256, SIGN_VERIFY)<br/>Assigned alias/oauth2-signing-key
    
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
        text public_key_pem "ECDSA NIST P-256 Public Key (PEM)"
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

### 6. Two-Stage Defense-in-Depth Password Pipeline

```mermaid
flowchart LR
    User["User Types Password<br/>('secret123')"] --> ClientTier["Client Tier (Rails IdP / Manager)<br/>• Computes SHA-256(plaintext)<br/>• Never stores or logs plaintext"]
    ClientTier -->|"TLS Network Transport<br/>(Fixed 64-char Hex Digest)<br/>Plaintext NEVER crosses wire!"| Boundary["Spring Auth Server Boundary<br/>(/api/admin/users/authenticate)<br/>Protected by X-Admin-Api-Key"]
    Boundary --> ServerTier["Server Tier (Spring Security)<br/>• Evaluates is_fraud flag first<br/>• Verifies via BCryptPasswordEncoder(10)<br/>• Salted, adaptive GPU-resistant hashing"]
    ServerTier --> Storage[("PostgreSQL app_users<br/>password_hash = $2b$10$...<br/>Safe against offline brute force")]
```

---

## Enterprise Standards & Security Controls Reference Matrix

The matrix below provides a unified specification, implementation, and enforcement reference for all identity, cryptographic, and security controls across the platform.

```mermaid
flowchart TB
    subgraph EnterpriseStandards ["Governing Standards & Profiles"]
        OAuth21["OAuth 2.1 Draft 11<br/>• Mandatory PKCE S256<br/>• Deprecate Implicit & Password Grants<br/>• Strict Exact Redirect Matching"]
        FAPI2["FAPI 2.0 Security Profile<br/>• Mandatory RFC 9126 PAR<br/>• Sender-Constraining (RFC 9449 DPoP)<br/>• Asymmetric Auth (RFC 7523 private_key_jwt)<br/>• Cryptographic Response Mode (RFC 9221 JARM)"]
        FIPS["FIPS 140-3 Cryptographic Posture<br/>• Level 3 Hardware Boundary (AWS KMS HSM)<br/>• ECDSA NIST P-256 (ES256) / FIPS 186-5<br/>• 128-bit Symmetric Security Strength"]
        OIDC["OpenID Connect Core 1.0<br/>• Discovery & Dynamic JWKS Metadata<br/>• at_hash & c_hash Integrity Verification<br/>• OIDC Back-Channel Logout 1.0 Push"]
    end

    subgraph EnforcedInCode ["Application Implementation Components"]
        direction TB
        AS["Spring Authorization Server Engine<br/>• StrictClientAssertionAuthenticationConverter (ES256 only)<br/>• StrictDPoPTokenRequestAuthenticationConverter<br/>• DPoPNonceFilter (Atomic Redis SETNX nonces)<br/>• JarmAuthorizationResponseHandler (KMS ES256 signing)<br/>• ClientPreDeterminedScopeConverter (Server-governed scopes)<br/>• OidcBackChannelLogoutService (Asynchronous retry)"]
    end

    OAuth21 --> AS
    FAPI2 --> AS
    FIPS --> AS
    OIDC --> AS
```

| Capability / Control | Governing Standard | Impl. | Enforced | Baseline Limitation & Enforced Policy | Enforcement Mechanism & Code Location | Security Threat Mitigated |
|---|---|:---:|:---:|---|---|---|
| **Pushed Authorization Requests (PAR)** | [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) | [x] | [x] | Parameters in front-channel URL are leaked in browser history and proxy logs. Enforces backchannel `POST /oauth2/par` over TLS; returns opaque single-use `request_uri` (60s TTL). Inline auth parameters at `/oauth2/authorize` fail closed. | `OAuth2AuthorizationServerConfigurer.pushedAuthorizationRequestEndpoint()` | Query string leakage (CWE-598), parameter tampering |
| **DPoP Sender-Constrained Tokens** | [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | [x] | [x] | Bearer tokens (RFC 6750) exfiltrated via memory or logs can be replayed. Enforces binding access tokens to client ephemeral EC key thumbprint (`cnf.jkt`). Token endpoint mandates `DPoP` HTTP header. | `StrictDPoPTokenRequestAuthenticationConverter`, `TokenCustomizerConfig` | Bearer token exfiltration and unauthorized replay |
| **DPoP Server-Provided Nonces** | [RFC 9449 §8](https://datatracker.ietf.org/doc/html/rfc9449#section-8) | [x] | [x] | Proof replay permitted within clock skew window. Enforces single-use server nonces stored in Redis (60s TTL). Initial token requests trigger `HTTP 400 use_dpop_nonce` challenge. Subsequent proof must bind nonce, atomically consumed via `setIfAbsent`. | `DPoPNonceFilter` | Clock-skew proof replay, pre-computed proof attacks |
| **Proof Key for Code Exchange (PKCE S256)** | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) / [OAuth 2.1 §4.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11) | [x] | [x] | Cleartext codes intercepted via custom schemes or browser extensions. Mandatory PKCE (`requireProofKey: true`). Plain `code_challenge_method` rejected; high-entropy SHA-256 (`S256`) strictly enforced. | Client settings (`requireProofKey: true`), `OAuth2AuthorizationCodeAuthenticationProvider` | Authorization code interception (CWE-200) and code injection |
| **JWT-Secured Authorization Response Mode (JARM)** | [RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221) | [x] | [x] | Front-channel redirects expose cleartext parameters (`?code=...` or `?error=...`), allowing code injection or phishing via forged error descriptions. Enforces signing all front-channel responses into AWS KMS ES256 JWS (`?response=<jwt>`). Plaintext callback parameters rejected. | `JarmAuthorizationResponseHandler`, `JarmErrorResponseHandler`, `TokenValidator` | Parameter tampering, code injection, phishing via forged errors |
| **Asymmetric Client Authentication (`private_key_jwt`)** | [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | [x] | [x] | Static client secrets are leaked in configs, git, or logs, and lack non-repudiation. Shared secrets are completely disabled (`HTTP 401`). Clients authenticate by signing assertion JWTs with their registered ECDSA NIST P-256 (`ES256`) key. | `StrictClientAssertionAuthenticationConverter`, `ClientAssertionDecoderFactory` | Credential stuffing, static secret leakage, brute force |
| **Client Assertion JTI Replay Prevention** | [RFC 7523 §3](https://datatracker.ietf.org/doc/html/rfc7523#section-3) / [RFC 8725 §3.8](https://datatracker.ietf.org/doc/html/rfc8725#section-3.8) | [x] | [x] | Intercepted client assertions replayed over internal networks. Assertion `jti` tracked in Redis (`oauth2:jti:<id>`, 5-minute TTL) via atomic `setIfAbsent`, rejecting replayed assertions with `HTTP 401`. | `ClientAssertionDecoderFactory` | Client assertion interception and replay |
| **Strict Algorithm Pinning (`alg: ES256`)** | [RFC 8725 §3.1](https://datatracker.ietf.org/doc/html/rfc8725#section-3.1) | [x] | [x] | Decoders accepting `none` or symmetric HMAC `HS256` allow signature bypass (CVE-2015-9235). Server and client libraries strictly enforce `alg == "ES256"`. All symmetric or unapproved asymmetric algorithms fail closed. | `SingleKeyJWSKeySelector`, `KmsEcSigner`, `TokenValidator` | JWT algorithm confusion and signature bypass |
| **Authorization Server Issuer Identification** | [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | [x] | [x] | Clients interacting with multiple IdPs cannot identify which server minted the code. AS returns explicit `iss` in response and JARM payload. Client verifies issuer before code exchange. | `JarmAuthorizationResponseHandler`, `oauth2_client_kit/client.rb` | OAuth 2.0 Mix-Up attacks |
| **Access Token Integrity Hash (`at_hash`)** | [OIDC Core 1.0 §3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken) | [x] | [x] | ID Tokens lack cryptographic binding to access tokens. AS computes SHA-256 left-half base64url hash of access token and embeds in ID Token; client verifies before establishing session. | `TokenCustomizerConfig`, `oauth2_client_kit/client.rb` | Access token substitution in flight |
| **Authorization Code Integrity Hash (`c_hash`)** | [OIDC Core 1.0 §3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken) | [x] | [x] | ID Tokens lack cryptographic binding to authorization codes. AS computes SHA-256 left-half base64url hash of code and embeds in ID Token; client verifies during exchange. | `TokenCustomizerConfig`, `oauth2_client_kit/client.rb` | Authorization code substitution and injection |
| **OpenID Connect Provider Discovery** | [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | [x] | [x] | Misconfigured clients vulnerable to algorithm downgrade. Serves discovery metadata at `/.well-known/openid-configuration`, advertising strictly supported algorithms (`ES256`) and auth methods (`private_key_jwt`). | `oidc.providerConfigurationEndpoint()` | Downgrade attacks, metadata spoofing |
| **JSON Web Key Set (JWKS)** | [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | [x] | [x] | Slow key resolution or cleartext key distribution. In-memory `ImmutableJWKSet` serves public EC keys at `/oauth2/jwks` in sub-millisecond response time with zero KMS latency. | `KeyConfig` | Key resolution bottlenecks and tampering |
| **Graceful Multi-Key Overlap Rotation** | [NIST SP 800-57 Part 1](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | [x] | [x] | Abrupt key cutovers invalidate in-flight tokens. Concurrently publishes active (`alias/oauth2-signing-key`) and retiring (`alias/oauth2-signing-key-previous`) keys at `/oauth2/jwks` across token TTL window. | `KeyConfig`, `rotate_kms_keys.sh` | Service outages and token rejection during rotation |
| **OpenID Connect Back-Channel Logout** | [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | [x] | [x] | Front-channel logouts fail if users close browsers or third-party cookies are blocked. AS dispatches signed `logout_token` JWS asynchronously to client endpoints with 3-attempt exponential backoff. | `OidcBackChannelLogoutService`, `TokenStore` | Incomplete session invalidation, zombie sessions |
| **OpenID Connect RP-Initiated Logout** | [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | [x] | [x] | Post-logout redirect manipulation and open redirects. Validates `id_token_hint`, compares `post_logout_redirect_uri` against client whitelist, evicts `SHARED_SESSION_ID` from Redis; features `GracefulLogoutHandler` fallback. | `AuthorizationServerConfig`, `GracefulLogoutHandler` | Open redirect vulnerabilities, post-logout hijacking |
| **OAuth 2.0 Token Revocation** | [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | [x] | [x] | Revoked tokens remain usable until natural expiry. Authenticated `/oauth2/revoke` purges authorizations in PostgreSQL and immediately flushes Redis session caches. | `AuthorizationServerConfig`, `JdbcOAuth2AuthorizationService` | Zombie sessions and persisting authorizations |
| **OAuth 2.0 Token Introspection (`identity_checkpoint!`)** | [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | [x] | [x] | Resource servers trust stale access tokens until expiry. Real-time `/oauth2/introspect` check; client gem provides `identity_checkpoint!` pre-flight guard before sensitive actions (e.g. payments). | `AuthorizationServerConfig`, `ControllerMethods#identity_checkpoint!` | Unauthorized execution of high-value actions |
| **Server-Determined Authorization Scopes** | Enterprise Security Policy | [x] | [x] | Clients request arbitrary scopes; misconfigurations lead to privilege escalation. Client scope parameter ignored; authorized scopes pre-determined and assigned strictly from PostgreSQL registered client config. | `ClientPreDeterminedScopeAuthorizationRequestConverter` | Client privilege escalation |
| **Zero Static Shared Secrets** | [OAuth 2.1 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) | [x] | [x] | Shared secrets leaked in code, configs, or DB breaches. `client_secret` column and mechanisms completely eradicated; all clients authenticate via asymmetric ECDSA NIST P-256 key pairs. | `oauth2_registered_client`, `PostgresRegisteredClientRepository` | Secret exfiltration, hardcoded credentials, brute force |
| **Two-Stage Defense-in-Depth Password Pipeline** | [NIST SP 800-63B §5.1.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html) | [x] | [x] | Plaintext passwords transmitted over network; stored with single or weak hashes. Client computes SHA-256 pre-hash (raw password never crosses wire); Spring applies `BCrypt(cost=10)` adaptive salt before DB persistence. | `users.ts`, `sessions_controller.rb`, `UserAdminController` | Network credential sniffing, offline rainbow table attacks |
| **Hardware-Backed Asymmetric Signing Boundary** | [FIPS 140-2 / FIPS 140-3 Level 3](https://csrc.nist.gov/publications/detail/fips/140/3/final) | [x] | [x] | Private keys stored on disk or loaded into JVM heap memory; vulnerable to heap inspection. Signing keys reside in AWS KMS HSM (`ECC_NIST_P256`). Token digest signing executed via KMS RPC. Keys never enter host memory. Startup fails closed if KMS unreachable. | `KmsEcSigner`, `KmsJwtEncoder`, `KeyConfig` | Memory scraping, heap dumps, core dump exfiltration |
| **Edge Perimeter DMZ & Administrative Isolation** | Zero-Trust Architecture | [x] | [x] | Admin/actuator endpoints co-located on public ports; vulnerable to SSRF. Nginx edge proxy exposes public OAuth routes on port 9000, returning `403 Forbidden` for `/api/admin/*` and `/actuator/*`. Internal bastion on port 9001 requires constant-time `X-Admin-Api-Key`. | `poc-nginx/nginx.conf`, `AdminApiKeyFilter` | SSRF, management exposure, unauthorized client manipulation |
| **In-Memory Near-Cache with Cluster Invalidation** | High-Performance Architecture | [x] | [x] | Relational DB query on every request causes database contention and latency spikes. Client records and public keys cached in `ConcurrentHashMap` (~0.001 ms lookup); mutations broadcast via Redis Pub/Sub (`oauth2as:clients:reload`) for cluster invalidation. | `PostgresRegisteredClientRepository`, `ClientReloadRedisSubscriber` | Database contention, authorization latency bottlenecks |
| **Native HTTP/2 Stream Multiplexing (`h2c`)** | [RFC 9113](https://datatracker.ietf.org/doc/html/rfc9113) | [x] | [x] | TCP handshake overhead, connection churn, and head-of-line blocking under burst traffic. `server.http2.enabled: true` in `application.yml` allowing concurrent request streams over a single TCP socket. | `spring-auth-server/src/main/resources/application.yml` | Connection churn, latency spikes, head-of-line blocking |
| **Constant-Time Cryptographic Verification** | Side-Channel Defense | [x] | [x] | String equality comparisons leak timing information. All credential and API key comparisons use constant-time `MessageDigest.isEqual`. | `AdminApiKeyFilter`, `UserAdminController` | Timing side-channel attacks |
| **Strict Input & Session Validation** | Defensive Architecture | [x] | [x] | Malformed session IDs cause NoSQL/Redis injection or cache pollution. Session IDs strictly validated as UUIDv4 before Redis lookups; cookies enforce `HttpOnly`, `SameSite: Lax`, and `Secure`. | `SharedRedisSessionFilter`, `sessions_controller.rb` | Session fixation, Redis command injection, cookie theft |
| **OWASP Defense-in-Depth Security Headers** | OWASP Top 10 | [x] | [x] | Missing headers leave browser vulnerable to clickjacking and MIME sniffing. Strict headers applied: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`, `Referrer-Policy: strict-origin-when-cross-origin`. | `SecurityConfig`, `nginx.conf` | Clickjacking, MIME-type confusion, XSS |
| **Standardized OAuth 2.1 CORS Policy** | [OAuth 2.1 §1.6](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11) | [x] | [x] | Overly permissive CORS opens internal endpoints. Strict CORS configuration allowing preflight `OPTIONS` for registered browser clients on token endpoints with exposed `DPoP-Nonce` header. | `CorsConfig` | Cross-origin request forgery, unauthorized cross-origin access |
| **Automated Database Authorization Pruning** | Data Hygiene & Lifecycle | [x] | [x] | Expired authorizations accumulate indefinitely, degrading query performance. Flyway V2 B-tree indices on authorization expiry timestamps + scheduled cleanup service (`OAuth2AuthorizationCleanupService`) purging expired records nightly. | `V2__create_authorization_expiry_indices.sql`, `OAuth2AuthorizationCleanupService` | Unbounded database table growth, query degradation |
| **JWT-Secured Authorization Request (JAR)** | [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101) | [ ] | [ ] | Documented design option. Not implemented because RFC 9126 PAR already provides superior confidentiality and integrity without requiring client-side JWS wrapping of request objects. | [`jar_rfc9101_design_option.md`](docs/architecture/jar_rfc9101_design_option.md) | Request parameter tampering (addressed by PAR) |
| **Mutual-TLS Client Authentication (mTLS)** | [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) | [ ] | [ ] | Documented roadmap option for B2B clients. RFC 7523 `private_key_jwt` currently enforced. | [`higher_key_and_crypto_standards.md`](docs/architecture/higher_key_and_crypto_standards.md) | Client impersonation (addressed by `private_key_jwt`) |

---

## Cryptographic Architecture & FIPS 140-3 Posture

### Algorithmic Baseline: ECDSA NIST P-256 (ES256)

The platform standardizes on **ECDSA NIST P-256 (`ES256` / `prime256v1` / `secp256r1`)** across all architectural tiers:

| Dimension | RSA-2048 (`RS256`) [Legacy] | ECDSA P-256 (`ES256`) [Enforced] | Architectural Benefit |
|---|---|---|---|
| **Security Strength** | 112 bits symmetric equivalent | **128 bits symmetric equivalent** | Meets NIST SP 800-57 recommendations through and beyond 2030 (matches AES-128). |
| **Signature Wire Size** | 256 bytes (2,048 bits) | **64 bytes (512 bits raw IEEE P1363)** | **75% reduction** in signature payload size, minimizing HTTP header overhead on DPoP and JARM hops. |
| **Public Key Size** | ~450 bytes (X.509 PEM) | **~178 bytes (X.509 PEM)** | Smaller JWKS metadata responses and lower memory footprint. |
| **Ephemeral Key Generation** | ~39.85 ms (prime search) | **~0.01 ms (curve point multiplication)** | Sub-millisecond client key generation for ephemeral DPoP keys. |
| **End-to-End Session Latency** | 494.5 ms average (p95 = 686.0 ms) | **167.1 ms average (p95 = 217.0 ms)** | Lower latency under concurrent load due to lightweight curve mathematics and compact wire payloads. |
| **Financial-Grade Conformance** | Optional / Legacy | **Primary Recommended Algorithm** | Aligned with Financial-grade API (FAPI 2.0 Security Profile). |

### Signature Transcoding: ASN.1 DER to Raw IEEE P1363

AWS KMS outputs ECDSA signatures encoded in ASN.1 DER format (RFC 3279), whereas JSON Web Signature (JWS / RFC 7515 §A.3) strictly mandates raw IEEE P1363 $(R \parallel S)$ 64-byte concatenated format:

- **Token Signing ([`KmsEcSigner.java`](spring-auth-server/src/main/java/com/example/authserver/security/KmsEcSigner.java)):** Upon receiving the DER signature from AWS KMS `kms:Sign`, the signer transcodes the DER sequence into the 64-byte IEEE P1363 format via `com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToConcat(derSignature, 64)`.
- **Client Assertion Validation ([`ClientAssertionDecoderFactory.java`](spring-auth-server/src/main/java/com/example/authserver/security/ClientAssertionDecoderFactory.java)):** Accepts IEEE P1363 JWS signatures natively, validating them against the client's registered `ECPublicKey`.

### Cryptographic Boundary Definition

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SYSTEM CRYPTOGRAPHIC BOUNDARY                             │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │               AWS KMS HARDWARE SECURITY MODULE (HSM) BOUNDARY                  │   │
│   │                                                                                │   │
│   │  • Key Specification: ECC_NIST_P256 (NIST P-256 / secp256r1)                   │   │
│   │  • Algorithm: ECDSA_SHA_256 (FIPS 186-5 & FIPS 180-4 Approved)                 │   │
│   │  • Key Material: Generated inside HSM; NEVER enters host or JVM memory         │   │
│   │  • Real AWS Certification: FIPS 140-2 Level 3 / FIPS 140-3 Level 3 Transition │   │
│   │    (NIST CMVP Certificate #4489 / #4140)                                       │   │
│   │  • LocalStack (Dev Environment): Software emulation only (Non-FIPS)            │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│                                           ▲                                            │
│                                           │ RPC over TLS                               │
│                                           ▼                                            │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │                       APPLICATION & RUNTIME BOUNDARIES                         │   │
│   │                                                                                │   │
│   │  • JVM Crypto: OpenJDK SunEC/SunJCE (Requires ACCP / bc-fips in production)    │   │
│   │  • Client Assertions: In-memory ECDSA verification against PostgreSQL EC keys │   │
│   │  • Password Storage: BCrypt cost=10 (Requires PBKDF2 for strict FIPS 140-3)   │   │
│   │  • Operating System: Standard Linux containers (Requires FIPS host kernel)    │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Development Environment (LocalStack):**
   - Uses software emulation in LocalStack for local testing.
   - **Status: Non-FIPS (Development & Testing only).** Provides functional API parity without hardware cryptographic guarantees.
2. **Production AWS Deployment (AWS KMS):**
   - Asymmetric signing keys reside within AWS Key Management Service Hardware Security Modules.
   - AWS KMS HSMs are certified under **FIPS 140-2 Level 3** overall, and physical security is validated to **FIPS 140-3 Level 3** (NIST CMVP Cert #4489 / #4140).
   - **Status: Token Signing Key Storage and Private Key Operations ARE FIPS 140-2/140-3 Level 3 Validated.** Private keys cannot be extracted via heap inspection, core dumps, or operating system compromise.

### System-Wide FIPS 140-3 Compliance Roadmap

Certifying an *entire application system* as FIPS 140-3 compliant requires that **all** cryptographic operations (including in-memory verification, TLS termination, and password hashing) execute within NIST CMVP-validated modules. The required production steps are:

1. **Connect to AWS KMS FIPS Endpoints:**
   - Configure AWS SDK endpoint: `https://kms-fips.<region>.amazonaws.com`.
   - Enforces FIPS-validated TLS 1.2/1.3 sessions for all RPC calls between the Authorization Server and AWS KMS.
2. **Install a FIPS-Validated Cryptographic Provider in the JVM:**
   - Configure container JVM with **Amazon Corretto Crypto Provider (ACCP)** in FIPS mode, or install **Bouncy Castle FIPS (`bc-fips-1.0.2+.jar`)** in `java.security`.
   - Ensures in-memory SHA-256 digests, DPoP thumbprints, and client assertion checks execute within a validated cryptographic module.
3. **Align Password Hashing with NIST SP 800-132:**
   - Migrate `app_users.password_hash` to NIST-approved **PBKDF2 with HMAC-SHA-256** (minimum 600,000 iterations), or delegate authentication to an enterprise FIPS-compliant IdP via SAML 2.0 / OIDC federation.
4. **Enable FIPS Mode on Host Operating System Kernel:**
   - Run containers on Amazon Linux 2023 or RHEL with the `fips=1` kernel boot parameter enabled.
5. **Enforce FIPS-Approved Cipher Suites at Reverse Proxy / ALB:**
   - Terminate TLS on the Application Load Balancer (ALB) or Nginx edge proxy using only FIPS-approved cipher suites (e.g., `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `ECDHE-ECDSA-AES128-GCM-SHA256`).

---

## OpenID Connect (OIDC) Conformance & Profile Alignment

The platform provides full conformance with OpenID Connect Core 1.0 specifications, hardened to align with the **Financial-grade API (FAPI 2.0 Security Profile)**:

- **Discovery Endpoint (`/.well-known/openid-configuration`):** Publishes OIDC 1.0 discovery metadata including supported response types, response modes (`jwt`, `query.jwt`), grant types, and signing algorithms (`ES256`).
- **JWKS Endpoint (`/oauth2/jwks`):** Serves public EC P-256 keys in RFC 7517 format with unique `kid` identifiers.
- **Authorization Endpoint (`/oauth2/authorize`):** Supports `response_type=code` with `scope=openid` via mandatory RFC 9126 PAR.
- **Token Endpoint (`/oauth2/token`):** Exchanges authorization codes for Access Tokens, ID Tokens, and Refresh Tokens under mandatory DPoP and `private_key_jwt` constraints.
- **UserInfo Endpoint (`/userinfo`):** Returns standard OIDC claims (`sub`, `email`, `name`, `roles`) protected by DPoP sender-constraining.
- **RP-Initiated & Back-Channel Logout:** Implements OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 with signed `logout_token` JWS delivery.

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
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6ImRlbW8tY2xpZW50LWtleS0xIn0.eyJpc3MiOiJkZW1vLWNsaWVudCIsInN1YiI6ImRlbW8tY2xpZW50IiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwL29hdXRoMi9wYXIiLCJqdGkiOiI0NDM1MjM0OS0xMmEzLTRjOTktODFlMS0zOTQ4MmFjOTBkMTIiLCJleHAiOjE3NTgxMzAzMjAsImlhdCI6MTc1ODEzMDIwMH0.KjS...
```

**Decoded `client_assertion` (RFC 7523 JWT):**
```json
{
  "header": { "alg": "ES256", "kid": "demo-client-key-1" },
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

Upon user authentication at the Rails IdP, the Spring Authorization Server computes an ES256 signature via AWS KMS and redirects the browser with the signed JWT in the `response` query parameter:

```http
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?response=eyJhbGciOiJFUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJhdWQiOlsiZGVtby1jbGllbnQiXSwiaWF0IjoxNzU4MTMwMjAwLCJleHAiOjE3NTgxMzAzMjAsImNvZGUiOiJhdXRoLWNvZGUtZGIzOTRhYzktOWEzOS00ZjExLWExMGEtMzQ1Njg5YWJjZGVmIiwic3RhdGUiOiJhZjBpZmpzbGRraiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c...
```

**Decoded JARM JWS Header:**
```json
{
  "alg": "ES256",
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
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6ImRlbW8tY2xpZW50LWtleS0xIn0...
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

The client rebuilds the DPoP proof embedding `"nonce": "dpop-nonce-9fa3148e-6701-447a-8bd1-b1e612f0e014"`:

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
&client_assertion=eyJhbGciOiJFUzI1NiIs...
```

**Successful Token Response (`HTTP 200 OK`):**
```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6WyJkZW1vLWNsaWVudCJdLCJleHAiOjE3NTgxMzExMDAsImlhdCI6MTc1ODEzMDIwMCwianRpIjoiYTgyNGViMTItZTkxNy00YmU3LWJjOTAtY2QwNzhlZTAxMmEyIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCB1c2VyLnJlYWQgZGVtby5zZWNyZXRfYWNjZXNzIiwiY25mIjp7ImprdCI6InExWmdvblp2WmpjSmJ3Nlp3Z011bVlYbF93MVgweExnY2V0Wl92SWI0S1EifX0.H7...",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "rt_87b92f4c9ae2438b97d1b324",
  "scope": "openid profile email user.read demo.secret_access",
  "id_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6WyJkZW1vLWNsaWVudCJdLCJleHAiOjE3NTgxMzExMDAsImlhdCI6MTc1ODEzMDIwMCwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJhdF9oYXNoIjoiN3FYcVp2WmpjSmJ3Nlp3Z011bVlYQSIsImNfaGFzaCI6IjNSbVlYS2J2WmpjSmJ3Nlp3Z011bVEifQ.P0..."
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

token=eyJhbGciOiJFUzI1Ni...<access_token>
&token_type_hint=access_token
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs...
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
&client_assertion=eyJhbGciOiJFUzI1NiIs...
```

**Revocation Response (`HTTP 200 OK`):**
```http
HTTP/1.1 200 OK
```
*(Subsequent introspection queries return `{"active": false}`).*

---

### Hop 5: OpenID Connect Back-Channel Logout 1.0 (Signed `logout_token` JWS)

When session revocation occurs, Spring Authorization Server dispatches a server-to-server POST to registered client backchannel endpoints:

```http
POST /oidc/backchannel_logout HTTP/1.1
Host: demo-client:8080
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJFUzI1NiIsImtpZCI6Imttcy1hdXRoLXNlcnZlci1rZXktMSJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJzdWIiOiJhbGljZV9zbWl0aCIsImF1ZCI6ImRlbW8tY2xpZW50IiwiaWF0IjoxNzU4MTMwMjUwLCJqdGkiOiJkM2E1ZjAxOC02NTY2LTQ5NWEtOGI3Zi1mZmYxMzk1ZjBlMzQiLCJzaWQiOiI3YTg5YzgxZi1lMzU3LTRjOTQtYjZhMC1hMzg1ZWVlYTRiN2YiLCJldmVudHMiOnsiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9ldmVudC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fX0.Kx...
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
> [!NOTE]
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

## Performance & Concurrency Benchmarks

The automated **k6** load testing suite in [`k6/oauth_load_test.js`](k6/oauth_load_test.js) evaluates throughput, concurrency limits, and latency percentiles across two concurrent scenarios:
1. **`full_oauth_session_flow`:** 5 concurrent virtual users executing the full 6-hop interactive authorization session with dynamic multi-user pool isolation across PostgreSQL and Redis.
2. **`discovery_and_jwks_burst`:** Ramping arrival rate up to 30 req/sec querying discovery and JWKS endpoints.

### Measured Empirical Benchmarks

| Metric | Target / Threshold | In-Memory Software Signing | AWS KMS Hardware Signing (`ECC_NIST_P256` / `ES256`) | Status |
|---|---|---|---|:---:|
| **Cryptographic Boundary** | Hardware HSM | Software JCE (JVM memory) | **AWS KMS HSM (FIPS 140-2/3 Level 3 in AWS)** | **PASS** |
| **Algorithm Pinning** | Strict `ES256` | Optional | **Strict ES256 enforced (`none` & `HS256` rejected)** | **PASS** |
| **Key Rotation Support** | Multi-Key JWKS | Single key | **Graceful Multi-Key JWKS (Active + Previous)** | **PASS** |
| **KMS Signatures / Flow** | Non-repudiation | 0 (Local CPU) | **3 (JARM Auth Code + Access Token + ID Token)** | **PASS** |
| **User & Session Isolation** | Isolated sessions | Single shared user | **Dynamic Multi-User Pool (`setup`/`teardown`)** | **PASS** |
| **Auth Session Completion** | > 95.0% | `98.79%` | **`100.00%`** (225 / 225 completed) | **PASS** |
| **Hourly Session Capacity** | > 3,000 sessions/hr | ~29,400 sessions/hr | **~27,000 sessions/hr** (~7.5 sessions/sec) | **PASS** |
| **Full Session Latency (p50)** | < 500 ms | `112 ms` | **`163.0 ms`** (6 hops + 3 KMS calls + DB + Redis + BCrypt) | **PASS** |
| **Full Session Latency (p95)** | < 1,500 ms | `146 ms` | **`217.0 ms`** | **PASS** |
| **Average Full Session Latency** | < 600 ms | `121.4 ms` | **`167.1 ms`** (min 122 ms, max 382 ms) | **PASS** |
| **Total HTTP Error Rate** | < 1.0% | `0.04%` | **`0.00%`** (0 / 3,278 requests failed) | **PASS** |
| **Total HTTP Throughput** | > 50 req/sec | ~108 req/sec | **104.5 req/sec** (3,278 requests in 31.4s) | **PASS** |
| **Public Metadata Check Rate** | 100.0% | `100.00%` | **`100.00%`** (100% returned 200 OK) | **PASS** |

> For complete benchmarking methodology and scaling analysis, see [`k6/README.md`](k6/README.md) and [`docs/architecture/performance_and_scalability.md`](docs/architecture/performance_and_scalability.md).

---

## Production Hardening & Deployment Roadmap

| Capability / Control | Implementation Details | Benefits | Trade-offs & Operational Costs | Classification |
|---|---|---|---|---|
| **Edge Web Application Firewall (WAF)** | Deploy AWS WAF or Cloudflare in front of the Application Load Balancer (ALB) or Nginx proxy with managed rule groups (Core Rule Set, Known Bad Inputs, Amazon IP Reputation) and rate limiting on `/oauth2/token` and `/oauth2/par`. | Shields application containers from volumetric DDoS, credential stuffing, and malicious scraper bots before requests hit application runtimes. | Minor latency addition (1–3 ms); managed service costs; requires periodic rule tuning. | Cloud Infrastructure Configuration |
| **TLS 1.3 & HSTS at Reverse Proxy / ALB** | Terminate TLS with ACM certificates on ALB / Nginx; enforce TLS 1.2/1.3; redirect HTTP 80 to 443; inject `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header. | Eliminates cleartext traffic on public networks; offloads TLS handshakes from application instances; prevents SSL stripping. | Requires automated certificate renewal and security group management. | Cloud Infrastructure Configuration |
| **Per-Client & Edge Rate Limiting** | **Edge Layer**: Configure Nginx `limit_req_zone` for IP-based throttling on `/oauth2/token` and `/oauth2/par`.<br/>**App Layer**: Add distributed per-client rate-limiting filter (e.g. Bucket4j backed by Redis) keyed by authenticated `client_id`. | Protects the authorization server and KMS Sign API from runaway client loops, credential stuffing, or compromised client abuse. | Additional Redis round-trip latency on token exchange; requires configuring per-tier quota allocations. | Deployment Config + Codebase Change (Bucket4j in Spring) |
| **Mutual TLS (mTLS) for B2B Clients (RFC 8705)** | Configure ALB or Nginx reverse proxy with client certificate verification; pass validated client certificate headers (`X-Forwarded-Client-Cert`); implement Spring Security `TlsClientAuthenticationConverter`. | Hardware-grade client authentication using client-side X.509 certificates (e.g. smart cards, HSMs); eliminates per-request JWT assertion generation overhead. | High PKI complexity; requires managing Certificate Authorities (CAs), certificate lifecycles, and revocation lists (CRL/OCSP). | Codebase Change + Deployment Configuration |
| **Cloud Secrets Manager Integration** | Store database passwords, Redis credentials, and admin API keys in AWS Secrets Manager or HashiCorp Vault; inject securely via ECS/EKS task definitions. | Eliminates plaintext secrets in code repositories and environment configuration files; supports automated credential rotation. | Cold-start latency while retrieving secrets; additional API call costs. | Cloud Infrastructure Configuration |
| **Automated KMS Lifecycle Schedule** | Deploy an AWS EventBridge rule and Lambda function to periodically execute the rotation flow in `scripts/rotate_kms_keys.sh` (e.g. semi-annually), sending operator alerts via SNS. | Guarantees compliance with cryptographic key expiration standards (NIST SP 800-57, PCI DSS 4.0) with zero manual intervention. | Requires monitoring rotation windows to prevent premature decommissioning of keys with active in-flight tokens. | Cloud Infrastructure Configuration |
| **Distributed Redis High-Availability** | Migrate standalone Redis container to an AWS ElastiCache Redis replication group (multi-AZ with automatic failover) or Redis Sentinel; configure connection strings accordingly. | Eliminates single point of failure for SSO sessions, JTI replay prevention, and L2 client configuration caching. | Increased cloud infrastructure costs; eventual consistency considerations during failover events. | Cloud Infrastructure Configuration |

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

1. **Generate EC Key Pair**: Create a dedicated ECDSA NIST P-256 key pair (`config/keys/client_private_key.pem`).
2. **Register in Client Manager**: Provide your Client ID, Redirect URIs, and Public Key PEM via the [Client Manager UI](http://localhost:3001) or Admin REST API (`POST /api/admin/clients`).
3. **Install Client Library**: Add `gem "oauth2_client_kit"` to your `Gemfile` and run `bundle install`.
4. **Configure Initializer**: Set up `config/initializers/oauth2_client_kit.rb` with your `client_id`, private key, and issuer URL.
5. **Mount Routes & Protect Controllers**: Add `mount_oauth2_client_kit` to `config/routes.rb` and `require_authentication!` to your controllers.

> For complete step-by-step instructions and code snippets, see the [New Client Onboarding & Integration Guide](docs/guides/new_client_onboarding_guide.md).

---

## Running the Automated Test Suites

The platform employs a multi-layered testing strategy combining end-to-end browser journeys, comprehensive unit suites with 100% enforced code coverage across all services, and static analysis.

### 1. End-to-End Functional Test Suite (Cucumber)

The `e2e-tests` directory contains automated **Cucumber** / **Capybara** / **Cuprite** (headless Chrome) end-to-end scenarios executing against the live services (`demo-client :8080`, `rails-app :3000`, `nginx :9000`, `spring-auth-server :9001`):

- **`oauth_authorization.feature`**: Full interactive authorization code flow (PAR, PKCE S256, DPoP, Rails SSO redirect, `private_key_jwt` token exchange, and authenticated profile render).
- **`token_lifecycle.feature`**: Refresh token rotation with DPoP sender constraint, sensitive action authorization via real-time token introspection (`RFC 7662`), and explicit token revocation (`RFC 7009`).
- **`error_journeys.feature`**: JARM error response mode validation, simulating Account Locked (client custom view override) and Account Suspended (OAuth2ClientKit default error view).
- **`invalid_login.feature`**: Credential validation failure handling at the Rails IdP with flash error feedback.
- **`fraud_revocation.feature`**: Admin fraud flag activation via Spring Admin API immediately terminating the user's active session and revoking authorizations across Redis and PostgreSQL.

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
| **`oauth2_client_kit`** | RSpec + WebMock | SimpleCov | **100.0% Lines** (116/116 specs) | `cd oauth2_client_kit && mise exec -- bundle exec rspec` |
| **`rails-app`** | RSpec-Rails | SimpleCov | **100.0% Lines** (26/26 specs) | `cd rails-app && mise exec -- bundle exec rspec` |
| **`demo-client`** | RSpec-Rails | SimpleCov | **100.0% Lines** (8/8 specs) | `cd demo-client && mise exec -- bundle exec rspec` |
| **`client-manager`** | Vitest + React Testing Library | `@vitest/coverage-v8` | **100% All** (47/47 tests) | `cd client-manager && pnpm test` |
| **`spring-auth-server`** | JUnit 5 + Mockito | JaCoCo | **100% Branches/Lines** (184/184 tests) | `cd spring-auth-server && mise exec -- mvn test` |

### 3. Static Analysis & Linting (RuboCop, Checkstyle, Spotless, Oxlint)

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

### 4. Automated OWASP ZAP Security Scanning (DAST)

The test suite incorporates automated dynamic application security testing (DAST) using **OWASP ZAP**. In contrast to unauthenticated vulnerability crawlers, this pipeline proxies browser traffic through ZAP during the live Cucumber end-to-end journey, testing real OAuth 2.1 protocol exchanges (PAR, PKCE, DPoP, Rails sessions, JARM, Token Exchange, Introspection, and Revocation).

```bash
# Execute full OWASP ZAP security scan and generate reports
./bin/run-zap-e2e.sh
```

- **Interactive HTML Report**: `security-reports/zap-report.html`
- **Markdown Summary**: `security-reports/zap-summary.md`
- **Baseline Posture**: 0 High vulnerabilities across the full stack.

---

## Repository Structure & Subsystem Index

```
.
├── docker-compose.yml              # Multi-container orchestration (Postgres, LocalStack, Redis, Spring, Rails, Demo, Manager)
├── README.md                       # Platform architectural documentation
├── bin/
│   └── run-zap-e2e.sh              # Automated OWASP ZAP test execution & report generation script
├── zap/                            # OWASP ZAP DAST container definition & socat loopback forwarder
│   ├── Dockerfile                  # zaproxy/zap-bare image with socat installation
│   └── entrypoint.sh               # Loopback port forwarder & ZAP daemon startup
├── security-reports/               # Generated OWASP ZAP HTML & Markdown scan reports
│   ├── zap-report.html             # Interactive OWASP ZAP vulnerability assessment
│   └── zap-summary.md              # Markdown summary and alert counts by severity
├── k6/                             # Automated k6 performance and concurrency load testing suite
│   ├── oauth_load_test.js          # Multi-scenario k6 load test (Full OAuth flow + Caching burst)
│   └── README.md                   # k6 load testing execution guide & benchmark analysis
├── docs/                           # Architecture specifications and technical guides
│   ├── architecture/
│   │   ├── README.md               # Topology, communication matrix, and architecture index
│   │   ├── oauth2_par_dpop_flow.md # End-to-end PAR + DPoP + PKCE + Rails SSO sequence diagram
│   │   ├── client_config_and_caching_flow.md # Multi-tier near-cache & hot-reload sequence diagrams
│   │   ├── kms_multi_key_rotation_flow.md   # AWS KMS HSM signing & zero-downtime rotation
│   │   ├── token_lifecycle_and_logout_flow.md# Revocation, Introspection, and Backchannel Logout flows
│   │   ├── postgres_persistence_and_performance.md # Rationale for DB-backed clients & Java isolation
│   │   ├── performance_and_scalability.md   # Bottleneck audit, benchmark telemetry, and scale roadmap
│   │   ├── network_perimeter_and_proxy_routing.md # Edge proxy / ALB routing & access matrix
│   │   ├── contracts_and_data_dictionary.md # Shared session schemas, Redis taxonomy, and DB DDL
│   │   ├── user_management_and_authentication.md # app_users store, Admin API, and fraud revocation
│   │   ├── higher_key_and_crypto_standards.md # Cryptographic baseline, curves, and FIPS assessment
│   │   ├── jar_rfc9101_design_option.md     # RFC 9101 JAR design option evaluation
│   │   ├── component_interactions_and_data_flows.md # Component-by-component data ingress, storage & state matrix
│   │   └── spring_security_usage_and_divergences.md # Spring Security 7 features, divergences, and improvements
│   └── guides/
│       ├── new_client_onboarding_guide.md   # Step-by-step onboarding for new client applications
│       ├── developer_cookbook.md            # Dual-mode execution, custom claims, and cache invalidation
│       └── testing_and_troubleshooting.md   # Security testing and debugging runbooks
├── localstack/                     # LocalStack AWS KMS initialization & key provisioning
│   └── init/02-init-kms.sh         # Provisions ECC_NIST_P256 signing keys in KMS with alias
├── e2e-tests/                      # End-to-End Cucumber & Capybara/Cuprite test suite
│   ├── features/                   # 5 Gherkin feature files (8 scenarios)
│   └── README.md                   # E2E test execution & OWASP ZAP DAST documentation
├── client-manager/                 # Next.js 16 OAuth 2.1 Client Configuration Manager
│   ├── app/                        # Dashboard UI, client modals, raw JSON viewer
│   ├── lib/                        # WebCrypto P-256 key generator & Spring Admin API client
│   └── __tests__/                  # Vitest unit tests (100% coverage enforced)
├── spring-auth-server/             # Spring Boot 4 / Spring Security 7 Authorization Server
│   ├── pom.xml                     # Maven build, Checkstyle, Spotless, and JaCoCo gates
│   ├── src/test/                   # JUnit 5 + Mockito unit tests (100% coverage enforced)
│   └── src/main/                   # Custom filters, converters, KMS signers, and Flyway migrations
├── rails-app/                      # Ruby on Rails 7 Identity Provider
│   ├── app/controllers/sessions_controller.rb # Authenticates credentials & writes session to Redis
│   └── README.md                   # Rails IdP architecture & security documentation
├── oauth2_client_kit/              # Standalone Reusable OAuth 2.1 & OIDC Client Gem
│   ├── lib/                        # Core protocol engine (PAR, DPoP, private_key_jwt, JARM)
│   └── README.md                   # Gem documentation & quickstart
└── demo-client/                    # Thin Demo Rails App (Pure UI & Action Calls to Gem)
    ├── app/controllers/pages_controller.rb # Thin pages controller (landing, profile, identity_checkpoint!)
    └── README.md                   # Demo client documentation
```
