# Architecture & Communication Flows

This directory contains technical architectural diagrams and end-to-end communication sequence flows for the OAuth 2.1 & OpenID Connect platform.

---

## Component Topology & Infrastructure

```mermaid
flowchart TB
    subgraph Users ["User Agents & Administrators"]
        Browser["User Browser / Client User-Agent"]
        Admin["Administrator Browser"]
    end

    subgraph Applications ["Application Tier"]
        DemoClient["Ruby Demo Client\n(Port 8080)\nPuma + Redis DB 1"]
        RailsIdP["Rails Identity Provider\n(Port 3000)\nSession SSO Engine"]
        ClientManager["Next.js Client Manager\n(Port 3001)\nWeb Crypto + Admin UI"]
        SpringAS["Spring Authorization Server\n(Port 9000)\nSpring Boot 4 / Security 7 / Java 25"]
    end

    subgraph SecurityTier ["Cryptographic Hardware Module"]
        LocalStackKMS[("LocalStack AWS KMS\n(Port 4566)\nFIPS 140-2 Level 3 HSM Token Signing")]
    end

    subgraph DataTier ["Data & Storage Tier"]
        RedisServer[("Redis Server\n(Port 6379)\nDB 0 & DB 1")]
        PostgresDB[("PostgreSQL 16\n(Port 5432 - Java Only)\nACID Single Source of Truth")]
    end

    %% User Interactions
    Browser -->|1. Visit / Start Login| DemoClient
    Browser -->|3. Authenticate Credentials| RailsIdP
    Browser -->|4. Authorize with SHARED_SESSION_ID| SpringAS
    Admin -->|Manage Clients & Generate Keys| ClientManager

    %% Backchannel & Inter-Service Communications
    DemoClient -->|PAR, Token Exchange, UserInfo, Revoke\n(private_key_jwt + DPoP)| SpringAS
    SpringAS -.->|OIDC Back-Channel Logout\n(Signed logout_token)| DemoClient
    ClientManager -->|HTTP REST Admin API\n(X-Admin-Api-Key)| SpringAS

    %% Data Store Connections
    RailsIdP -->|Write session:uuid| RedisServer
    SpringAS -->|Read session:uuid (DB 0)\nJTI replay cache\nRedis Pub/Sub listener| RedisServer
    DemoClient -->|Store sessions & DPoP keys (DB 1)| RedisServer

    %% PostgreSQL and KMS
    SpringAS -->|JDBC Connection Pool (HikariCP)\nOnly Java connects to DB| PostgresDB
    SpringAS -->|Sign JWT Access Tokens (RS256)| LocalStackKMS
```

---

## Detailed Sequence Flow Guides

Click the links below to inspect specific end-to-end communication flows:

1. [**OAuth 2.1 Authorization Code Flow with PAR, DPoP & Rails SSO**](oauth2_par_dpop_flow.md)
   - Step-by-step breakdown of RFC 9126 PAR backchannel submission, RFC 7523 client assertion verification, Rails IdP SSO session creation, RFC 9207 issuer identification, and RFC 9449 sender-constrained DPoP token minting.

2. [**Client Configuration, Persistence & Near-Caching Flow**](client_config_and_caching_flow.md)
   - Deep dive into the **PostgreSQL Persistence $\rightarrow$ L1 JVM Near-Cache $\rightarrow$ Redis Pub/Sub Cluster Invalidation** hierarchy, demonstrating sub-millisecond lookups and secure HTTP Admin API integration without direct DB exposure.

3. [**Token Lifecycle, Revocation & OIDC Back-Channel Logout Flow**](token_lifecycle_and_logout_flow.md)
   - Detailed diagrams for RFC 7009 Token Revocation, RFC 7662 Token Introspection, and OpenID Connect Back-Channel Logout 1.0 signed JWT dispatch.

4. [**PostgreSQL Persistence, High-Performance Near-Caching & Architecture Specification**](postgres_persistence_and_performance.md)
   - Architectural deep-dive on PostgreSQL durability, AWS S3 decommissioning rationale, HikariCP configuration, Flyway schema migrations, and zero-loss horizontal scaling.

5. [**Performance, Scalability & Bottleneck Analysis**](performance_and_scalability.md)
   - Concurrency bottleneck identification, benchmark metrics (EC vs RSA DPoP, response caching, ETag 304s), resilience/retry patterns, and high-scale roadmap.

6. [**AWS KMS Key Management, Multi-Key JWKS Rotation & Algorithm Pinning**](kms_multi_key_rotation_flow.md)
   - Hardware Security Module (HSM) boundary, FIPS 140-2 Level 3 protection, zero-downtime multi-key JWKS rotation lifecycle, automated rotation tooling, and strict RFC 8725 algorithm pinning.

---

## Port & Protocol Reference

| Service | Port | Protocol / Path | Purpose |
|---|---|---|---|
| **`demo-client`** | `8080` | HTTP / TCP | End-user interactive OAuth 2.1 client application |
| **`rails-app`** | `3000` | HTTP / TCP | External login & Identity Provider (sets `SHARED_SESSION_ID`) |
| **`client-manager`** | `3001` | HTTP / TCP | Administrative UI for client configuration & Web Crypto key generation |
| **`spring-auth-server`**| `9000` | HTTP / TCP | RFC-hardened OAuth 2.1 & OIDC Authorization Server |
| **`postgres`** | `5432` | PostgreSQL / TCP | ACID persistence for registered clients & runtime authorization records |
| **`localstack`** | `4566` | HTTP / KMS API | Emulated AWS KMS (FIPS 140-2 Level 3 HSM Asymmetric Key Signing) |
| **`redis`** | `6379` | RESP / TCP | DB 0 (SSO, JTI), DB 1 (Client Tokens), and Pub/Sub cluster invalidation |

