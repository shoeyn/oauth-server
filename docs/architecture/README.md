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
        DemoClient["Ruby Demo Client<br/>(Port 8080)<br/>Puma + Redis DB 1"]
        RailsIdP["Rails Identity Provider<br/>(Port 3000)<br/>Session SSO Engine"]
        ClientManager["Next.js Client Manager<br/>(Port 3001)<br/>Web Crypto + Admin UI"]
        SpringAS["Spring Authorization Server<br/>(Port 9000)<br/>Spring Boot 4 / Security 7 / Java 25"]
    end

    subgraph SecurityTier ["Cryptographic Hardware Module"]
        LocalStackKMS[("LocalStack AWS KMS<br/>(Port 4566)<br/>FIPS 140-2 Level 3 HSM Token Signing")]
    end

    subgraph DataTier ["Data & Storage Tier"]
        RedisServer[("Redis Server<br/>(Port 6379)<br/>DB 0 & DB 1")]
        PostgresDB[("PostgreSQL 16<br/>(Port 5432 - Java Only)<br/>ACID Single Source of Truth")]
    end

    %% User Interactions
    Browser -->|1. Visit / Start Login| DemoClient
    Browser -->|3. Authenticate Credentials| RailsIdP
    Browser -->|4. Authorize with SHARED_SESSION_ID| SpringAS
    Admin -->|Manage Clients & Generate Keys| ClientManager

    %% Backchannel & Inter-Service Communications
    DemoClient -->|"PAR, Token Exchange, UserInfo, Revoke<br/>(private_key_jwt + DPoP)"| SpringAS
    SpringAS -.->|"OIDC Back-Channel Logout<br/>(Signed logout_token)"| DemoClient
    ClientManager -->|"HTTP REST Admin API<br/>(X-Admin-Api-Key)"| SpringAS

    %% Data Store Connections
    RailsIdP -->|Write session:uuid| RedisServer
    SpringAS -->|"Read session:uuid (DB 0)<br/>JTI replay cache<br/>Redis Pub/Sub listener"| RedisServer
    DemoClient -->|"Store sessions & DPoP keys (DB 1)"| RedisServer

    %% PostgreSQL and KMS
    SpringAS -->|"JDBC Connection Pool (HikariCP)<br/>Only Java connects to DB"| PostgresDB
    SpringAS -->|"Sign JWT Access Tokens (RS256)"| LocalStackKMS
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

7. [**Network Perimeter & Reverse Proxy Routing Architecture**](network_perimeter_and_proxy_routing.md)
   - External reverse proxy / ALB path routing specification isolating internal administrative APIs (`/api/admin/**`) from public OAuth 2.1 traffic, with configuration templates for AWS ALB, Nginx, Kubernetes Ingress, and Cloudflare WAF.

8. [**Interface Contracts & Unified Data Dictionary**](contracts_and_data_dictionary.md)
   - Formal JSON schema specification for the Rails $\leftrightarrow$ Spring Redis SSO session, unified Redis key taxonomy and TTL lifecycle matrix, and PostgreSQL DDL/ERD schema reference.

---

## Developer & Tester Guides

- [**Developer Cookbook & Iteration Guide**](../guides/developer_cookbook.md): Dual-mode execution (Docker vs. local IDE debugging), Admin API `curl` client registration examples, custom JWT claim recipes, and hot-cache reload commands.
- [**Testing & Troubleshooting Guide**](../guides/testing_and_troubleshooting.md): Test fixture & credential matrix, automated test execution, failure diagnostic workflows, and boilerplate for writing new functional test scenarios.

---

## Port & Protocol Reference

| Service | Port | Protocol / Path | Purpose |
|---|---|---|---|
| **`nginx`** | `9000` | HTTP / TCP | Edge perimeter reverse proxy (exposes public OAuth/OIDC, blocks /api/admin) |
| **`spring-auth-server`**| `9001` (internal) | HTTP / TCP | RFC-hardened OAuth 2.1 & OIDC Authorization Server backend (internal container :9000) |
| **`demo-client`** | `8080` | HTTP / TCP | End-user interactive OAuth 2.1 client application |
| **`rails-app`** | `3000` | HTTP / TCP | External login & Identity Provider (sets `SHARED_SESSION_ID`) |
| **`client-manager`** | `3001` | HTTP / TCP | Administrative UI for client configuration (connects directly to Spring :9000) |
| **`postgres`** | `5432` | PostgreSQL / TCP | ACID persistence for registered clients & runtime authorization records |
| **`localstack`** | `4566` | HTTP / KMS API | Emulated AWS KMS (FIPS 140-2 Level 3 HSM Asymmetric Key Signing) |
| **`redis`** | `6379` | RESP / TCP | DB 0 (SSO, JTI), DB 1 (Client Tokens), and Pub/Sub cluster invalidation |

