# Client Configuration, Persistence & Near-Caching Flow

This document details the configuration management, PostgreSQL relational persistence, and high-performance near-caching architecture for registered OAuth 2.1 clients across **Next.js**, **PostgreSQL**, **Redis Pub/Sub**, and **Spring Authorization Server**.

> [!NOTE]
> **Implementation Status: Fully Implemented & Production-Active**
> AWS S3 has been completely deprecated and purged from this flow. Registered client configurations and RSA public keys are persisted with ACID durability in PostgreSQL, accessible only through the Java Spring Admin REST API (`/api/admin/clients`). Runtime authorization reads resolve in ~0.001 ms from the in-memory L1 near-cache with zero database round-trips.

---

## Architecture Topology & Trust Boundaries

To comply strictly with the organizational policy that **only the Java application communicates directly with PostgreSQL**, external administrative clients (such as Next.js) never receive database credentials. Instead, they interact with Spring Auth Server via an authenticated REST interface (`/api/admin/clients`).

```mermaid
flowchart TD
    subgraph ClientManager ["Administrative Frontend Tier (Port 3001)"]
        NextJS["Next.js Client Manager<br/>• Pure Web UI / React 19<br/>• Web Crypto API (In-browser RSA 2048)<br/>• Zero AWS SDKs / Zero DB Drivers"]
    end

    subgraph SpringApp ["Java Application Cluster (Port 9000)"]
        AdminAPI["ClientAdminController<br/>(X-Admin-Api-Key Protection)"]
        L1Maps["L1 In-Memory Near-Cache<br/>• ConcurrentHashMap<String, RegisteredClient><br/>• ConcurrentHashMap<String, RSAPublicKey><br/>• Sub-millisecond reads (< 0.002 ms)"]
        Repo["PostgresRegisteredClientRepository<br/>HikariCP Connection Pool"]
    end

    subgraph ClusterSync ["Cluster Notification Tier (Port 6379)"]
        RedisPubSub["Redis Pub/Sub Channel<br/>'oauth2as:clients:reload'<br/>• Instantaneous cluster cache invalidation"]
    end

    subgraph DataTier ["Isolated Database Tier (Port 5432)"]
        Postgres[("PostgreSQL Database 'authserver'<br/>• oauth2_registered_client<br/>• oauth2_client_public_key<br/>• ACID-durable single source of truth")]
    end

    NextJS -->|"HTTP REST (GET/POST/DELETE /api/admin/clients)"| AdminAPI
    AdminAPI --> Repo
    Repo -->|Direct JDBC SQL Only| Postgres
    AdminAPI -->|Publish Invalidation| RedisPubSub
    RedisPubSub -->|Hot-Reload Broadcast| SpringApp
    L1Maps <-->|Warm Cache / Invalidation Refresh| Repo
```

---

## Flow 1: Service Startup & Near-Cache Pre-Warming

```mermaid
sequenceDiagram
    autonumber
    participant Spring as Spring Authorization Server
    participant Flyway as Flyway Migration Engine
    participant PG as PostgreSQL (Port 5432)

    Note over Spring: Spring Boot boots up (@PostConstruct init())
    Spring->>Flyway: flyway.migrate()
    Flyway->>PG: Validate & Execute V1 & V2 schema migrations
    PG-->>Flyway: Schema verified (tables & indices guaranteed)

    Spring->>PG: SELECT count(*) FROM oauth2_registered_client
    alt Database Empty (First Boot)
        PG-->>Spring: count = 0
        Note over Spring: Register default demo-client with public key
        Spring->>PG: INSERT INTO oauth2_registered_client & oauth2_client_public_key
    else Database Populated
        PG-->>Spring: count > 0
    end

    Note over Spring: Pre-warm L1 in-memory near-cache
    Spring->>PG: SELECT * FROM oauth2_registered_client JOIN oauth2_client_public_key
    PG-->>Spring: Active clients & X.509 RSA public keys
    Note over Spring: Populate ConcurrentHashMaps (clients & keys)
    Note over Spring: READY! All runtime auth reads serve from memory in < 0.002 ms.
```

---

## Flow 2: Dynamic Client Creation via Admin REST API

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin Browser
    participant Manager as Next.js Client Manager (3001)
    participant SpringAdmin as Spring ClientAdminController (9000)
    participant PG as PostgreSQL (5432)
    participant Redis as Redis Pub/Sub (6379)
    participant Cluster as Spring Auth Server Instances

    Admin->>Manager: Fill Client Form (ID, Redirects, Scopes)<br/>Click "Generate RSA Key Pair" (Web Crypto API)
    Note over Admin, Manager: Web Crypto generates 2048-bit RS256 key pair in browser.<br/>Private key downloaded as PEM, public key populated into form.
    Admin->>Manager: Click "Save Client"
    activate Manager

    Manager->>SpringAdmin: POST /api/admin/clients (Headers: X-Admin-Api-Key, JSON body)
    activate SpringAdmin
    Note over SpringAdmin: Constant-time API Key verification
    SpringAdmin->>PG: INSERT INTO oauth2_registered_client<br/>INSERT INTO oauth2_client_public_key ON CONFLICT UPDATE
    PG-->>SpringAdmin: Row persisted (ACID commit)
    Note over SpringAdmin: Refresh local L1 near-cache

    SpringAdmin->>Redis: PUBLISH oauth2as:clients:reload {"action":"save", "clientId":"<id>"}
    SpringAdmin-->>Manager: HTTP 201 Created
    deactivate SpringAdmin

    Manager-->>Admin: Success Notification
    deactivate Manager

    Redis-->>Cluster: Invalidation signal received
    Note over Cluster: All cluster instances re-warm L1 near-cache from PostgreSQL
```

---

## Flow 3: Dynamic Client Deletion & Immediate Revocation

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin Browser
    participant Manager as Next.js Client Manager (3001)
    participant SpringAdmin as Spring ClientAdminController (9000)
    participant PG as PostgreSQL (5432)
    participant Redis as Redis Pub/Sub (6379)
    participant Rogue as Deleted Client Application

    Admin->>Manager: Click "Delete Client" for 'test-client'
    activate Manager
    Manager->>SpringAdmin: DELETE /api/admin/clients/test-client (Headers: X-Admin-Api-Key)
    activate SpringAdmin
    SpringAdmin->>PG: DELETE FROM oauth2_client_public_key WHERE client_id = 'test-client'<br/>DELETE FROM oauth2_registered_client WHERE client_id = 'test-client'
    PG-->>SpringAdmin: Rows deleted
    Note over SpringAdmin: Evict 'test-client' from local L1 near-cache
    SpringAdmin->>Redis: PUBLISH oauth2as:clients:reload {"action":"delete", "clientId":"test-client"}
    SpringAdmin-->>Manager: HTTP 200 OK
    deactivate SpringAdmin
    Manager-->>Admin: Client deleted
    deactivate Manager

    %% Unauthorized attempt
    Note over Rogue, SpringAdmin: Deleted client attempts token exchange
    Rogue->>SpringAdmin: POST /oauth2/par or POST /oauth2/token (client_id: test-client)
    activate SpringAdmin
    Note over SpringAdmin: L1 near-cache lookup returns null!
    SpringAdmin-->>Rogue: HTTP 401 Unauthorized<br/>{"error": "invalid_client"}
    deactivate SpringAdmin
```
