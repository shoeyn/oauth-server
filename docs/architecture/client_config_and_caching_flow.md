# Multi-Tier Client Configuration & Hot-Reload Flow

This document details the configuration management and multi-tiered caching architecture for registered OAuth 2.1 clients across **Next.js**, **LocalStack S3**, **Redis**, and **Spring Authorization Server**.

---

## Multi-Tier Cache Hierarchy

```mermaid
flowchart TD
    subgraph L1 ["L1: In-Memory Cache (Spring Boot Process)"]
        L1Maps["ConcurrentHashMap<String, RegisteredClient>\nConcurrentHashMap<String, RSAPublicKey>\n• Latency: < 1 microsecond\n• Zero network overhead at authorization/token time"]
    end

    subgraph L2 ["L2: Redis Hash Cache (Redis Server DB 0)"]
        L2Hash["Hash Key: oauth2:clients:configs\nField: client_id | Value: JSON DTO\n• Latency: < 2 milliseconds\n• Expiration: 30-day sliding TTL\n• Survives Spring server reboots & deployments\n• Zero S3 calls on warm restarts"]
    end

    subgraph L3 ["L3: Persistent Object Store (LocalStack S3)"]
        L3S3["Bucket: oauth2-clients\nObjects: clients/<client_id>.json\n• Durable Single Source of Truth\n• Audit history, backup, and external management"]
    end

    L1Maps <-->|Warm boot reads / Refresh updates| L2Hash
    L2Hash <-->|Cold start fallback / Refresh sync| L3S3
```

---

## Flow 1: Service Startup (Warm Boot vs. Cold Start)

```mermaid
sequenceDiagram
    autonumber
    participant Spring as Spring Authorization Server
    participant Redis as Redis (Port 6379)
    participant S3 as LocalStack S3 (Port 4566)

    Note over Spring: Spring Boot boots up (@PostConstruct init())
    Spring->>Redis: HGETALL oauth2:clients:configs
    alt Cache Hit (Warm Boot - Normal Operating Condition)
        Redis-->>Spring: Map<clientId, clientJson>
        Note over Spring: 1. Deserialize ClientConfigDto<br/>2. Parse X.509 RSA public key PEMs<br/>3. Populate in-memory ConcurrentHashMaps<br/>4. Log: "Loaded X clients from Redis (booted without querying S3)"
        Note over Spring, Redis: READY in < 5ms! (Zero S3 network requests)
    else Cache Miss (Cold Start - Redis Empty or First Run)
        Redis-->>Spring: Empty / Nil
        Note over Spring: Log: "Redis client cache is empty or unavailable. Fetching from S3..."
        Spring->>S3: ListObjectsV2 (prefix: "clients/")
        S3-->>Spring: Object Keys [clients/demo-client.json, ...]
        loop For each JSON object
            Spring->>S3: GetObject (key: clients/<id>.json)
            S3-->>Spring: JSON Payload
            Note over Spring: Parse DTO, parse RSA public key, populate in-memory maps
        end
        Spring->>Redis: HSET oauth2:clients:configs <id> <json>
        Spring->>Redis: EXPIRE oauth2:clients:configs 2592000 (30 Days)
        Note over Spring: Log: "Synchronized X clients to Redis cache with 30 days TTL"
        Note over Spring, S3: READY (Redis cache now warm for subsequent reboots)
    end
```

---

## Flow 2: Dynamic Client Creation & Real-Time Hot-Reload

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin Browser
    participant Manager as Next.js Client Manager (3001)
    participant S3 as LocalStack S3 (4566)
    participant Redis as Redis (6379)
    participant Spring as Spring Auth Server (9000)

    Admin->>Manager: Fill Client Form (ID, Redirects, Scopes)<br/>Click "Generate RSA Key Pair" (Web Crypto API)
    Note over Admin, Manager: Web Crypto generates 2048-bit RS256 key pair in browser.<br/>Private key downloaded as PEM; public key populated into form.
    Admin->>Manager: Click "Save Client Configuration"
    activate Manager

    %% 1. Write S3
    Manager->>S3: PutObject (bucket: oauth2-clients, key: clients/<id>.json)
    S3-->>Manager: HTTP 200 OK

    %% 2. Sync Redis Hash
    Manager->>Redis: HSET oauth2:clients:configs <id> <json>
    Manager->>Redis: EXPIRE oauth2:clients:configs 2592000 (30 Days)

    %% 3. Publish Reload Event
    Manager->>Redis: PUBLISH oauth2:clients:reload {"action": "save", "clientId": "<id>"}
    Manager-->>Admin: HTTP 201 Created (Client saved)
    deactivate Manager

    %% 4. Spring Reload Trigger
    activate Spring
    Redis-->>Spring: Message on 'oauth2:clients:reload': RELOAD:<id>
    Note over Spring: ClientReloadRedisSubscriber receives event.<br/>Triggers asynchronous refresh() in < 15ms.
    Spring->>S3: ListObjectsV2 & GetObject
    S3-->>Spring: Fresh JSONs
    Note over Spring: 1. Update in-memory ConcurrentHashMaps<br/>2. Re-sync Redis Hash with renewed 30-day TTL<br/>3. Log: "Reloaded X clients from S3"
    deactivate Spring

    Note over Admin, Spring: New client can immediately authenticate with private_key_jwt without server restart!
```

---

## Flow 3: Dynamic Client Deletion & Immediate Revocation

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin Browser
    participant Manager as Next.js Client Manager (3001)
    participant S3 as LocalStack S3 (4566)
    participant Redis as Redis (6379)
    participant Spring as Spring Auth Server (9000)
    participant Rogue as Deleted Client App

    Admin->>Manager: Click "Delete Client" for 'test-client'
    activate Manager
    Manager->>S3: DeleteObject (key: clients/test-client.json)
    S3-->>Manager: HTTP 204 No Content
    Manager->>Redis: HDEL oauth2:clients:configs test-client
    Manager->>Redis: PUBLISH oauth2:clients:reload {"action": "delete", "clientId": "test-client"}
    Manager-->>Admin: HTTP 200 OK (Deleted)
    deactivate Manager

    %% Spring Reload Trigger
    activate Spring
    Redis-->>Spring: Message on 'oauth2:clients:reload': RELOAD:test-client
    Spring->>S3: ListObjectsV2 (test-client is absent)
    Note over Spring: 1. Evict test-client from in-memory maps<br/>2. Re-sync Redis Hash<br/>3. Log: "Reloaded 1 client from S3"
    deactivate Spring

    %% Negative test verification
    Note over Rogue, Spring: Deleted client attempts token exchange
    Rogue->>Spring: POST /oauth2/par or POST /oauth2/token (client_id: test-client)
    activate Spring
    Note over Spring: StrictClientAssertionAuthenticationConverter looks up test-client.<br/>Not found in in-memory repository!
    Spring-->>Rogue: HTTP 401 Unauthorized<br/>{"error": "invalid_client"}
    deactivate Spring
```
