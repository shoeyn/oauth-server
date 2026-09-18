# k6 Performance & Concurrency Load Testing

This directory contains automated **k6** load testing scripts designed to evaluate throughput, concurrency limits, latency percentiles, and caching behavior across the OAuth 2.1 & OpenID Connect platform.

> **Scope note:** This suite measures **performance, throughput, and redirect/flow plumbing** under concurrent load. It exercises the full authorization flow to generate realistic traffic, but it does **not** verify the cryptographic security guarantees themselves (e.g. DPoP sender-constraint binding, PAR request integrity, JARM response signing/validation). Those correctness properties are asserted by the end-to-end Cucumber test suite (`e2e-tests/`) and unit test suites with 100% enforced coverage across each component. Treat k6 results as capacity/latency evidence, not as security assurance.

---

## Overview of Test Scenarios (`oauth_load_test.js`)

The test script runs two concurrent scenarios simulating realistic enterprise usage:

### 1. `full_oauth_session_flow` (Interactive Multi-Session Authorization)
- **Executor:** `constant-vus` (5 concurrent virtual users) for 30 seconds.
- **Dynamic Multi-User Pool & Session Isolation:**
  - Before test execution, `setup()` pre-provisions an isolated pool of distinct user accounts (`load_user_${i}_${runId}@example.com`) using Spring Boot's internal Admin API (`POST http://localhost:9001/api/admin/users`) with SHA-256 pre-hashed passwords conforming to the platform's defense-in-depth security model.
  - Each concurrent Virtual User (VU) authenticates with its own dedicated user account from the pool (`load_user_${vuIndex}@example.com`).
  - This exercises **real multi-user concurrency and true session tree isolation** across the entire stack:
    - Independent BCrypt password verification per user in Spring Boot.
    - Isolated session trees in Redis (`session:<uuid>`) avoiding shared session collisions or cache hot-spotting.
    - Distinct OAuth authorization codes, grants, and token records in PostgreSQL (`oauth2_authorization`).
    - Dedicated client session token storage in Redis DB 1.
  - Upon test completion, `teardown()` automatically purges all provisioned test users via `DELETE /api/admin/users/:email`, leaving zero residual test state in PostgreSQL.
- **Workflow:** Executes the complete **6-hop end-to-end OAuth 2.1 flow**:
  1. `GET /` $\rightarrow$ Extracts Rails CSRF authenticity token.
  2. `POST /auth/start` $\rightarrow$ Submits RFC 9126 PAR request with PKCE ($S256$), 192-bit cryptographic state, and ephemeral EC P-256 DPoP key. Returns 302/303 redirect.
  3. `GET /oauth2/authorize` $\rightarrow$ Spring AS checks session, redirects to Rails IdP.
  4. `GET /login` & `POST /login` $\rightarrow$ Rails IdP authenticates user, writes session to Redis DB 0, sets `SHARED_SESSION_ID` cookie, and returns redirect to Spring AS return URL.
  5. `GET /oauth2/authorize` $\rightarrow$ Spring AS evaluates Redis session, issues authorization code with RFC 9207 `iss=http://localhost:9000`, redirects to `/callback`.
  6. `GET /callback` $\rightarrow$ Demo client validates issuer, calls `/oauth2/token` with code + `private_key_jwt` client assertion + DPoP proof, validates ID token against cached JWKS, queries `/userinfo` with DPoP, stores tokens in Redis DB 1, and redirects to `/profile`.
  7. `GET /profile` $\rightarrow$ Verifies authenticated profile rendering.

### 2. `discovery_and_jwks_burst` (High-Throughput Public Metadata Burst)
- **Executor:** `ramping-arrival-rate` ramping up to **30 req/sec** (equivalent to **108,000 req/hour**).
- **Workflow:** Continuously queries `/.well-known/openid-configuration` and `/oauth2/jwks`, asserting that **100% of metadata requests return HTTP 200 OK** with sub-millisecond response times under heavy burst traffic without impacting interactive user login latency.

---

## Prerequisites

1. **Install k6:**
   ```bash
   brew install k6
   ```

2. **Ensure all platform services are running:**
   ```bash
   # Check service health (via Nginx perimeter proxy at port 9000, or direct internal port 9001)
   curl -s http://localhost:9000/healthz | grep UP
   # or direct internal Spring health: curl -s http://localhost:9001/actuator/health | grep UP
   curl -s http://localhost:3000/health | grep UP
   curl -s http://localhost:8080/health | grep UP
   ```

---

## Execution Commands

### 1. Standard Multi-Scenario Load Test (Recommended)
Runs both concurrent scenarios (5 VUs for full auth flow + 30 req/sec caching burst) for 30 seconds:
```bash
k6 run k6/oauth_load_test.js
```

### 2. Fast Smoke Test
Quickly validates correctness with 2 concurrent users across 10 iterations:
```bash
k6 run --vus 2 --iterations 10 k6/oauth_load_test.js
```

### 3. Extended Concurrency Stress Test
Pushes higher concurrency (15 virtual users for 60 seconds):
```bash
k6 run --vus 15 --duration 60s k6/oauth_load_test.js
```

### 4. Custom Output (JSON / CSV)
Export metrics for graphing in Grafana, Datadog, or Excel:
```bash
k6 run --summary-export=k6/summary.json k6/oauth_load_test.js
```

---

## Measured Benchmark Results

### 1. Hardware-Backed AWS KMS Signing Benchmark (Multi-Session Dynamic Pool)

With **AWS KMS HSM asymmetric signing (`ECC_NIST_P256` / `ES256`)**, **graceful multi-key JWKS rotation**, **strict ES256 algorithm pinning**, and **dynamic multi-user session isolation**:

```
  █ THRESHOLDS 

    auth_session_success_rate .......: ✓ 'rate>0.95' rate=100.00%
    auth_session_total_duration_ms ..: ✓ 'p(95)<1500' p(95)=217.0 ms
    http_req_failed .................: ✓ 'rate<0.05' rate=0.00%

  █ KEY PERFORMANCE INDICATORS 

    • Total Checks Succeeded:          3,923 out of 3,923 (100.00% pass rate)
    • Total HTTP Requests:             3,278 requests in 31.4 seconds (104.5 req/sec sustained)
    • Equivalent Hourly Throughput:    ~376,000 HTTP requests / hour
    • Full OAuth Sessions Completed:   225 full sessions in 30s (~7.5 sessions/sec)
    • Equivalent Auth Session Rate:    ~27,000 full auth sessions / hour
    • End-to-End Session Latency:      p(50) = 163 ms | avg = 167.1 ms | p(90) = 205.3 ms | p(95) = 217.0 ms | max = 382 ms
    • Public Discovery / JWKS Checks:  100.00% (100% returned 200 OK)
    • Overall HTTP Failure Rate:       0.00% (0 out of 3,278 requests failed)
    • Cryptographic Signatures / Flow: 3 (JARM Auth Code + Access Token + ID Token)
    • Session & User Concurrency:      Dynamic pool of 15 users; distinct sessions in Redis DB 0/1 & PostgreSQL
    • Cryptographic Boundary:          AWS KMS (real AWS = FIPS 140-2 / FIPS 140-3 Level 3 HSM; LocalStack = software emulation, dev only). Zero private keys in JVM memory.
```

### 2. In-Memory Software Signing vs. AWS KMS Hardware Signing (Multi-Session)

| Metric | Target / Threshold | In-Memory Software Signing | AWS KMS Hardware Signing (`ECC_NIST_P256` / `ES256`) | Status |
|---|---|---|---|:---:|
| **Cryptographic Boundary** | Hardware HSM | Software JCE (JVM memory) | **FIPS 140-2/3 Level 3 KMS HSM in real AWS** (LocalStack locally) | **PASS** |
| **Algorithm Pinning** | Strict ES256 | Optional | **Strict ES256 enforced (`none` & `HS256` rejected)** | **PASS** |
| **Key Rotation Support** | Multi-Key JWKS | Single key | **Graceful Multi-Key JWKS (Active + Previous)** | **PASS** |
| **KMS Signatures / Flow** | Non-repudiation | 0 (Local CPU) | **3 (JARM Auth Code + Access Token + ID Token)** | **PASS** |
| **User & Session Isolation** | Isolated sessions | Single shared user | **Dynamic Multi-User Pool (`setup`/`teardown`)** | **PASS** |
| **Auth Session Completion** | > 95.0% | `98.79%` | **`100.00%`** (225 / 225 completed) | **PASS** |
| **Hourly Auth Session Rate** | > 3,000 sessions/hr | ~29,400 sessions/hr | **~27,000 sessions/hr** (~7.5 sessions/sec) | **PASS** |
| **Full Session Latency (median)** | < 500 ms | `112 ms` | **`163.0 ms`** (6 hops + 3 KMS calls + DB + Redis + BCrypt) | **PASS** |
| **Full Session Latency (p95)** | < 1,500 ms | `146 ms` | **`217.0 ms`** | **PASS** |
| **Total HTTP Error Rate** | < 1.0% | `0.04%` | **`0.00%`** (0 / 3,278 requests failed) | **PASS** |
| **Public Metadata Check Rate** | 100.0% | `100.00%` | **`100.00%`** (100% returned 200 OK) | **PASS** |

---

## Architecture References
- Detailed bottleneck analysis and scaling roadmap: [`docs/architecture/performance_and_scalability.md`](../docs/architecture/performance_and_scalability.md)
- KMS multi-key rotation architecture and sequence flows: [`docs/architecture/kms_multi_key_rotation_flow.md`](../docs/architecture/kms_multi_key_rotation_flow.md)
