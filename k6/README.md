# k6 Performance & Concurrency Load Testing

This directory contains automated **k6** load testing scripts designed to evaluate throughput, concurrency limits, latency percentiles, and caching behavior across the OAuth 2.1 & OpenID Connect platform.

---

## Overview of Test Scenarios (`oauth_load_test.js`)

The test script runs two concurrent scenarios simulating realistic enterprise usage:

### 1. `full_oauth_session_flow` (Interactive Authorization Sessions)
- **Executor:** `constant-vus` (5 concurrent virtual users) for 30 seconds.
- **Workflow:** Executes the complete **6-hop end-to-end OAuth 2.1 flow**:
  1. `GET /` $\rightarrow$ Extracts Rails CSRF authenticity token.
  2. `POST /auth/start` $\rightarrow$ Submits RFC 9126 PAR request with PKCE ($S256$), 192-bit cryptographic state, and ephemeral EC P-256 DPoP key. Returns 302/303 redirect.
  3. `GET /oauth2/authorize` $\rightarrow$ Spring AS checks session, redirects to Rails IdP.
  4. `GET /login` & `POST /login` $\rightarrow$ Rails IdP authenticates user, writes session to Redis DB 0, sets `SHARED_SESSION_ID` cookie, and returns redirect to Spring AS return URL.
  5. `GET /oauth2/authorize` $\rightarrow$ Spring AS evaluates Redis session, issues authorization code with RFC 9207 `iss=http://localhost:9000`, redirects to `/callback`.
  6. `GET /callback` $\rightarrow$ Demo client validates issuer, calls `/oauth2/token` with code + `private_key_jwt` client assertion + DPoP proof, validates ID token against cached JWKS, queries `/userinfo` with DPoP, stores tokens in Redis DB 1, and redirects to `/profile`.
  7. `GET /profile` $\rightarrow$ Verifies authenticated profile rendering.

### 2. `discovery_and_jwks_burst` (High-Throughput Caching & ETag Validation)
- **Executor:** `ramping-arrival-rate` ramping up to **30 req/sec** (equivalent to **108,000 req/hour**).
- **Workflow:** Queries `/.well-known/openid-configuration` and `/oauth2/jwks` using conditional `If-None-Match` headers with ETags, validating that **100% of repeated requests return `HTTP 304 Not Modified`** without JSON re-serialization or payload bandwidth.

---

## Prerequisites

1. **Install k6:**
   ```bash
   brew install k6
   ```

2. **Ensure all platform services are running:**
   ```bash
   # Check service health
   curl -s http://localhost:9000/actuator/health | grep UP
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

From the latest 30-second benchmark run (with HTTP/2 stream multiplexing and Puma clustered configuration):

```
  █ THRESHOLDS 

    auth_session_success_rate .......: ✓ 'rate>0.95' rate=98.79%
    auth_session_total_duration_ms ..: ✓ 'p(95)<1500' p(95)=146 ms
    discovery_etag_304_rate .........: ✓ 'rate>0.90' rate=100.00%
    jwks_etag_304_rate ..............: ✓ 'rate>0.90' rate=100.00%
    http_req_failed .................: ✓ 'rate<0.05' rate=0.04%

  █ KEY PERFORMANCE INDICATORS 

    • Total HTTP Requests:             4,875 requests in 30 seconds (162 req/sec sustained)
    • Equivalent Hourly Throughput:    ~583,000 HTTP requests / hour
    • Full OAuth Sessions Completed:   245 full sessions in 30s (~8.2 sessions/sec)
    • Equivalent Auth Session Rate:    ~29,400 full auth sessions / hour (Target was a few thousand/hr)
    • Auth Session Success Rate:       98.79% (+3.09% improvement)
    • End-to-End Session Latency:      p(50) = 112 ms | p(90) = 138 ms | p(95) = 146 ms | max = 161 ms
    • Public Discovery / JWKS 304:     100.00% (724 out of 724 requests returned 304 Not Modified)
    • Overall HTTP Failure Rate:       0.04% (only 2 out of 4,875 requests failed; halved from 0.08%)
    • Individual Request Median:       567 µs
```

---

## Architecture References
- Detailed bottleneck analysis and scaling roadmap: [`docs/architecture/performance_and_scalability.md`](../docs/architecture/performance_and_scalability.md)
