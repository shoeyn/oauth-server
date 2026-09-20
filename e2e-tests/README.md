# End-to-End Cucumber Test Suite

Comprehensive browser-driven end-to-end integration tests for the OAuth 2.1 / OpenID Connect platform, powered by **Cucumber**, **Capybara**, and **Cuprite** (headless Chrome driver via Chrome DevTools Protocol).

---

## Scenarios & Features

The suite tests real interactive browser flows across all running platform services:

1. **`features/oauth_authorization.feature`**:
   - Tests the complete interactive authorization flow: clicks login on the Demo Client (`:8080`), follows PAR redirect through Spring AS (`:9000`), logs into the Rails IdP (`:3000`), receives JARM callback, completes code exchange with `private_key_jwt` and DPoP proof, and asserts successful profile page rendering.

2. **`features/token_lifecycle.feature`**:
   - **Token Refresh**: Tests refresh token rotation at the token endpoint with RFC 9449 DPoP proof headers.
   - **Sensitive Action (Introspection Guard)**: Verifies that real-time token introspection (`RFC 7662`) confirms `active=true` before granting access to sensitive actions.
   - **Token Revocation**: Exercises RFC 7009 token revocation, confirming tokens are invalidated at the Authorization Server and local sessions cleared.

3. **`features/error_journeys.feature`**:
   - **Simulate Account Locked**: Tests JARM front-channel error responses with client custom error view overrides.
   - **Simulate Account Suspended**: Tests JARM front-channel error responses using the default `OAuth2ClientKit` error template.

4. **`features/invalid_login.feature`**:
   - Validates that invalid user credentials at the Rails IdP produce user-friendly error messages and prevent unauthorized redirects.

5. **`features/fraud_revocation.feature`**:
   - Tests fraud flag activation via Spring Boot's internal Admin API (`POST /api/admin/users/:email/fraud`).
   - Asserts that flagging a user as fraud terminates their active SSO session in Redis and revokes all issued tokens/authorizations in PostgreSQL, causing subsequent introspection checks to immediately fail (`active=false`).

---

## Dynamic Test User Lifecycle

Each scenario automatically provisions a clean, isolated test user before execution in `features/support/hooks.rb`:
- Sends `POST /api/admin/users` to Spring Admin API (`:9001`) with a unique `test_user_<hex>@example.com` and pre-hashed SHA-256 password.
- Cleans up and deletes the test user via `DELETE /api/admin/users/:email` in the `After` hook.

---

## Running the Tests

### Prerequisites
Ensure all platform services are running:
```bash
docker compose up -d
```

### Execution Commands

```bash
# Install gems
mise exec -- bundle install

# Execute all 8 scenarios
mise exec -- bundle exec cucumber

# Execute a single feature
mise exec -- bundle exec cucumber features/oauth_authorization.feature

# Dry-run step definition validation (enforces --strict)
mise exec -- bundle exec cucumber --dry-run

# Run RuboCop static analysis
mise exec -- rubocop
```

---

## Automated OWASP ZAP Security Scanning (DAST)

The test harness integrates automated **Dynamic Application Security Testing (DAST)** powered by **OWASP ZAP** (`zaproxy/zap-bare`). Rather than using unauthenticated "spray-and-pray" crawlers that fail against modern OAuth/OIDC flows, the suite runs as a **proxy-driven passive and active inspection pipeline**.

### Architecture & Traffic Flow

```
┌─────────────────┐       HTTP Proxy (127.0.0.1:8090)       ┌────────────────────────┐
│ Cuprite Chrome  │ ──────────────────────────────────────> │    OWASP ZAP Daemon    │
│ (Cucumber E2E)  │                                         │ (Docker: profile=sec)  │
└─────────────────┘                                         └───────────┬────────────┘
         │                                                              │
         │ Transparent loopback port forwarding (socat)                 │ Inspects all traffic,
         │ preserves Host: localhost:<port> & RFC 6265 cookie domains   │ headers, tokens, cookies
         ▼                                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│ Target Services: Demo Client (:8080) | Spring AS (:9000) | Rails IdP (:3000)       │
└────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Cuprite Chrome Driver**: Configured with `--proxy-server=http://127.0.0.1:8090` and `--proxy-bypass-list=<-loopback>`, routing all local HTTP traffic through ZAP while disabling Chrome background telemetry (`disable-background-networking`, `disable-sync`).
2. **Transparent Socat Port Forwarding**: The ZAP Docker container (`zap/Dockerfile` & `zap/entrypoint.sh`) runs background `socat` daemons binding `127.0.0.1:<port>` to `host.docker.internal:<port>` for ports `8080`, `9000`, `3000`, `3001`, and `9001`. This preserves `Host: localhost:<port>` and RFC 6265 cookie domain boundaries (`localhost`), preventing authentication redirect bounces.
3. **Automated Alert Aggregation**: At the conclusion of the test run, Cucumber's `AfterConfiguration` hook queries the ZAP REST API (`/JSON/alert/view/alerts/`), filters out non-application origins, outputs a severity breakdown in the console, and writes comprehensive HTML and Markdown reports to `security-reports/`.

### Running ZAP Security Scans

#### Option 1: Automated All-in-One Runner (Recommended)

The runner script boots the ZAP daemon, awaits API readiness, resets the session, runs all Cucumber E2E scenarios through the proxy, and exports reports:

```bash
./bin/run-zap-e2e.sh
```

#### Option 2: Manual Execution

```bash
# 1. Start OWASP ZAP daemon
docker compose --profile security up -d zap

# 2. Run Cucumber with ZAP proxy flags
export ZAP_PROXY=true
export ZAP_HOST=127.0.0.1
export ZAP_PORT=8090
export FAIL_ON_ZAP_ALERTS=false  # Set to true to fail CI on High/Medium alerts

bundle exec cucumber
```

### Generated Security Reports

Reports are automatically generated and saved to the project root:
- `security-reports/zap-report.html`: Full interactive OWASP ZAP HTML vulnerability report with request/response evidence, CWE/WASC classifications, and remediation advice.
- `security-reports/zap-summary.md`: Concise Markdown summary with alert count breakdown by severity (High, Medium, Low, Informational) and targeted endpoints.

