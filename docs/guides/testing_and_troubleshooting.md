# Testing, Test Harness & Diagnostic Troubleshooting Guide

This guide details the automated test infrastructure, pre-configured test fixtures, failure diagnostic workflows, and instructions for authoring new integration tests across the OAuth 2.1 & OpenID Connect platform.

---

## 1. Test Fixtures & Pre-Configured Credentials

The development and test environments are provisioned with standard mock fixtures:

| Entity | Identifier / Name | Key / Secret | Location | Purpose |
|---|---|---|---|---|
| **Default User** | `demo_user` | `password` | Rails Login DB / In-memory | Interactive browser login & test authentication |
| **Admin Key** | N/A | `secret-admin-key` | Header `X-Admin-Api-Key` | Admin REST API authentication (`/api/admin/*`) |
| **Default Client** | `demo-client` | Asymmetric RSA Private Key | `demo-client/keys/client_private_key.pem` | Main test client (`private_key_jwt`, DPoP, PAR) |
| **KMS Signing Key** | `kms-auth-server-key-1` | LocalStack KMS HSM (RSA_2048) | Alias: `alias/oauth2-signing-key` | Token signing & JWKS public key verification |

---

## 2. Automated Test Execution

### Running the Complete Functional Test Suite
Executes all 4 end-to-end Ruby/Faraday test suites:
```bash
./spring-auth-server/functional_tests/run_functional_tests.sh
```

### Running Individual Test Suites
```bash
cd spring-auth-server/functional_tests

# Suite 1: Core OAuth 2.1 & OIDC (PAR, DPoP, PKCE, Issuer ID, Introspection, Revocation, Logout)
ruby test_oauth_security_features.rb

# Suite 2: PostgreSQL Dynamic Client Provisioning & Redis Pub/Sub Cluster Invalidation
ruby test_s3_dynamic_client_reload.rb

# Suite 3: Performance, ETag 304 Caching, EC P-256 vs RSA Benchmarks, Network Retries
ruby test_performance_and_resilience.rb

# Suite 4: AWS KMS Hardware Signing, Algorithm Pinning Rejection ('none' & 'HS256'), Multi-Key Rotation
ruby test_kms_signing.rb
```

### Running k6 Load & Concurrency Tests
```bash
# Standard 30s multi-scenario load test (full session flow + 30 req/s discovery burst)
k6 run k6/oauth_load_test.js

# Fast smoke test (2 virtual users, 10 iterations)
k6 run --vus 2 --iterations 10 k6/oauth_load_test.js
```

---

## 3. Failure Diagnostic & Troubleshooting Matrix

If automated tests or manual flows fail, use the following quick-triage diagnostic checklist:

### A. Test Suite 4 Fails: LocalStack KMS Key Missing or Unreachable
- **Symptom:** `AwsKmsJwtSigner` fails on startup with `AwsServiceException: Key does not exist` or `Connection refused`.
- **Diagnostic Command:**
  ```bash
  aws --endpoint-url=http://localhost:4566 kms list-aliases
  ```
- **Remediation:** If the alias `alias/oauth2-signing-key` is missing:
  ```bash
  # Re-run LocalStack initialization script
  docker compose restart localstack
  # Verify key is present
  curl -s http://localhost:4566/_localstack/health | grep kms
  ```

### B. Test Suite 1 Fails on Client Authentication (`invalid_client`)
- **Symptom:** Spring returns `HTTP 401 Unauthorized` during code exchange.
- **Diagnostic Command:**
  ```bash
  # Verify client exists in PostgreSQL
  docker compose exec postgres psql -U postgres -d authserver -c "SELECT client_id, scopes FROM oauth2_registered_client;"
  # Verify public key is persisted
  docker compose exec postgres psql -U postgres -d authserver -c "SELECT client_id, length(public_key_pem) FROM oauth2_client_public_key;"
  ```
- **Remediation:** If the database is empty, restart Spring to let Flyway seed `V3__seed_default_demo_client.sql`:
  ```bash
  docker compose restart spring-auth-server
  ```

### C. Nginx Edge Proxy Returns Unexpected `HTTP 403 Forbidden`
- **Symptom:** Browser or test returns `{"error":"forbidden","message":"Administrative endpoints are restricted to internal networks."}`.
- **Diagnostic Cause:** You called an administrative URL (`/api/admin/**`) or Actuator URL (`/actuator/**`) against public port `9000`.
- **Remediation:** Direct administrative calls to the internal bastion port (`http://localhost:9001`) or container DNS (`http://spring-auth-server:9000`). Public clients must use only standard OAuth endpoints (`/oauth2/**`, `/userinfo`, `/connect/logout`).

---

## 4. How to Author a New Functional Test Scenario

To author a new automated integration test, use the following standardized Ruby boilerplate based on `ParOAuth2Client`:

```ruby
#!/usr/bin/env ruby
require "net/http"
require "json"
require "securerandom"
require_relative "../../demo-client/app/services/par_oauth2_client"

CLIENT_ID = "demo-client"
KEY_PEM = File.read(File.expand_path("../../demo-client/keys/client_private_key.pem", __dir__))

client = ParOAuth2Client.new(CLIENT_ID, KEY_PEM, {
  public_issuer_url: "http://localhost:9000",
  internal_issuer_url: "http://localhost:9000"
})

puts "1. Pushing Authorization Request (PAR)..."
state = SecureRandom.hex(16)
code_verifier = SecureRandom.hex(32)
code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)

request_uri = client.push_authorization_request({
  response_type: "code",
  state: state,
  code_challenge: code_challenge,
  code_challenge_method: "S256",
  redirect_uri: "http://localhost:8080/callback"
})

puts "   SUCCESS: Obtained request_uri -> #{request_uri}"
```
