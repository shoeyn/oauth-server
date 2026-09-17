# Testing, Test Harness & Diagnostic Troubleshooting Guide

This guide details the automated test infrastructure, pre-configured test fixtures, failure diagnostic workflows, and instructions for authoring new integration tests across the OAuth 2.1 & OpenID Connect platform.

---

## 1. Test Fixtures & Pre-Configured Credentials

The development and test environments are provisioned with standard fixtures and dynamic provisioning hooks:

| Entity | Identifier / Name | Key / Secret | Location | Purpose |
|---|---|---|---|---|
| **Default Seed User** | `alice_smith@example.com` | `secret123` | PostgreSQL `app_users` (BCrypt) | Interactive browser login, k6 load testing, manual demo testing |
| **Dynamic E2E User** | `test_user_<hex>@example.com` | `password123` | Dynamically created per scenario | Isolated test user created by Cucumber `hooks.rb` via Spring Admin API |
| **Admin Key** | N/A | `secret-admin-key` | Header `X-Admin-Api-Key` | Admin REST API authentication (`/api/admin/*`) |
| **Default Client** | `demo-client` | Asymmetric RSA Private Key | `demo-client/keys/client_private_key.pem` | Main test client (`private_key_jwt`, DPoP, PAR) |
| **KMS Signing Key** | `kms-auth-server-key-1` | LocalStack KMS HSM (RSA_2048) | Alias: `alias/oauth2-signing-key` | Token signing & JWKS public key verification |

---

## 2. Automated Test Execution

### End-to-End Functional Test Suite (Cucumber)
Executes browser-driven feature specs via headless Chrome (Cuprite) against the live running services (`http://localhost:8080`, `http://localhost:3000`, `http://localhost:9000`, `http://localhost:9001`):

```bash
cd e2e-tests
mise exec -- bundle install
mise exec -- bundle exec cucumber
```

Dry-run step definition validation (enforces `--strict`):
```bash
cd e2e-tests
mise exec -- bundle exec cucumber --dry-run
```

Run a specific feature file:
```bash
cd e2e-tests
mise exec -- bundle exec cucumber features/oauth_authorization.feature
mise exec -- bundle exec cucumber features/token_lifecycle.feature
mise exec -- bundle exec cucumber features/error_journeys.feature
mise exec -- bundle exec cucumber features/invalid_login.feature
mise exec -- bundle exec cucumber features/fraud_revocation.feature
```

### Component Unit Test Suites (100% Coverage Enforced)

Each component enforces 100% test coverage:

```bash
# 1. OAuth2ClientKit (Ruby Gem - RSpec + WebMock + SimpleCov, 115 specs):
cd oauth2_client_kit
mise exec -- bundle exec rspec

# 2. Rails IdP (Rails 7 - RSpec-Rails + SimpleCov, 26 specs):
cd rails-app
mise exec -- bundle exec rspec

# 3. Demo Client (Rails 8 - RSpec-Rails + SimpleCov, 8 specs):
cd demo-client
mise exec -- bundle exec rspec

# 4. Client Manager UI (Next.js 16 - Vitest + React Testing Library, 47 tests):
cd client-manager
pnpm test

# 5. Spring Authorization Server (Spring Boot 4 / Java 25 - JUnit 5 + Mockito + JaCoCo, 182 tests):
cd spring-auth-server
mise exec -- mvn test
```

### Static Analysis & Linting

```bash
# Ruby linting (Ruby 4.0 / RuboCop across all gems and apps):
cd oauth2_client_kit && mise exec -- rubocop
cd rails-app && mise exec -- rubocop
cd demo-client && mise exec -- rubocop
cd e2e-tests && mise exec -- rubocop

# Java code formatting and style (Spotless Google Java Format + Checkstyle):
cd spring-auth-server && mise exec -- mvn spotless:check checkstyle:check
cd spring-auth-server && mise exec -- mvn spotless:apply  # Auto-format

# TypeScript / Next.js linting & formatting (Oxlint + Oxfmt):
cd client-manager && pnpm lint
cd client-manager && pnpm format:check
```

### Running k6 Load & Concurrency Tests

```bash
# Fast smoke test (2 virtual users, 10 iterations)
k6 run --vus 2 --iterations 10 k6/oauth_load_test.js

# Standard 30s multi-scenario load test (full session flow + 30 req/s discovery burst)
k6 run k6/oauth_load_test.js
```

---

## 3. Failure Diagnostic & Troubleshooting Matrix

If automated tests or manual flows fail, use the following quick-triage diagnostic checklist:

### A. LocalStack KMS Key Missing or Unreachable
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

### B. E2E or Client Authentication Fails with `invalid_client`
- **Symptom:** Spring returns `HTTP 401 Unauthorized` during code exchange or token request.
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

### D. Token Refresh Fails with `invalid_dpop_proof`
- **Symptom:** Spring token endpoint returns `HTTP 400 Bad Request` with `invalid_dpop_proof: DPoP proof header is strictly required on token endpoint requests (RFC 9449)`.
- **Diagnostic Cause:** The client session did not persist the ephemeral DPoP private key generated during the initial authorization flow, or failed to construct the `DPoP` HTTP header for the refresh request.
- **Remediation:** Ensure the client uses `OAuth2ClientKit.token_store` which securely stores the `dpop_key` alongside the refresh token and attaches valid DPoP proofs with single-use nonces.

---

## 4. How to Author a New Functional Test Scenario

To author a new end-to-end integration test:

1. **Create a Gherkin Feature**: Add a new scenario to an existing `.feature` file in `e2e-tests/features/` or create a new file (e.g., `e2e-tests/features/my_feature.feature`):

```gherkin
Feature: My New Feature

  Background:
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    When I fill in the test user credentials
    And I click "Authorize & Return to OAuth Server"
    Then I should see "Successfully authenticated via OAuth 2.1"

  Scenario: Verify protected feature
    When I click "🛡️ Perform Sensitive Action (Introspection Guard)"
    Then I should see "Sensitive Action Approved! Token Introspection verified active=true"
```

2. **Add Step Definitions (if needed)**: If you introduce new Gherkin steps, define them in `e2e-tests/features/step_definitions/oauth_steps.rb` using Capybara matchers:

```ruby
When('I click the custom action button') do
  click_on 'My Custom Action'
end

Then('I should see custom confirmation') do
  expect(page).to have_content('Action completed successfully')
end
```

3. **Verify Under Strict Mode**:
```bash
cd e2e-tests
mise exec -- bundle exec cucumber --dry-run
mise exec -- bundle exec cucumber
```
