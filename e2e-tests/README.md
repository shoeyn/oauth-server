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
