# OAuth 2.1 & OpenID Connect Client Kit (`oauth2_client_kit`)

A high-assurance, production-grade Ruby library and mountable Rails Engine for OAuth 2.1 and OpenID Connect (OIDC). Provides zero-configuration client security protocols including RFC 9126 (PAR), RFC 7523 (Asymmetric `private_key_jwt`), RFC 9449 (DPoP sender-constrained tokens with server nonces), RFC 7636 (PKCE S256), and pre-flight identity introspection checkpoints.

---

## Features & Standards Compliance

- **RFC 9221 JWT-Secured Authorization Response Mode (JARM):** Enforces cryptographic JWS signing (RS256) of all front-channel authorization responses (codes, issuer identity, state, and error responses). Plaintext callback parameters are strictly rejected, preventing parameter injection, code tampering, and phishing via forged error descriptions.
- **RFC 9126 Pushed Authorization Requests (PAR):** Backchannel parameter submission keeping parameters out of browser logs.
- **RFC 7523 Asymmetric Client Authentication:** RS256 `private_key_jwt` assertions eliminating static client secrets.
- **RFC 9449 DPoP Sender-Constrained Tokens:** Cryptographically binds access tokens to client keys with automated RFC 9449 §8 server nonce retry loops.
- **RFC 7636 PKCE:** High-entropy code verifiers with SHA-256 challenges.
- **RFC 9207 Issuer Identification:** Protects against Mix-Up attacks.
- **OIDC Core 1.0:** Strict RS256 algorithm pinning, in-memory multi-key JWKS caching with rate-limited rotation, `at_hash`, and `c_hash` verification.
- **OIDC Logout:** Single Sign-Out via RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
- **Identity Checkpoint (`identity_checkpoint!`):** Pre-flight RFC 7662 token introspection for sensitive actions (e.g. payments) with immediate session revocation handling.

---

## Installation & Onboarding

> [!TIP]
> **Complete Step-by-Step Onboarding Guide:** See [`docs/guides/new_client_onboarding_guide.md`](../docs/guides/new_client_onboarding_guide.md) for full instructions on key generation, registering via the Client Configuration Manager, and testing your OAuth 2.1 integration.

Add to your application's `Gemfile`:

```ruby
gem "oauth2_client_kit", path: "../oauth2_client_kit"
```

Then execute:
```bash
bundle install
```

---

## Rails Integration

### 1. Configure the Client
Create `config/initializers/oauth2_client_kit.rb`:

```ruby
OAuth2ClientKit.configure do |config|
  config.client_id = "my-client"
  config.private_key_path = Rails.root.join("keys/client_private_key.pem").to_s
  config.issuer_url = ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
  config.internal_issuer_url = ENV.fetch("AUTH_SERVER_URL_INTERNAL", config.issuer_url)
  config.redis_url = ENV.fetch("REDIS_URL", "redis://localhost:6379/1")
  config.after_login_path = "/profile"
  config.after_logout_path = "/"
end
```

### 2. Mount Authentication Routes
In `config/routes.rb`:

```ruby
Rails.application.routes.draw do
  root to: "pages#index"
  get "/profile", to: "pages#profile"

  # Mounts /auth/start, /callback, /auth/refresh, /auth/revoke, /logout, /oidc/backchannel_logout
  mount_oauth2_client_kit
end
```

### 3. Controller Methods & Identity Checkpoint
Include `OAuth2ClientKit::ControllerMethods` in your controller:

```ruby
class PaymentsController < ApplicationController
  include OAuth2ClientKit::ControllerMethods

  before_action :require_authentication!

  def create
    # Pre-flight Identity Checkpoint before processing payment:
    # Verifies active status via RFC 7662 Token Introspection to ensure the session hasn't been terminated early.
    # If revoked at Authorization Server, automatically terminates session and halts action.
    checkpoint = identity_checkpoint!

    unless checkpoint[:active]
      flash[:error] = "Security Checkpoint Failed: Session invalid or revoked."
      return redirect_to root_path
    end

    # Proceed with payment...
    flash[:notice] = "Payment approved for user #{checkpoint[:sub]}!"
    redirect_to root_path
  end
end
```

### Available Helper Methods
- `current_user`: Merged profile claims (ID token + UserInfo)
- `authenticated?`: Boolean indicating active user session
- `require_authentication!`: Guard redirecting unauthenticated users to root
- `current_access_token`: Active raw access token
- `current_token_data`: Complete cached token attributes
- `ensure_fresh_access_token!`: Refreshes access token if expiring within 60s
- `identity_checkpoint!`: Pre-flight introspection check to verify if session is still active (aliases: `validate_user!`, `verify_active_token_for_sensitive_action!`)
- `refresh_token_session!`: Explicitly trigger token refresh

---

## Architecture & Integration Model

### Component Separation & Storage Boundaries

```
 ┌─────────────────────────────────────────────────────────────┐
 │                Host Application (e.g. Rails)                │
 │  • Business Domain Controllers, Models, and Views           │
 │  • Client Application Session (Cookies, Redis DB, or DB)    │
 │    (e.g., shopping cart, user preferences, tenant ID)       │
 └──────────────────────────────┬──────────────────────────────┘
                                │ includes ControllerMethods
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                   oauth2_client_kit Gem                     │
 │  • Engine / Route Dispatcher (`mount_oauth2_client_kit`)     │
 │  • Asymmetric Client Assertion (`private_key_jwt`, RS256)   │
 │  • Sender-Constrained DPoP Engine (EC P-256 / ES256)        │
 │  • Strict Algorithm Pinning & JWKS Cache                    │
 │  • Backchannel Logout Receiver (`/oidc/backchannel_logout`)  │
 └──────────────┬──────────────────────────────┬───────────────┘
                │ Reads / Writes Token Data    │ Backchannel TLS
                ▼                              ▼
 ┌──────────────────────────────┐ ┌────────────────────────────┐
 │  Isolated Token Store (DB 1) │ │ Spring Authorization Server │
 │  • Raw tokens & DPoP keys    │ │ (http://localhost:9000)    │
 │  • Single-use OAuth states   │ └────────────────────────────┘
 │  • Sub/SID lookup indexes    │
 └──────────────────────────────┘
```

### Application Sessions vs. Token Store Isolation

Clients often maintain their own user state (cart items, active tabs, tenant context, etc.). To avoid polluting client data or creating storage conflicts:

1. **Client Application Session**: Managed entirely by the host app via standard `session[...]`. The gem only sets minimal reference pointers (`session[:user]`, `session[:token_key]`, `session[:id_token_claims]`).
2. **Token Store**: Managed separately by `OAuth2ClientKit::TokenStore` in a dedicated cache namespace or Redis database (e.g. `redis://localhost:6379/1`). This isolates high-entropy cryptographic keys and raw tokens, and permits asynchronous Back-Channel Logout (BCL) to purge user tokens across Redis without corrupting unrelated application data.

---

## Identity Checkpoint Sequence (`identity_checkpoint!`)

Before executing high-value or sensitive operations (payments, administrative changes, data export), applications can call `identity_checkpoint!` to ensure that the user's authorization session has not been revoked out-of-band by security administrators or fraud-detection engines:

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant App as Host Rails Application
    participant Gem as oauth2_client_kit
    participant Store as Redis Token Store
    participant AS as Authorization Server

    User->>App: POST /checkout (Sensitive Action)
    App->>Gem: identity_checkpoint!
    Gem->>Store: Read active access_token & client_assertion
    Gem->>AS: POST /oauth2/introspect (RFC 7662 + private_key_jwt)
    alt Session Valid (active: true)
        AS-->>Gem: HTTP 200 { active: true, sub: "user-123", exp: ... }
        Gem-->>App: { active: true, sub: "user-123" }
        App-->>User: HTTP 200 Payment Processed Successfully
    else Session Revoked / Terminated Early (active: false)
        AS-->>Gem: HTTP 200 { active: false }
        Gem->>Store: Evict token cache entry
        Gem->>App: reset_session
        Gem-->>App: { active: false, reason: "token_inactive_or_revoked" }
        App-->>User: HTTP 302 Redirect to / (Session Terminated)
    end
```

---

## RFC 9221: JWT-Secured Authorization Response Mode (JARM)

`oauth2_client_kit` strictly enforces RFC 9221 JARM across all authorization callbacks. Both successful code exchanges and authorization error notifications are returned as cryptographically signed JWS JWTs (`?response=<jwt>`) signed by the Authorization Server's AWS KMS hardware key (RS256).

### Attack Surface Mitigation

1. **Anti-Tampering:** Attacker cannot alter `code`, `state`, `iss`, or `error` parameters in the browser URL.
2. **Anti-Phishing / Error Forgery Defense:** In standard OAuth 2.0 (RFC 6749), error descriptions are plain query parameters (`?error=access_denied&error_description=...`). An attacker could forge phishing messages or inject arbitrary text making the client application display misleading instructions (e.g. *"Your account is suspended, send 1 BTC to address XYZ to unlock"*). With RFC 9221 JARM, the error payload is signed with AWS KMS RS256, mathematically guaranteeing authenticity.
3. **Strict Plaintext Rejection:** Any callback received without a signed `response` parameter (e.g., `?code=...` or `?error=...`) is immediately rejected as an unauthenticated, untrusted request.

### JARM Authorization & Error Flow Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant Client as Host Rails App (oauth2_client_kit)
    participant AS as Spring Authorization Server (AWS KMS)
    participant IdP as Identity Provider

    User->>Client: 1. Start Login (POST /auth/start)
    Client->>AS: 2. Backchannel PAR (response_mode=jwt, PKCE, private_key_jwt)
    AS-->>Client: 3. Return opaque request_uri
    Client-->>User: 4. Redirect to /oauth2/authorize?client_id=...&request_uri=...
    User->>IdP: 5. Authenticate at IdP
    alt Authentication Success
        IdP-->>AS: User authenticated
        AS->>AS: Generate KMS RS256 JWS (code, iss, aud, exp, state)
        AS-->>User: HTTP 302 /callback?response=<JARM_JWT>
        User->>Client: GET /callback?response=<JARM_JWT>
        Client->>Client: Verify KMS RS256 signature against AS JWKS
        Client->>AS: Backchannel Token Exchange (DPoP + private_key_jwt)
        AS-->>Client: Tokens Issued (DPoP sender-constrained)
        Client-->>User: HTTP 302 /profile (Authenticated)
    else Authentication Failure (e.g. locked user, access denied)
        IdP-->>AS: Redirect back with error=access_denied&error_description=...
        AS->>AS: Generate KMS RS256 JWS (error, error_description, iss, aud, exp, state)
        AS-->>User: HTTP 302 /callback?response=<JARM_ERROR_JWT>
        User->>Client: GET /callback?response=<JARM_ERROR_JWT>
        Client->>Client: Verify KMS RS256 signature against AS JWKS
        Client-->>User: HTTP 403 / 400 Render Host Custom Error View
    else Plaintext Callback Attack
        User->>Client: GET /callback?code=forged_code (or ?error=forged_msg)
        Client->>Client: Check params[:response] -> MISSING
        Client-->>User: HTTP 302 / 400 Reject unauthenticated plaintext parameters
    end
```

---

## Error Handling & View Overrides

During authentication journeys, if an issue occurs (such as an account lock, consent cancellation, suspended user, or invalid request), errors are cryptographically signed by the Authorization Server and returned to the client callback as an RFC 9221 JARM token (`/callback?response=<jwt>`).

The library automatically validates the JARM signature, decodes the verified error claims, and renders clean, accessible error screens with appropriate HTTP statuses (`403 Forbidden` for `access_denied` / `unauthorized_client`, `401 Unauthorized` for authentication requirements, and `400 Bad Request` for request errors).

### View Override Resolution

Consuming applications can customize error views using standard Rails template overrides:

1. **Per-Error Custom Template**: `app/views/oauth2_client_kit/auth/<error_code>.html.erb`  
   *Example:* Creating `app/views/oauth2_client_kit/auth/access_denied.html.erb` in your host application will automatically handle all `access_denied` errors (e.g. account locked or user cancelled) with custom branding, helpdesk links, or retry workflows.
2. **Global Error Override**: `app/views/oauth2_client_kit/auth/error.html.erb`  
   Creating this in your host application overrides the fallback template for all error codes.
3. **Built-in Gem Default**: `oauth2_client_kit/app/views/oauth2_client_kit/auth/error.html.erb`  
   If no custom templates are provided by the host app, the gem renders its built-in error card inside the host application's layout showing `@error`, `@error_description`, and action buttons to retry or return home.

Available instance variables in error views:
- `@error`: The OAuth 2.1 error code (e.g. `access_denied`, `account_suspended`, `invalid_request`).
- `@error_description`: Cryptographically verified explanation from the identity provider.
- `@error_uri`: (Optional) Diagnostic documentation link from the identity provider.

