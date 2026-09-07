# Ruby on Rails Identity Provider (IdP)

A hardened, production-grade authentication application built with **Ruby on Rails 7**, serving as the external Identity Provider (IdP) for the Spring Authorization Server ecosystem.

---

## Overview

When an unauthenticated user attempts to authorize at the Spring Authorization Server, Spring redirects the user's browser to this Rails application (`http://localhost:3000/login?return_to=...`).

Upon successful credentials verification, Rails:
1. Generates a secure cryptographic UUIDv4 session identifier.
2. Writes user authentication claims to Redis (DB 0) under key `session:<uuid>`.
3. Issues a hardened `SHARED_SESSION_ID` cookie to the user's browser.
4. Redirects the user back to the sanitized `return_to` parameter on Spring Authorization Server.

Spring's `SharedRedisSessionFilter` inspects the cookie, loads the session from Redis DB 0, and establishes a Spring `SecurityContext` without ever storing user credentials in Spring Boot.

---

## Security Hardening & Defenses

Every controller and configuration in this application is strictly annotated with explanatory comments documenting the specific vulnerability mitigated:

| Security Feature | Implementation Location | Vulnerability Mitigated |
|---|---|---|
| **HttpOnly Cookie** | `sessions_controller.rb` | Mitigates XSS-based cookie theft by blocking client-side JavaScript access. |
| **SameSite: Lax** | `sessions_controller.rb` | Blocks Cross-Site Request Forgery (CSRF) by omitting cookies on cross-origin requests. |
| **Secure Flag** | `sessions_controller.rb` | Enforces transmission over encrypted HTTPS channels in production. |
| **No Session ID in URLs** | `sessions_controller.rb` | Eliminates **CWE-598 URL leakage** into browser histories, server access logs, and HTTP Referer headers. |
| **Open Redirect Whitelist** | `sessions_controller.rb` (`ALLOWED_RETURN_HOSTS`) | Restricts redirects strictly to `localhost:9000`, `127.0.0.1:9000`, and `spring-auth-server:9000`, stopping open redirect and credential phishing attacks. |
| **Constant-Time Verification** | `sessions_controller.rb` | Uses `ActiveSupport::SecurityUtils.secure_compare` to eliminate side-channel timing attack vectors. |
| **Session Invalidation on Login** | `sessions_controller.rb` | Destroys previous Redis session keys upon re-authentication to prevent session fixation attacks. |
| **Strict UUID Format Validation** | `sessions_controller.rb` | Enforces regex pattern `^[0-9a-fA-F-]{36}$` before performing Redis operations to avoid key injection. |
| **Persistent Redis Connection** | `sessions_controller.rb` (`self.redis_client`) | Reuses a thread-safe Redis client connection to eliminate TCP socket churn and ephemeral port exhaustion under heavy concurrent login spikes. |
| **CSRF Protection** | `application_controller.rb` | Mandates `protect_from_forgery with: :exception` on all state-changing endpoints. |

---

## Test Accounts

The following demo accounts are available out of the box:

| Username | Password | Full Name | Roles |
|---|---|---|---|
| `alice_smith` | `secret123` | Alice Smith | `ROLE_USER`, `ROLE_ADMIN` |
| `bob_jones` | `password456` | Bob Jones | `ROLE_USER` |

---

## Running Locally

### With Mise
```bash
cd rails-app
mise exec -- bundle install
mise exec -- bundle exec rails server -p 3000 -b 0.0.0.0
```

### With Docker Compose
```bash
docker compose up -d rails-app
```
Visit: **`http://localhost:3000/login`**
