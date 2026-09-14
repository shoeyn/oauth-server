# Git Diff Audit & Remediation Plan

Full review of every changed and new file in the working tree. Grouped by severity.

---

## Critical Issues

### 🔴 1. SHA-256 password hashing instead of bcrypt

[UserAdminController.java](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/controller/UserAdminController.java) uses raw `MessageDigest.getInstance("SHA-256")` in **three separate places** (create, edit, authenticate). This is a serious security issue:

- SHA-256 is a fast hash — it's trivially brute-forceable with GPUs.
- The password hash comparison at [line 181](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/controller/UserAdminController.java#L181) uses `String.equals()` which is not constant-time (timing attack vector).
- The hashing logic is **duplicated** three times instead of being extracted to a method.

**Fix**: Replace with `BCryptPasswordEncoder` from Spring Security (already a dependency). Use `passwordEncoder.encode()` for storage and `passwordEncoder.matches()` for verification (which is constant-time). Extract to a private method. Update [V4 migration](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/resources/db/migration/V4__create_users_table.sql) seed data to use a bcrypt hash.

---

### 🔴 2. FQNs everywhere in AuthorizationServerConfig graceful logout

[AuthorizationServerConfig.java lines 120-173](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/config/AuthorizationServerConfig.java#L120-L173) is littered with fully qualified names:

- `org.springframework.context.ApplicationContext`
- `org.springframework.web.context.support.WebApplicationContextUtils`
- `com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext>`
- `org.springframework.security.oauth2.jwt.NimbusJwtDecoder`
- `org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration`
- `org.springframework.security.oauth2.core.OAuth2TokenValidatorResult`
- `org.springframework.security.oauth2.jwt.Jwt`
- `org.springframework.security.oauth2.server.authorization.client.RegisteredClient`
- `java.util.List<String>`
- `jakarta.servlet.http.Cookie` (used inline despite `Cookie` already being imported at line 11)
- `jakarta.servlet.http.HttpServletResponse` (used inline despite `HttpServletResponse` already being imported at line 12)

**Fix**: Move all to proper `import` statements at the top of the file. Most are already imported or trivial to add.

---

### 🔴 3. Graceful logout rebuilds a JwtDecoder on every request

The errorResponseHandler creates a **new `NimbusJwtDecoder`** on every failed logout attempt by pulling beans from the `ApplicationContext` via the servlet context. This is fragile and wasteful.

**Fix**: Refactor the graceful logout fallback into a dedicated `@Component` class (e.g., `GracefulLogoutHandler`) that gets `JwtDecoder`, `RegisteredClientRepository`, `StringRedisTemplate`, and `redisPrefix` injected properly via constructor injection. The inline lambda just delegates to it.

---

### 🔴 4. Open redirect in graceful logout — `postLogoutRedirectUri` not validated against full URL

At [line 163](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/config/AuthorizationServerConfig.java#L163), `response.sendRedirect(postLogoutRedirectUri)` uses the raw request parameter value. Although the code checks `client.getPostLogoutRedirectUris().contains(postLogoutRedirectUri)`, the `postLogoutRedirectUri` from the request could contain path traversal fragments, query params, or encodings that differ from what's registered but still redirect maliciously.

**Fix**: Parse the `postLogoutRedirectUri` as a `URI`, normalise it, and compare strictly against the registered set. Use Spring's `UriComponentsBuilder` for safe comparison.

---

## High Priority Issues

### 🟠 5. No tests for UserAdminController

[UserAdminController.java](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/controller/UserAdminController.java) is a brand-new 195-line controller with 7 endpoints (list, create, edit, flag fraud, unflag fraud, delete, authenticate) and **zero unit tests**. This is the most critical new business logic in the diff.

**Fix**: Write `MockMvc` unit tests covering all 7 endpoints, including edge cases (empty email, wrong password, fraud flag check, pagination boundaries, SQL error handling).

---

### 🟠 6. No tests for the graceful logout fallback

The new 57-line `errorResponseHandler` in [AuthorizationServerConfig.java](file:///Users/nathanshoemark/SpringSecurity/spring-auth-server/src/main/java/com/example/authserver/config/AuthorizationServerConfig.java#L114-L176) has no tests. Once refactored into a dedicated component, it should have unit tests for:
- Expired but validly-signed token → graceful redirect
- Forged/tampered token → falls through to 400
- Missing `id_token_hint` → falls through to 400
- `post_logout_redirect_uri` not registered → falls through to 400
- Redis session eviction during fallback

---

### 🟠 7. Vitest coverage thresholds silently lowered

[vitest.config.ts](file:///Users/nathanshoemark/SpringSecurity/client-manager/vitest.config.ts) dropped `statements` from 100→95 and `functions` from 100→90 with no explanation. This undermines the "as close to 100% as possible" testing policy.

**Fix**: Either restore to 100% and write the missing tests, or document exactly which untestable code is excluded and keep thresholds at 100% with proper `exclude` patterns.

---

### 🟠 8. `client-manager/lib/users.ts` — unused import

[Line 1](file:///Users/nathanshoemark/SpringSecurity/client-manager/lib/users.ts#L1) imports `ClientConfig` from `./types` but never uses it.

**Fix**: Remove the unused import.

---

### 🟠 9. Rails layout indentation broken

[rails-app/app/views/layouts/application.html.erb](file:///Users/nathanshoemark/SpringSecurity/rails-app/app/views/layouts/application.html.erb) — the injected error message divs and `<%= yield %>` are not indented consistently with the surrounding `<body>` tag. The closing `</div>` sits at column 0.

**Fix**: Re-indent to match the original 4-space ERB indentation.

---

## Medium Priority Issues

### 🟡 10. `sessions_controller.rb` — `flash.now[:error]` set but never rendered

At line 320 in the diff, the simulate_error branch sets `flash.now[:error]` alongside `@error_message`. But the layout only checks `flash[:error]` (not `flash.now[:error]`). In a `render` (not redirect), Rails uses `flash.now`, so the `flash[:error]` check in the layout will never match this particular path.

**Fix**: The layout should check both, or just use `@error_message` consistently and remove the `flash.now[:error]` line to avoid confusion.

---

### 🟡 11. Duplicated session cookie eviction logic

The cookie clearing pattern (find `SHARED_SESSION_ID` in cookies, delete from Redis, create zeroed cookie) now appears **three times** in `AuthorizationServerConfig.java` — the success handler, the graceful fallback, and the success flow. This violates DRY.

**Fix**: Extract into a private helper method `evictSharedSession(HttpServletRequest, HttpServletResponse, StringRedisTemplate, String redisPrefix)` or put it in the proposed `GracefulLogoutHandler` component.

---

### 🟡 12. `success.html.erb` references CSS classes that don't exist

[success.html.erb](file:///Users/nathanshoemark/SpringSecurity/rails-app/app/views/sessions/success.html.erb) uses `class="auth-container"` and `class="alert alert-success"`, but the Rails layout stylesheet doesn't define either of these classes. The view will render unstyled.

**Fix**: Use the existing `.card` class from the layout, or add inline styles consistent with the login form.

---

### 🟡 13. `client-manager/app/layout.tsx` — description metadata removed

The original had a descriptive `description` field in the Next.js metadata. The diff removes it entirely.

**Fix**: Keep a concise description — it's used for SEO/previews and costs nothing.

---

## Summary of Required Work

| # | File | Issue | Action |
|---|------|-------|--------|
| 1 | `UserAdminController.java` | SHA-256 passwords | Replace with `BCryptPasswordEncoder` |
| 2 | `AuthorizationServerConfig.java` | FQNs in graceful logout | Move to imports |
| 3 | `AuthorizationServerConfig.java` | Rebuilds JwtDecoder per request | Extract to `GracefulLogoutHandler` component |
| 4 | `AuthorizationServerConfig.java` | Open redirect risk | Normalise URI before redirect |
| 5 | `UserAdminController.java` | No tests | Write full MockMvc test suite |
| 6 | `AuthorizationServerConfig.java` | No tests for graceful logout | Write unit tests for new component |
| 7 | `vitest.config.ts` | Coverage thresholds lowered | Restore to 100% or justify |
| 8 | `client-manager/lib/users.ts` | Unused import | Remove |
| 9 | `rails-app/app/views/layouts/application.html.erb` | Broken indentation | Re-indent |
| 10 | `sessions_controller.rb` | `flash.now` vs `flash` mismatch | Use `@error_message` only |
| 11 | `AuthorizationServerConfig.java` | Duplicated cookie eviction | Extract helper |
| 12 | `success.html.erb` | Missing CSS classes | Use existing `.card` class |
| 13 | `client-manager/app/layout.tsx` | Missing description metadata | Restore |

## Verification Plan

### Automated Tests
- `cd spring-auth-server && docker compose run --rm spring-auth-server mvn clean test` — JUnit + JaCoCo
- `cd client-manager && pnpm test` — Vitest
- `cd e2e-tests && mise exec -- bundle exec cucumber` — Cucumber E2E

### Manual Verification
- Confirm bcrypt hashes in Postgres after migration
- Confirm graceful logout redirects properly with an expired token
- Confirm no FQNs remain in any Java source files
