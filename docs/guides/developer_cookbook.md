# Developer Cookbook & Iteration Guide

This guide provides practical instructions for engineers iterating on the Spring Authorization Server, adding custom claims, provisioning OAuth clients via API, and debugging services locally in an IDE.

> [!TIP]
> **Looking to connect a new application to this service?** See the step-by-step [New Client Onboarding & Integration Guide](new_client_onboarding_guide.md) for instructions on generating keys, registering in the Client Manager, and configuring `oauth2_client_kit` in Rails.

---

## 1. Dual-Mode Execution (Docker vs. Local IDE Debugging)

Developers can run dependencies (PostgreSQL, Redis, LocalStack KMS, Nginx) in Docker while running `spring-auth-server` locally inside IntelliJ IDEA or VS Code to set breakpoints and enjoy instant compilation.

### Step 1: Start Supporting Services in Docker
```bash
# Start background infrastructure, skipping spring-auth-server and nginx
docker compose up -d postgres redis localstack rails-app
```

### Step 2: Configure Environment Variables in Your Local IDE
Set the following environment variables in your IntelliJ / VS Code Run Configuration:

```bash
# PostgreSQL (Port 5432 exposed to localhost)
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/authserver
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=postgres

# Redis (Port 6379 exposed to localhost)
REDIS_HOST=localhost
REDIS_PORT=6379

# Rails Login IdP (Browser redirect target)
RAILS_LOGIN_URL=http://localhost:3000/login

# Canonical Issuer URL
AUTH_SERVER_ISSUER=http://localhost:9000

# AWS KMS / LocalStack (Port 4566 exposed to localhost)
AWS_KMS_ENABLED=true
AWS_KMS_ENDPOINT=http://localhost:4566
AWS_KMS_KEY_ALIAS=alias/oauth2-signing-key
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test

# Administrative API Key
AUTH_ADMIN_API_KEY=secret-admin-key
```

### Step 3: Run Spring Boot
Launch `com.example.authserver.AuthServerApplication` directly from your IDE or via Maven:
```bash
mise exec -- mvn spring-boot:run
```

---

## 2. Registering an OAuth Client via Admin REST API (`curl`)

While the **Next.js Client Manager** (`http://localhost:3001`) provides an interactive interface, you can provision clients directly via `curl` for CI/CD pipelines and automated seeding.

### Step 1: Generate a 2048-bit RSA Key Pair
```bash
openssl genrsa -out /tmp/my_client_private.pem 2048
openssl rsa -in /tmp/my_client_private.pem -pubout -out /tmp/my_client_public.pem
```

### Step 2: Register Client via Admin API
```bash
PUB_KEY=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0}' /tmp/my_client_public.pem)

curl -X POST http://localhost:9001/api/admin/clients \
  -H "Content-Type: application/json" \
  -H "X-Admin-Api-Key: secret-admin-key" \
  -d '{
    "clientId": "my-service-client",
    "clientName": "Internal Accounting Microservice",
    "clientAuthenticationMethods": ["private_key_jwt"],
    "authorizationGrantTypes": ["authorization_code", "refresh_token"],
    "redirectUris": ["http://localhost:8080/callback"],
    "postLogoutRedirectUris": ["http://localhost:8080/"],
    "scopes": ["openid", "profile", "email", "accounting.read"],
    "requireProofKey": true,
    "requireAuthorizationConsent": false,
    "requirePushedAuthorizationRequests": true,
    "accessTokenTimeToLiveMinutes": 15,
    "refreshTokenTimeToLiveDays": 30,
    "publicKeyPem": "'"${PUB_KEY}"'"
  }'
```
*Note: Target internal port `9001` (or local port `9000` when running outside Docker), as the Nginx perimeter proxy blocks `/api/admin/*` externally with HTTP 403.*

---

## 3. How to Add Custom JWT & UserInfo Claims

All token claim minting is centralized in [`TokenCustomizerConfig.java`](../../spring-auth-server/src/main/java/com/example/authserver/config/TokenCustomizerConfig.java).

### Example: Adding a Custom Tenant & Organization Claim
To add an `organization_id` or `tenant_tier` claim into minted Access Tokens:

1. Open [`TokenCustomizerConfig.java`](../../spring-auth-server/src/main/java/com/example/authserver/config/TokenCustomizerConfig.java).
2. Inside `jwtTokenCustomizer()`, locate the Access Token block:
   ```java
   if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
       // Existing DPoP 'cnf' binding logic...

       // Add your custom claims:
       context.getClaims().claim("tenant_id", "tenant-alpha-001");
       context.getClaims().claim("account_tier", "enterprise_tier");
   }
   ```
3. To propagate claims to the OIDC ID Token, add them to the `OidcParameterNames.ID_TOKEN` block in the same file:
   ```java
   if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
       context.getClaims().claim("organization_unit", "FinTech");
   }
   ```

---

## 4. Hot-Reloading Client Caches in a Running Cluster

When a client configuration is updated directly in PostgreSQL without the Admin REST API:
You can trigger an immediate cluster-wide near-cache refresh by publishing an event to Redis:

```bash
docker compose exec redis redis-cli PUBLISH oauth2as:clients:reload '{"action":"reload"}'
```
Every active Spring Authorization Server node listening on the channel will purge its `ConcurrentHashMap` L1 cache and reload all clients from PostgreSQL in `< 5 ms`.
