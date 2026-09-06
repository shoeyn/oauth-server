# OAuth 2.1 Client Configuration Manager (Next.js 15 & LocalStack S3)

A modern, responsive administrative web application and REST API for managing dynamic OAuth 2.1 client configurations in **AWS S3** (locally emulated via **LocalStack**), backed by **Redis Pub/Sub** for zero-downtime hot-reloading in Spring Authorization Server.

---

## Architecture Overview

```
+------------------------------------------------------------------------------------+
| Next.js Client Manager (http://localhost:3001)                                      |
| - Interactive Dashboard & Client Management                                        |
| - In-Browser 2048-bit RSA Key Pair Generator (Web Crypto API)                      |
| - Server-Determined Scopes & Token TTL Settings                                    |
| - REST API (/api/clients, /api/clients/[id])                                       |
+--------------------------+-----------------------------------+---------------------+
                           | S3 PutObject / DeleteObject       | Redis PUBLISH
                           v                                   v
             +------------------------------+     +----------------------------------+
             | LocalStack S3 (Port 4566)     |     | Redis (Port 6379)                |
             | Bucket: oauth2-clients       |     | Channel: oauth2:clients:reload   |
             | Key: clients/<client_id>.json|     +----------------+-----------------+
             +--------------+---------------+                      |
                            | getObject()                          | Redis Message Listener
                            v                                      v
+------------------------------------------------------------------+-----------------+
| Spring Authorization Server (http://localhost:9000)                                |
| - S3RegisteredClientRepository: Dynamically loads and caches client JSON configs   |
| - ClientReloadRedisSubscriber: Refreshes client repository in real time (<20ms)    |
| - Dynamic private_key_jwt validation: Authenticates clients via S3 public key      |
+------------------------------------------------------------------------------------+
```

---

## Features

1. **S3-Backed Client Configuration**:
   - Stores all client definitions as JSON files in `s3://oauth2-clients/clients/<client_id>.json`.
   - Complete schema support for redirect URIs, post-logout URIs, token TTLs, and grant types.

2. **In-Browser Cryptographic Key Pair Generation**:
   - Generate secure 2048-bit RSA key pairs (`RS256`) directly in the browser via the native Web Crypto API.
   - Automatically populates the public key in X.509 PEM format into the configuration form.
   - Provides a one-click download for the corresponding private key (`<client_id>_private_key.pem`) for use by the client application.

3. **Server-Determined Scopes Configuration**:
   - Toggle standard server-determined scopes (`openid`, `profile`, `email`, `user.read`, `demo.secret_access`) or define custom scopes.
   - Guarantees clients cannot self-assign privileged scopes.

4. **Zero-Downtime Hot-Reloading via Redis Pub/Sub**:
   - Saving or deleting a client via the UI or API publishes a `RELOAD:<client_id>` message to the Redis channel `oauth2:clients:reload`.
   - Spring Authorization Server's `ClientReloadRedisSubscriber` receives the message and refreshes its in-memory repository without restarting.

5. **LocalStack Emulation (Zero AWS Costs)**:
   - Configured to communicate exclusively with LocalStack S3 (`http://localhost:4566` / `http://localstack:4566`), avoiding any external AWS calls or credentials.

---

## S3 Client JSON Schema

Each client is persisted at `clients/<client_id>.json` matching this schema:

```json
{
  "clientId": "partner-client",
  "clientName": "Partner Client Application",
  "clientAuthenticationMethods": ["private_key_jwt"],
  "authorizationGrantTypes": ["authorization_code", "refresh_token", "client_credentials"],
  "redirectUris": ["http://localhost:8080/callback"],
  "postLogoutRedirectUris": ["http://localhost:8080/"],
  "scopes": ["openid", "profile", "email", "user.read"],
  "requireProofKey": true,
  "requireAuthorizationConsent": false,
  "accessTokenTimeToLiveMinutes": 15,
  "refreshTokenTimeToLiveDays": 30,
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

---

## REST API Endpoints

### 1. `GET /api/clients`
Retrieves all registered clients currently stored in the S3 bucket.

### 2. `POST /api/clients`
Creates or updates a client JSON configuration in S3 and broadcasts a Redis reload event.
- **Request Body**: JSON matching the schema above.
- **Response**: HTTP 201 with saved client data.

### 3. `DELETE /api/clients/[id]`
Deletes the client configuration from S3 and broadcasts a Redis reload event.
- **Response**: HTTP 200 `{"deleted": true}`.

---

## Running Locally

### Prerequisites
- Node.js 18+ and `pnpm`
- Running Redis on `localhost:6379`
- Running LocalStack on `localhost:4566`

### Start Development Server
```bash
pnpm install
pnpm dev -p 3001
```

### Production Build & Run
```bash
pnpm build
pnpm start -p 3001
```
Visit: **`http://localhost:3001`**

---

## Running Functional Tests

```bash
bash functional_tests/run_functional_tests.sh
```
Verifies client creation, Redis event publishing, OAuth 2.1 code exchange authentication against Spring, and dynamic client deletion.
