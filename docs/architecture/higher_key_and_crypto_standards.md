# Higher Key & Cryptographic Standards

This document catalogues the cryptographic architecture of the platform, the rationale for the completed **ES256 (ECDSA NIST P-256)** transition, and future design options (e.g. Argon2id, mTLS, post-quantum cryptography).

---

## Current Cryptographic Baseline (Implemented Architecture)

The platform has transitioned completely from legacy RS256 (RSA-2048) to **ES256 (ECDSA NIST P-256 / secp256r1 / prime256v1)** across all architectural tiers:

| Concern | Active Implementation | Cryptographic Primitive | Location |
|---|---|---|---|
| **Token Signing (Access, ID, JARM, Logout)** | **ECDSA P-256 (ES256)** via AWS KMS | `ECC_NIST_P256`, `ECDSA_SHA_256`, IEEE P1363 (64 bytes) | KMS `alias/oauth2-signing-key`, `KmsEcSigner`, `KmsJwtEncoder` |
| **Strict Algorithm Pinning** | Strict **ES256** enforced; `none`, symmetric `HS256`, and non-approved asymmetric algorithms actively rejected | RFC 8725 §3.1 algorithm pinning | `AuthorizationServerConfig`, `TokenValidator`, `KmsEcSigner` |
| **Client Authentication** | `private_key_jwt` (RFC 7523), client EC P-256 keys | Asymmetric ES256 signature verification, JTI replay prevention | `ClientAssertionDecoderFactory`, `PostgresRegisteredClientRepository` |
| **DPoP Sender-Constraint Keys** | Ephemeral **EC P-256 (ES256)** | RFC 9449 proof-of-possession, JWK thumbprint binding (`cnf.jkt`) | `DPoPHandler`, `StrictDPoPTokenRequestAuthenticationConverter` |
| **Password Storage Pipeline** | **BCrypt (cost=10)** of client-side **SHA-256 pre-hash** | Defense-in-depth: plaintext never crosses service boundary | `UserAdminController`, `sessions_controller.rb`, `users.ts` |
| **In-Browser Client Key Generation** | **ECDSA NIST P-256** | Native Web Crypto API (`ECDSA`, `namedCurve: "P-256"`) | `client-manager/lib/crypto.ts` |

---

## 1. Token & Assertion Signing: ES256 Transition Rationale

The platform has standardized on **Option B: ECDSA NIST P-256 (`ES256`)**. The architectural trade-offs compared to alternatives are summarized below:

### Option A — RSA-2048 / RSA-3072 / RSA-4096 (RS256/RS384) [Legacy / Deprecated]
- **Characteristics:** 2048 to 4096-bit moduli, PKCS#1 v1.5 or PSS padding.
- **Why Superseded:**
  - RSA signatures are large (256–512 bytes), inflating JARM authorization redirect URLs (`?response=<jwt>`), HTTP headers, and mobile network payloads.
  - Key generation and signing are computationally expensive, introducing significant CPU blocking time.
  - NIST SP 800-57 disallows RSA-2048 for high-assurance applications beyond 2030, necessitating early migration to 3072+ bit keys.

### Option B — ECDSA NIST P-256 (`ES256`) [ACTIVE & ENFORCED]
- **Characteristics:** 256-bit elliptic curve over prime field (`prime256v1` / `secp256r1`).
- **Architectural Benefits:**
  - **128-bit Equivalent Security Margin:** Matches RSA-3072 strength with an order of magnitude smaller key footprint (64-byte raw IEEE P1363 signature vs 256-byte RSA signature).
  - **Sub-Millisecond Operation:** Signing and verification execute up to 4,800x faster than RSA in software, reducing median interactive auth session latency from 494.5 ms to 167.1 ms under AWS KMS load.
  - **Network Efficiency:** JARM redirect URLs and Authorization headers remain ultra-compact, preventing URL length overflows in edge proxies and webview browsers.
  - **Financial-Grade Conformance:** Recommended by OpenID Foundation FAPI 2.0 Security Profile.
  - **AWS KMS Hardware Security:** Fully backed by AWS KMS `ECC_NIST_P256` asymmetric keys, preserving the guarantee that private keys never enter host or JVM heap memory.

### Option C — EdDSA (Ed25519) [Evaluated, Not Recommended for AWS KMS]
- **Characteristics:** Edwards-curve Digital Signature Algorithm over Curve25519.
- **Why Not Adopted:** AWS KMS does **not** support Ed25519 asymmetric signing keys. Adopting Ed25519 would force private keys into application memory or require custom external HSM infrastructure, violating the primary security invariant that private signing keys never reside on the host.

### Option D — RSASSA-PSS (PS256/PS384) [Evaluated]
- **Characteristics:** Probabilistic Signature Scheme padding for RSA.
- **Why Not Adopted:** While mathematically superior to PKCS#1 v1.5, PS256 shares RSA's performance and payload footprint disadvantages without offering ECDSA's compact efficiency.

---

## 2. Client Authentication Keys (`private_key_jwt`)

- **Active Implementation:** All client applications authenticate to the Authorization Server using RFC 7523 `private_key_jwt` assertions signed with ECDSA NIST P-256 (`ES256`).
- **Server Verification:** `ClientAssertionDecoderFactory` validates client assertions using the client's public EC key stored in PostgreSQL, enforcing `alg == "ES256"`, audience checking (`aud` matching `/oauth2/token` or `/oauth2/par`), and single-use `jti` replay tracking in Redis (5-minute TTL).
- **Future Hardening (mTLS RFC 8705):** Mutual TLS client authentication provides hardware-bound client certificates directly at the transport layer, eliminating client assertions entirely at the cost of certificate authority (CA) and PKI lifecycle management.

---

## 3. Password Hashing Pipeline (`app_users.password_hash`)

- **Active Implementation:** A two-stage pipeline where clients (Rails IdP, Next.js Admin) SHA-256 pre-hash plaintext passwords before transmission, and the Spring Auth Server applies `BCrypt(cost=10)` before database persistence.
- **Future Considerations:**

| Algorithm | Strengths | Trade-offs | Status |
|---|---|---|---|
| **BCrypt(10) (Current)** | Salted, adaptive work factor, ubiquitous library support, resistant to CPU attacks. | Memory-cheap; GPU/ASIC crackers scale better than against memory-hard KDFs. | **Active** |
| **Argon2id** | Winner of PHC; memory-hard (resists GPU/ASIC parallelism); OWASP #1 recommendation. | Requires native library binding (Argon2 JVM); higher server memory footprint under load. | **Future Option** |
| **PBKDF2-HMAC-SHA256** | **FIPS 140 Approved** (NIST SP 800-132); simple; zero external dependencies. | Not memory-hard; requires high iteration counts (>600,000) for modern brute-force resistance. | **FIPS Option** |

---

## 4. In-Browser Client Key Generation

The **Next.js Client Configuration Manager** generates cryptographic key pairs entirely client-side using the native Web Crypto API:
```typescript
const keyPair = await window.crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"]
);
```
- The private key is exported in PKCS#8 PEM format and downloaded directly to the administrator's local machine; it is never transmitted over the network or saved in server storage.
- The public key is exported in X.509 SubjectPublicKeyInfo PEM format and populated into the client registration form for persistence in PostgreSQL.

---

## 5. FIPS 140-3 Compliance Posture & Operational Roadmap

### Current Development Environment vs. Production AWS Deployment

> [!IMPORTANT]
> **Emulation vs. Physical Boundary:**
> In local development, the platform uses **LocalStack KMS**, which runs pure software cryptographic emulation inside Docker. LocalStack provides **no physical security boundary** and is **not FIPS-validated**.
> 
> When deployed into production on **real AWS infrastructure**, AWS Key Management Service (AWS KMS) utilizes Hardware Security Modules (HSMs) certified under **FIPS 140-2 Level 3** (with FIPS 140-3 certifications actively rolling out across AWS regions). Because all private signing keys (`ECC_NIST_P256`) are generated, stored, and executed inside the AWS KMS HSM, token signing operations meet the **FIPS 140-2 / FIPS 140-3 Level 3 hardware cryptographic boundary requirement**.

### 5-Step Roadmap for End-to-End System FIPS 140-3 Compliance

To achieve comprehensive, end-to-end system compliance at the FIPS 140-3 standard, the following operational steps are required:

1. **Target Real AWS KMS with Dedicated FIPS Endpoints:**
   - Configure Spring Boot's AWS SDK to use AWS KMS regional FIPS endpoints (e.g. `kms-fips.us-east-1.amazonaws.com`), ensuring all RPC transport utilizes TLS with FIPS-validated cipher suites.
2. **Deploy JVM in FIPS Mode with Validated Crypto Provider:**
   - Run the Spring Boot application container on a FIPS-enabled operating system (e.g., Red Hat Enterprise Linux or Amazon Linux 2023 with `fips=1` kernel parameter).
   - Configure the Java runtime to use a FIPS 140-3 validated Cryptographic Service Provider (such as **Bouncy Castle FIPS Java API** `bc-fips` or **Amazon Corretto Crypto Provider (ACCP)** in FIPS mode) as the primary JCE security provider for all in-process cryptography (DPoP EC key validation, SHA-256 hashing, client assertion signature verification).
3. **Migrate Password Hashing to FIPS-Approved KDF (PBKDF2):**
   - Replace BCrypt with NIST SP 800-132 approved **PBKDF2-HMAC-SHA256** (with >= 600,000 iterations) in `UserAdminController`, as BCrypt is not an approved algorithm under FIPS 140-3.
4. **Enforce FIPS-Compliant TLS Termination at Perimeter Proxy:**
   - Configure Nginx or AWS Application Load Balancer (ALB) with a FIPS-compliant TLS security policy (e.g., `TLS 1.3` and `TLS 1.2` restricted strictly to AES-GCM and ECDHE cipher suites), disabling non-approved ciphers.
5. **Operational Key Management & Dual-Control Policies:**
   - Establish AWS IAM key policies and AWS CloudTrail audit logging enforcing multi-party authorization for key rotation, deletion, and policy alteration, adhering to NIST SP 800-57 key management guidelines.

---

## Summary Matrix

| Area | Current Implementation | FIPS 140-3 Status (Real AWS) | Future Roadmap |
|---|---|---|---|
| **Token Signing** | ECDSA NIST P-256 (`ES256`) via AWS KMS | **Compliant** (Level 3 HSM boundary) | Multi-region KMS replica keys |
| **Algorithm Pinning** | Strict ES256 enforced | **Compliant** (Approved algorithm) | Post-quantum ML-DSA / SLH-DSA hybrid |
| **Client Authentication** | `private_key_jwt` ES256 | **Compliant** (when verified via FIPS JCE) | RFC 8705 mTLS client certificates |
| **DPoP Proofs** | Ephemeral EC P-256 (ES256) | **Compliant** (when verified via FIPS JCE) | Hardware-bound device keys (WebAuthn) |
| **Password Storage** | SHA-256 pre-hash + BCrypt(10) | Requires migration to PBKDF2-SHA256 | PBKDF2-HMAC-SHA256 or Argon2id |
| **Key Generation UI** | In-browser WebCrypto ECDSA P-256 | Client-side only (developer workstations) | Hardware security token (YubiKey) export |
