# Higher Key & Cryptographic Standards (Design Options — Not Implemented)

This document catalogues **stronger cryptographic options** than the platform's current defaults,
with pros/cons and migration considerations. **None of these are implemented today** — this is a
decision aid for future hardening, not a description of current behaviour.

## Current Baseline (What Is Implemented Today)

| Concern | Current implementation | Location |
|---|---|---|
| Token signing (access/ID/JARM/logout) | **RSA-2048** via AWS KMS, `RSASSA_PKCS1_V1_5_SHA_256` (RS256) | KMS `alias/oauth2-signing-key` |
| Algorithm pinning | Strict **RS256** only; `none`/`HS256` rejected | `KeyConfig`, client kit `verify_signed_jwt` |
| Client authentication | `private_key_jwt` (RFC 7523), client RSA-2048 keys, RS256 | `ClientAssertionDecoderFactory` |
| DPoP proof keys | Ephemeral **EC P-256 (ES256)** or RSA-2048 | client kit `generate_dpop_key` |
| Password hashing at rest | **BCrypt(cost=10)** of a SHA-256 digest | `UserAdminController` |
| Client public-key generation (UI) | **RSA-2048**, `RSASSA-PKCS1-v1_5`, SHA-256 (WebCrypto) | `client-manager` |

> **FIPS accuracy note:** The README describes token signing as running inside a "FIPS 140-2 Level 3
> HSM." That is a claim about **AWS KMS in a real AWS deployment**, not about the code or the local
> LocalStack emulator (which provides **no** FIPS boundary). Local/dev signing is not FIPS-validated.
> "Highest FIPS standard" today would be **FIPS 140-3**; AWS KMS HSMs are validated under FIPS 140-2
> (Level 3 for the HSM) with 140-3 transition in progress. Do not assert 140-3 from this codebase.

---

## 1. Token & Assertion Signing Algorithms

### Option A — RSA-3072 / RSA-4096 (RS256/RS384)
- **Pros:** Drop-in with existing RSA/JWKS tooling; higher security margin (RSA-3072 ≈ 128-bit
  security, aligning with NIST SP 800-57 recommendations beyond 2030); KMS supports `RSA_3072`/`RSA_4096`.
- **Cons:** Larger signatures and slower signing (KMS `Sign` latency and cost rise with modulus size);
  bigger JWKS payloads; marginal benefit over well-managed RSA-2048 with rotation.

### Option B — ECDSA P-256 / P-384 (ES256 / ES384)
- **Pros:** Much smaller keys and signatures than RSA at equivalent strength (P-256 ≈ RSA-3072);
  faster signing; lower KMS cost; widely supported (`ES256` is a FAPI-friendly choice).
- **Cons:** Requires migrating algorithm pinning from RS256 → ES256 on **both** server and every client
  (the client kit currently hard-pins RS256 for ID/JARM/logout verification); ECDSA nonce-reuse is
  catastrophic if a non-KMS signer is ever introduced (KMS mitigates this).

### Option C — EdDSA (Ed25519, `EdDSA`)
- **Pros:** Deterministic signatures (no nonce-reuse risk), fast, compact, modern.
- **Cons:** **AWS KMS does not support Ed25519 signing**, breaking the "keys never leave the HSM"
  guarantee; JWT/JOSE library support is less universal; not FIPS-validated in most HSMs. Not
  recommended while KMS-backed signing is a hard requirement.

### Option D — RSASSA-PSS (PS256/PS384) instead of PKCS#1 v1.5
- **Pros:** PSS padding is the modern, provably-secure RSA scheme; recommended over PKCS#1 v1.5.
- **Cons:** KMS supports `RSASSA_PSS_SHA_256`, but every verifier (client kit's strict `alg == "RS256"`
  check) must be widened to accept `PS256`; some older clients lack PSS support.

**Recommendation (if hardening):** ECDSA **P-256 (ES256)** for the best size/speed/security balance, or
RSA-3072 if RSA compatibility must be preserved. Both are KMS-backed and keep the HSM guarantee.

---

## 2. Client Authentication Keys

- Current: client RSA-2048 + `private_key_jwt` (RS256).
- **Stronger:** EC P-256 client keys with ES256 assertions (smaller, faster) — the client kit's
  `build_client_assertion` and the server's `ClientAssertionDecoderFactory` would both need to accept
  EC. Alternatively, **mTLS client authentication (RFC 8705)** provides hardware-grade client identity
  (see the README roadmap) at the cost of PKI/CA lifecycle management.

---

## 3. Password Hashing (`app_users.password_hash`)

Current: `BCrypt(cost=10)` applied to a SHA-256 digest (see
[User Management §3](user_management_and_authentication.md#3-two-stage-password-pipeline-sha-256--bcrypt)).

<a id="password-hashing"></a>

| Algorithm | Pros | Cons |
|---|---|---|
| **BCrypt (current)** | Battle-tested; salted; adaptive cost; ubiquitous library support. | Memory-cheap → GPU/ASIC attacks scale better than against memory-hard KDFs; 72-byte input cap (a non-issue here because input is a fixed 64-char hex digest). |
| **Argon2id** (recommended) | Winner of the Password Hashing Competition; **memory-hard** (resists GPU/ASIC); tunable time/memory/parallelism; OWASP's first choice. | Newer; requires a maintained library (e.g. a JVM Argon2 binding); must tune parameters per environment; higher server memory per hash. |
| **scrypt** | Memory-hard; well-studied. | Parameter tuning is fiddly; fewer FIPS options. |
| **PBKDF2-HMAC-SHA256** | **FIPS 140 approved** (the only FIPS-validated option here); simple. | Not memory-hard → weakest against GPU attacks; needs very high iteration counts. |

**Recommendation:** migrate the server-tier hash to **Argon2id** for best resistance, or **PBKDF2** if a
strict FIPS-validated KDF is mandated. Migration can be transparent: verify against the stored scheme and
re-hash on next successful login. Keep the client-tier SHA-256 pre-hash as defence-in-depth regardless.

---

## 4. Key Sizes for Browser-Generated Client Keys

The Client Manager generates **RSA-2048** in-browser via WebCrypto. WebCrypto also supports RSA-4096 and
ECDSA P-256/P-384 (`ECDSA`/`ECDH`). Moving the UI generator to **ECDSA P-256** would align with an ES256
migration and produce smaller keys, but only after the server accepts EC client assertions (§2).

---

## 5. FIPS 140-3 Posture (Deployment, Not Code)

To legitimately claim a high FIPS posture in production:

- **Pros of pursuing 140-3:** strongest validated assurance; often a compliance requirement (PCI DSS,
  FedRAMP); AWS KMS HSMs already provide a validated boundary.
- **Cons / requirements:** it is an **operational/deployment** property — the code cannot guarantee it.
  You must (a) point signing at a real FIPS-validated AWS KMS region (not LocalStack), (b) run the JVM/OS
  in FIPS mode with a validated crypto provider (e.g. BouncyCastle FIPS) for any in-process crypto such as
  DPoP verification or password hashing, and (c) restrict algorithms to the validated set. Until then, the
  README's FIPS 140-2 Level 3 wording should be scoped to "when deployed against AWS KMS."

---

## Summary Recommendation Matrix

| Area | Keep | Consider | Avoid (here) |
|---|---|---|---|
| Token signing | RSA-2048 + rotation | ES256 (P-256) or RSA-3072; PS256 | Ed25519 (no KMS support) |
| Client auth | private_key_jwt RS256 | ES256 or mTLS (RFC 8705) | client secrets |
| Password hash | — | Argon2id (or PBKDF2 for FIPS) | plain SHA-256 alone |
| FIPS claims | scope to AWS KMS deployment | FIPS-mode JVM + provider for 140-3 | asserting 140-3 from code |
