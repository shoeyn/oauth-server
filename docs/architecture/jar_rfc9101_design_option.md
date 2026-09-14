# JWT-Secured Authorization Requests (JAR, RFC 9101) — Design Option

This document evaluates **RFC 9101 JAR** (signed request objects) as a future enhancement to the
platform's authorization-request security. **JAR is not implemented today.** The platform currently
secures the authorization request with **RFC 9126 PAR** (Pushed Authorization Requests). This is a
design/decision document, not a description of current behaviour.

---

## 1. What JAR Is

RFC 9101 lets a client encode the authorization request parameters (`client_id`, `redirect_uri`,
`scope`, `state`, `nonce`, `code_challenge`, …) into a **signed JWT — the "request object"** — and pass
it either:

- **by value** as a `request=<jwt>` parameter, or
- **by reference** as a `request_uri=<https-url>` the server dereferences.

The authorization server verifies the JWT signature against the client's registered key, guaranteeing
**integrity and authenticity** of the request parameters (non-repudiation, tamper-proofing).

## 2. JAR vs PAR — They Solve Overlapping but Distinct Problems

| Property | PAR (RFC 9126, **implemented**) | JAR (RFC 9101, **not implemented**) |
|---|---|---|
| Keeps params out of the browser/URL | ✅ (opaque `request_uri` handle) | ⚠️ Only when combined with PAR or `request_uri` by reference |
| Integrity/authenticity of params | ✅ via the authenticated backchannel POST (`private_key_jwt`) | ✅ via the request-object JWT signature |
| Confidentiality on the wire | ✅ TLS backchannel | ✅ TLS (JWE optional for payload confidentiality) |
| Requires client-side JWT signing of the request | ❌ | ✅ |
| FAPI 2.0 alignment | Required | **PAR + JAR together** is the FAPI 2.0 "signed request" profile |

**Key insight:** the current PAR flow already delivers the two properties most people want from JAR
(params never appear in the browser, and the request is authenticated) because the client pushes the
parameters over an authenticated (`private_key_jwt`) TLS backchannel. JAR adds a **separately verifiable,
non-repudiable signature over the request parameters themselves**, which is primarily valuable for FAPI
2.0 / high-assurance (open banking, health) profiles and for audit non-repudiation.

## 3. Why It Is Documented Rather Than Implemented

**Spring Authorization Server (the version used here, Spring Security 7 / Boot 4) does not provide
native RFC 9101 request-object parsing or verification.** Its `request_uri` handling is the **PAR**
handle (an opaque server-issued reference), not a JAR remote request object. Implementing JAR would
therefore require **custom, cross-cutting work on both server and clients**:

1. **Server:** a custom converter/filter on `/oauth2/par` (and/or `/oauth2/authorize`) that detects a
   `request` parameter, resolves the client's registered public key, verifies the JWS (with strict
   algorithm pinning — RS256/ES256), rejects `alg: none`, validates `iss`/`aud`/`exp`, and then unpacks
   the claims into the standard authorization request before handing off to the existing
   `ClientPreDeterminedScopeAuthorizationRequestConverter`.
2. **Client (Ruby `oauth2_client_kit`):** a new signing path in `push_authorization_request` to build and
   RS256-sign the request object, plus configuration for which clients use it.
3. **Client Manager (Next.js):** a per-client toggle and validation surface.
4. **Tests:** new server verification unit tests, negative tests (forged signature, `alg:none`,
   expired/aud-mismatch), client-kit specs, and e2e coverage.

This is a meaningful feature with real signature-verification security surface, not a configuration flag.
Given the current PAR flow already provides parameter confidentiality and authenticated integrity, the
incremental benefit (non-repudiation / strict FAPI 2.0) did not justify the implementation risk at this
time. It is recorded here as a first-class future option.

## 4. Recommended Implementation Shape (If Adopted)

The lowest-risk, highest-value form is **PAR + JAR** (FAPI 2.0 style), reusing the existing PAR plumbing:

- The client keeps pushing to `/oauth2/par`, but the pushed body carries a single signed `request` JWT
  instead of (or in addition to) individual parameters.
- The server verifies the request object **at the PAR endpoint**, then stores the resolved parameters
  against the issued `request_uri` exactly as today. The `/oauth2/authorize` step is unchanged.
- This keeps JAR verification in one place, preserves the opaque `request_uri` browser handoff, and
  avoids a second (unauthenticated, by-value `request` on `/authorize`) code path.

Supported variants would then be exactly two, both backchannel and both authenticated:

1. **PAR (plain)** — current behaviour; parameters pushed over `private_key_jwt` backchannel.
2. **PAR + JAR (signed request object)** — parameters wrapped in a client-signed, server-verified JWT.

The legacy direct `/oauth2/authorize` query-parameter flow is already rejected for PAR-enforced clients
by [`ClientPreDeterminedScopeAuthorizationRequestConverter`](../../spring-auth-server/src/main/java/com/example/authserver/security/ClientPreDeterminedScopeAuthorizationRequestConverter.java);
adopting JAR would be an opportunity to make PAR mandatory platform-wide, leaving only these two variants.

## 5. Pros & Cons Summary

**Pros of adopting JAR (as PAR + JAR):**
- Non-repudiable, independently verifiable signature over request parameters.
- FAPI 2.0 "signed request" conformance for high-assurance sectors.
- Defence against a compromised/misconfigured TLS-terminating proxy tampering with pushed params.
- Natural place to later add **JWE**-encrypted request objects for parameter confidentiality at rest.

**Cons / costs:**
- No native Spring support → custom verification code (security-sensitive; must pin algorithms and
  reject `alg:none`).
- Client-side signing complexity across the Ruby kit and any future clients.
- Additional key-management surface (request-object signing keys, potentially distinct from assertion keys).
- Marginal benefit over the existing authenticated PAR backchannel for non-FAPI use cases.

## 6. References

- [RFC 9101 — JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
- [RFC 9126 — Pushed Authorization Requests (PAR)](https://www.rfc-editor.org/rfc/rfc9126.html) (implemented — see [PAR + DPoP flow](oauth2_par_dpop_flow.md))
- FAPI 2.0 Security Profile (PAR + JAR "signed request" requirements)
