# goAuth v1 Security Posture

This document defines the security posture for goAuth v1 as implemented in this repository.

This is an engineering document, not marketing material. Claims here are bounded by the code and by explicit assumptions.

## Scope

goAuth provides authentication and authorization primitives:

- Access token issuance and validation (JWT)
- Opaque refresh token rotation and reuse detection
- Redis-backed session state and revocation
- Dynamic RBAC via versioned masks
- Account lifecycle controls (status, password change/reset)
- MFA primitives (TOTP, backup codes, MFA step-up challenge)
- Rate limiting, audit emission, and internal metrics

## Security Posture Summary

- Hot-path validation has no database dependency.
- Strict mode is fail-closed on Redis failures.
- JWT-only mode is intentionally availability-biased and bounded by short access token TTL.
- Refresh tokens are opaque and rotated every use; mismatch triggers session invalidation.
- Sensitive comparisons are constant-time where the engine performs comparisons.
- Provider-managed security objects (password hashes, TOTP secret storage, backup code consume semantics) are required to satisfy contract assumptions.
- ProductionMode configuration validation rejects unsafe cryptographic or contradictory settings at startup.

## Failure Semantics Matrix

| Failure | Behavior | Fail Open/Closed |
| --- | --- | --- |
| Redis down during `Validate` strict path | Reject request (`ErrUnauthorized`) | Closed |
| Redis down during `Validate` JWT-only path | Redis not used; continue with JWT checks | Bounded open |
| Redis down during hybrid non-strict route | Redis not used; continue with JWT checks | Bounded open |
| Redis down during hybrid strict route override | Reject request | Closed |
| Provider unavailable during login | Reject login | Closed |
| Provider unavailable during validate | Not applicable (provider not used) | N/A |
| MFA challenge store unavailable | Reject MFA confirm | Closed |
| Reset/email verification store unavailable | Reject operation | Closed |
| Audit dispatcher queue full with `DropIfFull=true` | Drop audit event, increment dropped counter | Configurable |
| Audit dispatcher queue full with `DropIfFull=false` | Backpressure/block until queued or context cancel | Configurable |
| Metrics disabled | No-op in metrics layer | Safe |

## Known Security Limitations

1. JWT-only mode cannot provide immediate revocation; bounded by access token TTL.
2. Access tokens are bearer tokens; theft enables replay until expiry or strict-path invalidation.
3. Device binding trust depends on application-supplied client IP and User-Agent context values.
4. Redis compromise can enable session manipulation (deletion/counter tampering), even though refresh secrets are hashed at rest.
5. Provider compromise can bypass account status/version and MFA object integrity.
6. Backup code one-time semantics depend on provider atomic consume implementation.
7. Audit is best-effort by configuration; drop mode can lose events under pressure.
8. Metrics are operational telemetry, not tamper-proof forensic evidence.

## Cryptographic Assumptions

- JWT signing: Ed25519 or HS256.
- Argon2id password hashing in PHC format.
- TOTP per RFC 6238 (SHA1/SHA256/SHA512), with replay protection option.
- Refresh token format: `base64url(SID[16] || SECRET[32])`.
- Session ID entropy: 128 bits (`crypto/rand` 16-byte value).
- Refresh secret entropy: 256 bits (`crypto/rand` 32-byte value).
- TOTP secret entropy: 160 bits (`crypto/rand` 20-byte value).
- Backup code entropy: `log2(32^N)` bits for code length `N` (default N=10 => ~50 bits per code), plus per-user hash salting.

## Security Review Inputs

The detailed threat model is documented in `THREAT_MODEL.md`.

The non-negotiable implementation invariants are documented in `ARCHITECTURE_INVARIANTS.md`.

Operational verification gates are documented in `SECURITY_REVIEW_CHECKLIST.md`.

## Freeze Statement

goAuth v1 Security Architecture Freeze.

Any future change that violates a listed invariant or materially changes threat posture is a security regression and must be treated as a breaking security change.

Major version increment is required for intentional breaking security model changes.
