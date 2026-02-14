# goAuth v1 Architecture Invariants

These invariants are non-negotiable for v1 security posture.

If any invariant is violated, treat it as a security regression.

## A. Validation and Hot-Path Invariants

1. `Validate()` must not call database/provider APIs.
2. JWT-only validation path must not access Redis.
3. Strict validation path must require Redis session read.
4. Strict validation must fail closed on Redis unavailability.
5. Hybrid non-strict path may proceed without Redis (bounded by access token TTL).
6. No reflection or dynamic policy evaluation in hot validation path.
7. Permission check remains O(1) mask-based.

## B. Token and Session Invariants

1. Access token is JWT only; refresh token is opaque only.
2. Refresh token format is fixed: `base64url(SID[16] || SECRET[32])`.
3. Refresh secrets are never persisted in plaintext; only SHA-256 hash is stored.
4. Refresh mismatch (reuse detection) must invalidate session immediately.
5. Session IDs are cryptographically random 128-bit values.
6. Session TTL must never extend beyond absolute session lifetime cap.
7. Session state is tenant-scoped in Redis keys.

## C. Cryptographic and Comparison Invariants

1. Password hashing uses Argon2id PHC format.
2. Secret comparisons performed by engine must use constant-time comparison.
3. TOTP verification must follow RFC 6238 counter/HMAC flow.
4. Backup code persistence stores only user-bound salted hash (`sha256(userID || 0x00 || code)`).
5. Backup code verification must map invalid and replay outcomes to indistinguishable invalid result at API level.
6. Cryptographically random values must come from `crypto/rand`.

## D. MFA/Recovery Invariants

1. MFA login is step-up challenge based; no partial session before MFA success.
2. MFA challenge must be one-time consumable.
3. MFA challenge expiry is absolute and checked against stored `expiresAt`.
4. Backup codes are one-time and must be atomically consumed by provider contract.
5. Backup code regeneration replaces full set; old set must not remain valid.

## E. Account Lifecycle Invariants

1. Account status transitions must advance `AccountVersion`.
2. Status-changing operations must invalidate all sessions for that user.
3. Strict path must enforce account status/account version from session.
4. JWT-only mode revocation remains bounded by access token TTL.

## F. Configuration and Build Invariants

1. Engine must not start with invalid/contradictory config.
2. ProductionMode must reject insecure cryptographic parameters.
3. JWT-only mode must reject strict-dependent checks that are ineffective by design.
4. Strict mode requires Redis availability at build/startup.
5. Config passed to builder must be copied; post-build external mutation must not alter engine behavior.

## G. Audit and Metrics Invariants

1. Audit events must never include raw passwords, raw OTPs, raw backup codes, or refresh secrets.
2. Audit error fields must use sanitized stable codes, not raw internal errors.
3. Audit drop behavior must be explicit and observable (`Dropped()` counter).
4. Metrics updates must be lock-free atomic operations.
5. Export adapters must read snapshots only and must not mutate engine state.

## H. Boundary Invariants

1. Engine remains transport-agnostic (no built-in HTTP server startup).
2. Engine remains provider-agnostic for persistence.
3. No DB dependency may be introduced into hot auth validation path.

## Freeze Statement

goAuth v1 Security Architecture Freeze.

Any change that weakens these invariants requires explicit security review and a major version decision.
