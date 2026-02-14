# goAuth v1 Threat Model

This threat model captures goAuth v1 scope, assumptions, mitigations, and residual risk.

## 1. System Boundary

### Engine controls

- JWT access token creation and verification.
- Refresh token decoding, hash comparison, rotation, and reuse handling.
- Redis session lifecycle (create/read/rotate/delete), revocation, and version checks.
- Validation mode behavior (JWT-only/hybrid/strict) and strict fail-closed behavior.
- MFA step-up challenge lifecycle in Redis.
- Reset and email verification challenge lifecycle in Redis.
- Rate limiting invocation and enforcement for engine-managed flows.
- Audit event emission and metrics increments.

### Engine does not control

- Transport security (TLS termination, mTLS, reverse proxy trust).
- HTTP routing and middleware placement correctness.
- Database schema, isolation, and query correctness.
- Secret management and key rotation infrastructure.
- Host hardening, network ACLs, and runtime/container isolation.

### Delegated to `UserProvider`

- User lookup and persistence.
- Password hash storage and updates.
- Account status persistence and version advancement.
- TOTP secret storage/enable/disable and last-used counter persistence.
- Backup code persistence and atomic consume semantics.
- Tenant uniqueness policy enforcement.

### Delegated to application layer

- Supplying trusted context values (`tenantID`, client IP, user-agent).
- Mapping route strictness and mode overrides.
- Sending email/SMS/push for reset and verification challenges.
- Operational response to audit drops and security alerts.

### Delegated to infrastructure

- Redis durability/availability/security.
- Database availability/integrity.
- NTP/time synchronization.
- Logging sink durability and access controls.

## 2. Assets to Protect

- Password hashes: credential verifier for primary factor.
- TOTP secrets: MFA seed material; compromise bypasses MFA.
- Backup code hashes: fallback MFA factor; compromise impacts account recovery.
- Refresh token secret component: long-lived session continuation credential.
- Access tokens: bearer authorization artifact.
- Session state in Redis: active auth state, versions, status, binding data.
- Account status and account version: immediate auth eligibility control.
- Audit stream integrity: forensic and detection data.
- Metrics integrity: operational security signal quality.
- Tenant isolation boundary: prevents cross-tenant data/action bleed.

## 3. Adversary Classes

### A. External attacker (no credentials)

- Credential stuffing and brute-force attempts.
- Identifier enumeration attempts.
- Refresh/reset/email challenge replay attempts.
- OTP and backup code brute force.
- Access/refresh token theft replay.

### B. Authenticated malicious user

- Cross-tenant access attempts.
- Session fixation/replay attempts.
- MFA bypass attempts via stale challenge or fallback misuse.
- Race attempts during account disable/lock transitions.
- Device spoofing attempts.

### C. Infrastructure adversary

- Redis inspection/manipulation.
- Session key scraping.
- Audit/log scraping.
- Token replay from stolen artifacts.

### D. Misconfigured operator

- Unsafe production config (weak Argon2, long TTLs, weak HS256 key).
- Contradictory mode combinations (JWT-only with strict-dependent checks).
- Missing Redis for strict/session-cap features.
- Enabling required controls while feature disabled.

## 4. Attack Class Analysis

| Attack class | Mitigated | How/Layer | Complete/Bounded | Assumptions |
| --- | --- | --- | --- | --- |
| 1. Password brute force | Partially | Login rate limiting in Redis (`al:*`, optional `ali:*`) | Bounded | Redis available; application still enforces strong password policy on account creation |
| 2. Password hash theft | Partially | Argon2id PHC with configurable cost | Bounded | Provider protects DB and hash storage; no weak production config |
| 3. Access token replay | Partially | Short TTL; strict paths require valid Redis session | Bounded | Token can be replayed until expiry on JWT-only paths |
| 4. Refresh token replay | Yes | Opaque refresh with server-side hash check and rotation | Strong | Redis/session integrity preserved |
| 5. Refresh reuse after rotation | Yes | Hash mismatch triggers immediate session delete | Strong | Store compare/delete path executes atomically |
| 6. Session fixation | Yes | Server-generated 128-bit session IDs on login only | Strong | Application does not accept externally supplied session IDs |
| 7. MFA code replay | Yes | TOTP last-used counter replay protection when enabled | Strong/Config-bound | Provider persists counter atomically |
| 8. MFA brute force | Partially | TOTP attempt limiter and MFA challenge attempt caps | Bounded | Redis available; app handles high-volume abuse globally |
| 9. Backup code replay | Yes | One-time consume; consumed code removed | Strong/Provider-bound | Provider `ConsumeBackupCode` is atomic |
| 10. Backup code brute force | Partially | Backup-code limiter (`abk:{tid}:{uid}`), cooldown and attempt cap | Bounded | Redis available; backup length/count adequately configured |
| 11. Email verification replay | Yes | Verification challenge consumed/deleted atomically in Redis | Strong | Redis store available and consistent |
| 12. Reset token replay | Yes | Reset challenge consumed/deleted atomically in Redis | Strong | Redis store available and consistent |
| 13. Account status race (disable during session) | Partially | Status change invalidates sessions; strict mode enforces immediately | Bounded | JWT-only mode remains bounded by access TTL |
| 14. Cross-tenant access | Partially | Tenant-scoped Redis keys and tenant checks in challenge flows | Bounded | App passes trusted tenant context consistently |
| 15. JWT signature forgery | Yes (for chosen algorithm assumptions) | Signature verification via configured signing method | Strong/Config-bound | Key secrecy; HS256 key strength; algorithm not downgraded |
| 16. Clock skew exploitation | Partially | Rejects far-future `iat` beyond configured max skew | Bounded | System clock reasonably synchronized |
| 17. Device-binding spoof | Partially | Hash compare of IP/UA in session vs context; enforce/detect modes | Bounded | Upstream IP/UA context trustworthy and normalized |
| 18. Redis partial failure | Partially | Strict routes fail closed; JWT-only/hybrid-nonstrict continue | Intentional bounded availability tradeoff | Mode configured intentionally |
| 19. Audit log suppression | Partially | Backpressure mode optional; drop counter exposed | Bounded | Operator monitors dropped count and sink health |
| 20. Metrics manipulation | Partially | Internal metrics are in-process and lock-free | Bounded | Metrics are not treated as tamper-proof security evidence |

## 5. Explicitly Not Mitigated

- Full client compromise (stolen active access token usable until expiry).
- Nation-state / hardware side-channel threat classes.
- Distributed botnets with rotating IP at internet scale.
- Compromised trusted infrastructure (DB/Redis/host) beyond bounded impact controls.
- Transport/header spoofing when application provides untrusted client context values.

## 6. Assumptions Required for Stated Guarantees

1. `UserProvider` enforces tenant isolation policy as configured by application.
2. `UserProvider` performs atomic backup code consume.
3. `UserProvider` advances `AccountVersion` on status transitions.
4. Redis and DB are access-controlled and network-protected.
5. Application provides trusted context values for tenant/IP/UA.
6. Signing keys are generated and stored securely outside the engine.

## 7. Security Model Intent

- Strict mode: security-first, fail-closed on Redis dependency.
- Hybrid mode: route-sensitive tradeoff between latency and immediacy.
- JWT-only mode: highest availability/perf, bounded revocation delay by access TTL.

These are intentional modes, not accidental degradations.
