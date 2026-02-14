Below is a **structured task log roadmap** based on everything we’ve architected so far. This is ordered strategically — not randomly.

This assumes:

* Task-06 (Argon2 + password verification) is in progress.
* Core session engine is stable.
* Drift control + rate limiting + TTL model are complete.

---

# 📘 AUTH ENGINE ROADMAP — TASK LOG

---

## 🔥 Task-07 — Session Invalidation & Logout API

We will implement first-class session invalidation primitives. This includes single-session logout and logout-all-sessions per user. Redis secondary index `au:{uid}` (set of session IDs) will be introduced to allow O(n) invalidation without DB lookup. Session deletion must be atomic and safe. LogoutAll must delete both session keys and secondary index. This task enables password change, account disable, reset flows, and admin revocation to behave correctly. Strict mode must fail closed if Redis unavailable. JWT-only mode cannot support instant logout by design. No performance impact to validation hot path.

---

## 🔥 Task-08 — Password Change Flow

Implement secure password change primitive inside engine. Flow: verify old password using Argon2 → hash new password → update DB → invalidate all sessions → reset lockout counters. Must support upgrade-on-change automatically. Must reject weak password if strength validation enabled. Must not log raw password. Must use constant-time compare. Must not affect validation hot path. Must integrate rate limiting to prevent brute-force password change abuse.

---

## 🔥 Task-09 — Account Disable & Lockout Enforcement

Introduce persistent account status enforcement. UserRecord must include Disabled flag and optional LockUntil timestamp. Engine login must reject disabled accounts before password verification (to reduce attack surface). Lockout must integrate with existing rate limiter but support persistent lock duration beyond Redis TTL if desired. Account disable must invalidate all sessions immediately. Validation path may optionally check account status version if strict mode enabled. No DB calls allowed in hot validation path.

---

## 🔥 Task-10 — Reset Token System (Forgot Password Primitive)

Implement secure reset token system as engine primitive. Reset token must be cryptographically random (256-bit). Only hashed token stored (SHA-256). TTL enforced in Redis. Single-use enforced via atomic delete. Reuse detection invalidates session optionally. Engine exposes GenerateResetToken(userID) and ResetPassword(token, newPassword). Application layer handles email/SMS. No raw token stored server-side. Replay-safe. No DB lookup required except final password update.

---

## 🔥 Task-11 — Email Verification Token Primitive

Implement verification token similar to reset token but logically separate namespace. Token must be random, hashed in Redis, TTL controlled. Engine exposes GenerateVerificationToken(userID) and VerifyEmailToken(token). Engine does not send email. Application handles flow. Must support invalidation and replay prevention. Must not interfere with reset tokens.

---

## 🔥 Task-12 — Account Creation Primitive

Provide engine-level CreateUser helper that hashes password and initializes metadata (Role, PermissionVersion, RoleVersion). Engine does not enforce verification policy. DB uniqueness enforcement delegated to UserProvider. Optional password strength validation integrated here. Must not allow weak hash configuration. Must not auto-login unless explicitly configured.

---

## 🔥 Task-13 — Advanced Session Security Hardening

Enhance device/IP binding enforcement in validation. Optional enforcement of user-agent binding. Implement optional account versioning to invalidate all sessions on global security event. Add optional session LRU in-memory cache to reduce Redis GET load. Maintain deterministic behavior across validation modes.

---

## 🔥 Task-14 — Admin Revocation & Role Management API

Provide primitives for: change user role, bump RoleVersion, bump PermissionVersion, invalidate user sessions. No DB logic inside engine; only version enforcement. Ensure version bump invalidates sessions deterministically. Ensure JWT-only mode behaves predictably (TTL-based enforcement).

---

## 🔥 Task-15 — Multi-Tenant Hardening

Fully enforce tenant isolation at engine level. Ensure Redis keys always include tenant prefix when enabled. Ensure userProvider requires tenantID in lookup when MultiTenant enabled. Prevent cross-tenant session validation. Add optional tenant versioning for mass invalidation.

---

## 🔥 Task-16 — Security Audit & Failure Semantics Review

Full audit pass on:

* Redis outage handling
* Strict vs hybrid mode correctness
* Rate limit edge cases
* Session TTL behavior
* Drift invalidation timing
* Token reuse detection
* Memory allocation in hot path
* Constant-time comparisons
* Panic safety

Goal: production-grade stability.

---

# 🧠 Strategic Order Summary

You should implement in this order:

1. Finish Task-06 (Argon2)
2. Task-07 (Logout & Invalidation)
3. Task-08 (Password Change)
4. Task-09 (Disable & Lockout)
5. Task-10 (Reset Tokens)
6. Task-11 (Verification Tokens)
7. Task-12 (CreateUser helper)
8. Hardening + multi-tenant improvements

Anything else before session invalidation is premature.


Implement Authenticator App.