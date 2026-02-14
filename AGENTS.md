# goAuth – Agent Architecture Guide

## Purpose

goAuth is a high-performance authentication guard written in Go.
It is designed for:

- ≤ 30–40ms API latency budgets
- 100K–1M active sessions
- Zero database access in hot path
- Hybrid stateless/stateful validation
- Dynamic RBAC with bitmask permissions
- Security-first defaults

This document defines architectural invariants.
Agents MUST follow these rules strictly.

---

# 1️⃣ Core System Goals

Primary Goals:

- High performance
- Built-in security defaults
- No DB access in hot path
- Minimal Redis overhead
- 128-bit session IDs
- Bitmask permission model
- Opaque rotating refresh tokens

Non-Goals (V1):

- OAuth providers
- Policy engines
- Multi-region orchestration

---

# 2️⃣ Architecture Overview

Components:

PostgreSQL:
- Credentials
- Role mapping
- PermissionVersion

Redis:
- Session store
- Refresh hash
- Rate limits
- Version control

JWT:
- Short-lived access token only

Refresh Token:
- Opaque
- Rotating
- Replay-detectable

---

# 3️⃣ Validation Modes

ValidationMode enum:

ModeJWTOnly
ModeHybrid (default)
ModeStrict

Rules:

JWTOnly:
- No Redis in hot path
- Mask embedded in JWT
- PermVersion embedded

Hybrid:
- Redis used for strict routes
- Lightweight routes skip Redis

Strict:
- Redis GET on every request

---

# 4️⃣ Permission System

Global registry.
Bit positions fixed at startup.
Max 512 permissions.

Mask types:
- Mask64
- Mask128
- Mask256
- Mask512

No slices in hot path.
No dynamic resizing.

Root bit optional (highest bit reserved).

---

# 5️⃣ Session Model (Redis)

Key:
as:{tid}:{sid}

Binary encoded session.

Contains:

- UserID (string)
- TenantID (string optional)
- Mask (bitmask)
- PermissionVersion
- RoleVersion (future)
- RefreshHash (32 bytes)
- CreatedAt
- ExpiresAt

Session size target:
~80–120 bytes

---

# 6️⃣ Refresh Token Model

Format:
base64url( SID[16] || SECRET[32] )

Server stores:
SHA256(secret)

Rotation mandatory.

On reuse detection:
Delete session immediately.

No JWT refresh tokens allowed.

---

# 7️⃣ Security Defaults

Default:
- Ed25519 signing
- Hybrid mode
- Rotation enforced
- Sliding expiration enabled
- Rate limiting enabled
- Fail closed for strict routes

Agents MUST NOT weaken these defaults.

---

# 8️⃣ Performance Constraints

- No DB in hot path
- Redis GET optional
- Bitmask check O(1)
- No reflection in hot path
- No interface dispatch in hot path
- No slices for permission masks

---

# 9️⃣ Hard Limits

- Max permissions: 512
- Max mask size: 512 bits
- Max session size enforced
- Panic at startup if exceeded

---

# 🔟 Code Standards

- No global state
- All freeze logic executed at Build()
- No mutation after Build()
- All cryptographic comparisons constant-time
- All tokens URL-safe base64
- All random values crypto-secure

---

# 1️⃣1️⃣ Future Extensions (V2)

- OAuth providers
- Dynamic role DB support
- RoleVersion enforcement
- Advanced anomaly detection

---

# Enforcement Rule

If a change:

- Adds DB to hot path
- Adds reflection
- Adds dynamic resizing in permission mask
- Adds unsafe type conversions
- Removes refresh rotation

It must be rejected.

Performance and security invariants override convenience.

