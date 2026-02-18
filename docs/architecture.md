# goAuth Architecture

## Overview

goAuth is a low-latency authentication guard that combines short-lived JWT access tokens with Redis-backed session state and rotating opaque refresh tokens. The hot path avoids database IO and uses fixed-size permission bitmasks.

## Components

- **Engine/Builder (root package):** initialization, validation, login, refresh, logout, account controls, audit, metrics.
- **session package:** Redis session persistence using compact binary encoding.
- **permission package:** fixed-width permission masks, registry freeze semantics, role-to-mask compilation.
- **jwt package:** access-token minting and verification.
- **password package:** Argon2id hashing and verification.
- **middleware package:** HTTP request guards for JWT-only/hybrid/strict checks.
- **refresh package:** refresh-token parsing and rotation helpers.
- **metrics exporters:** Prometheus and OpenTelemetry adapters.

## Package interaction flow

1. `Builder.Build()` freezes config and registries.
2. `Builder.Build()` wires a single `internal/flows.Service` from one `flows.Deps` graph.
3. `Engine.Login*` verifies credentials via `UserProvider`, then writes session state.
4. `Engine.Validate*` verifies JWT and optionally Redis session state depending on validation mode.
5. `Engine.Refresh` rotates refresh secret and issues fresh tokens.
6. Middleware wraps application handlers and enforces route-level authorization.

## Design principles

- Fail closed on malformed/expired/authentication-invalid inputs.
- No DB access in request hot path.
- Fixed-size bitmasks (up to 512 bits) for O(1) permission checks.
- Immutable-after-build configuration model.
- Centralized flow dependency wiring (`flows.New(deps)`) with root method delegation.

## Trade-offs

- Redis is required for strict/session-hardening behaviors.
- Opaque refresh tokens increase server-side state management complexity.
- Multi-region consistency and OAuth provider integrations are intentionally out of scope in v1.
