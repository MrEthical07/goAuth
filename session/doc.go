// Package session provides Redis-backed session persistence and compact binary session
// encoding for authentication hot paths.
//
// # Binary encoding
//
// Sessions are stored in Redis as a compact binary format (schema versions v1–v5) with
// forward migration on read. The encoder is append-only: new versions add fields but
// never reinterpret old ones.
//
// # Architecture boundaries
//
// This package owns the [Store] (Redis operations) and the [Session] model. It does NOT
// interpret JWT tokens, evaluate permissions, or enforce authentication policy — those
// responsibilities belong to the Engine.
//
// # What this package must NOT do
//
//   - Import goAuth, jwt, or permission (no upward imports).
//   - Perform application-level authorization decisions.
//   - Store plaintext secrets in [Session] fields.
package session
