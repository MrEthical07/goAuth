// Package goAuth provides a low-latency authentication engine with JWT access tokens,
// rotating opaque refresh tokens, Redis-backed session controls, and bitmask-based RBAC.
//
// The package is designed for concurrent server workloads: Engine methods are safe to call
// from multiple goroutines after initialization through [Builder.Build].
//
// # Architecture boundaries
//
// goAuth is the public surface. It exposes [Engine], [Builder], [Config], and value types
// (MetricsSnapshot, SessionInfo, etc.). All internal coordination — flow orchestration,
// session encoding, rate limiting, audit dispatch — lives under internal/ and is never
// exported.
//
// # What this package must NOT do
//
//   - Expose Redis clients, internal stores, or encoding details in its public API.
//   - Perform I/O outside of Engine methods (construction via Builder is allocation-only
//     until Build).
//   - Import any sub-package that re-imports goAuth (no import cycles).
//
// # Performance contract
//
// Validate is the hot path. It must not allocate beyond the returned Claims struct and
// must complete without Redis round-trips in ModeJWTOnly. Refresh, Login, and account
// operations are allowed one Redis round-trip per call.
package goAuth
