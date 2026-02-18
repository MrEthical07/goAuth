// Package stores provides Redis-backed, short-lived record stores for
// security-sensitive authentication flows: password reset, email verification,
// and MFA login challenges.
//
// # Design
//
// Each store persists a versioned, binary-encoded record in Redis with a TTL.
// Mutation operations (Consume, RecordFailure) use WATCH/MULTI optimistic
// transactions with automatic retry on contention. Records are single-use:
// consumed or deleted on success, and enforce attempt limits to resist
// brute-force attacks. Secret comparisons use constant-time compare.
//
// # Architecture boundaries
//
// This package owns persistence and concurrency control for transient
// challenge records. It does NOT generate tokens/OTPs, enforce rate limits,
// or make authentication decisions — those responsibilities belong to the
// flow functions in internal/flows.
//
// # What this package must NOT do
//
//   - Import goAuth or any sibling internal package.
//   - Log or expose plaintext secrets.
//   - Use non-constant-time comparisons for secret matching.
package stores
