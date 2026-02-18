// Package rate provides internal primitives used to build Redis-backed rate limit keys,
// errors, and limiter behavior for security-sensitive authentication workflows.
//
// # Window semantics
//
// Fixed-window counters: INCR + conditional EXPIRE on first hit. Key prefixes:
//   - al:  — login per-user
//   - ali: — login per-IP
//   - ar:  — refresh per-session
//
// # What this package must NOT do
//
//   - Implement domain-specific policies (those live in internal/limiters).
//   - Be imported outside the goAuth module.
package rate
