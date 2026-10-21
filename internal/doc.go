// Package internal contains helper utilities that are intentionally private to goAuth,
// including secure random generation and device fingerprint helpers.
//
// # Sub-packages
//
//   - audit — async event dispatch (Dispatcher + Sink implementations)
//   - flows — pure-function flow orchestrators for every Engine operation
//   - limiters — domain-specific rate limiters (account, backup-code, email, TOTP, reset)
//   - metrics — lock-free counters and latency histograms
//   - oidc — OpenID Connect ID-token verification and provider key cache
//   - rate — core Redis-backed rate limit primitives
//   - security — scanner baseline and perf regression tooling
//   - stores — shared store interface adapters
//
// # What this package must NOT do
//
//   - Export types that appear in the public goAuth API.
//   - Be imported by any package outside the goAuth module.
package internal
