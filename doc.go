// Package goAuth provides a low-latency authentication engine with JWT access tokens,
// rotating opaque refresh tokens, Redis-backed session controls, and bitmask-based RBAC.
//
// The package is designed for concurrent server workloads: Engine methods are safe to call
// from multiple goroutines after initialization through Builder.Build.
//
// Performance-sensitive validation paths avoid database access and minimize allocations by
// using fixed-width permission masks and short-lived JWT claims.
package goAuth
