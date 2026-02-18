// Package middleware exposes HTTP middleware adapters for JWT-only, hybrid, and strict
// authorization enforcement modes built on top of goAuth.Engine validation.
//
// # Guards
//
//   - [Guard] — auto-selects enforcement mode from Engine config.
//   - [RequireJWTOnly] — stateless JWT verification, no Redis call.
//   - [RequireStrict] — JWT + session store verification.
//
// Each guard reads the Authorization header, calls Engine.Validate, and injects
// validated claims into the request context.
//
// # Architecture boundaries
//
// This package translates HTTP semantics into Engine calls. It does NOT implement
// authentication logic itself — all decisions are delegated to Engine.Validate.
//
// # What this package must NOT do
//
//   - Parse or create JWTs directly (delegates to Engine).
//   - Access Redis (Engine handles I/O).
//   - Make authorization decisions beyond pass/reject from Engine.Validate.
package middleware
