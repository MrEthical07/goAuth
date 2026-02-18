// Package refresh implements parsing and validation utilities for opaque rotating refresh
// tokens.
//
// # Token format
//
// Opaque base64url-encoded tokens containing session ID, generation counter, and
// cryptographic nonce. Tokens are never stored in plaintext — the session store
// retains only the token hash.
//
// # Architecture boundaries
//
// This package owns token encoding/decoding and structural validation. Rotation
// policy, reuse detection, and session invalidation on replay are handled by the
// Engine and session store.
//
// # What this package must NOT do
//
//   - Access Redis or any I/O.
//   - Import goAuth, jwt, or session.
//   - Implement rotation or replay logic.
package refresh
