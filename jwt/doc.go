// Package jwt manages access-token issuance and verification using configured signing keys
// and strict validation semantics suitable for low-latency authentication paths.
//
// # Supported algorithms
//
// Ed25519 (default, recommended) and HS256. Algorithm selection is immutable after
// construction via [NewManager].
//
// # Architecture boundaries
//
// This package owns token encoding/decoding and claim construction. It does NOT manage
// sessions, refresh tokens, or permission evaluation. The parent Engine is responsible
// for coordinating JWT issuance with session creation.
//
// # What this package must NOT do
//
//   - Access Redis or any network resource.
//   - Import the parent goAuth package (to avoid import cycles).
//   - Cache tokens — callers control caching policy.
//   - Embed sensitive data (passwords, MFA secrets) in claims.
package jwt
