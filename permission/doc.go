// Package permission provides fixed-size bitmask types, a permission registry, and role
// composition helpers used by goAuth authorization checks.
//
// # Mask sizes
//
// Supported widths: 64, 128, 256, and 512 bits. A mask is selected at registry
// construction time and is immutable thereafter. Bit positions are assigned by
// [Registry.Register] and are stable for the lifetime of the process.
//
// # Architecture boundaries
//
// This package is a pure in-memory data structure with no I/O. It provides the
// codec (Encode/Decode) used by the session binary encoder.
//
// # What this package must NOT do
//
//   - Access Redis, databases, or the network.
//   - Import goAuth, jwt, or session.
//   - Dynamically resize masks after registry construction.
package permission
