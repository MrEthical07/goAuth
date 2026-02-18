// Package password implements password hashing and verification with Argon2id defaults.
//
// # Output format
//
// Hashes are encoded in PHC string format:
//
//	$argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
//
// The [Hasher] supports transparent parameter upgrades: if the stored hash was
// produced with weaker parameters, [Hasher.NeedsRehash] returns true so the caller
// can re-hash on the next successful login.
//
// # Architecture boundaries
//
// This package owns hashing and verification only. Password policy (length, reuse
// history) is enforced by the Engine.
//
// # What this package must NOT do
//
//   - Store or retrieve passwords — callers supply plaintext and receive hashes.
//   - Import any other goAuth package.
//   - Log plaintext passwords or hash parameters at runtime.
package password
