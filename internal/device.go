package internal

import "crypto/sha256"

// HashBindingValue returns the SHA-256 hash of a device binding value
// (IP address or User-Agent string).
func HashBindingValue(v string) [32]byte {
	return sha256.Sum256([]byte(v))
}
