package internal

import "crypto/sha256"

// HashBindingValue describes the hashbindingvalue operation and its observable behavior.
//
// HashBindingValue may return an error when input validation, dependency calls, or security checks fail.
// HashBindingValue does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func HashBindingValue(v string) [32]byte {
	return sha256.Sum256([]byte(v))
}
