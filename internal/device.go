package internal

import "crypto/sha256"

func HashBindingValue(v string) [32]byte {
	return sha256.Sum256([]byte(v))
}
