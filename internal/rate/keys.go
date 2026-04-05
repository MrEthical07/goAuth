package rate

import (
	"crypto/sha256"
	"encoding/hex"
)

func safeID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func loginUserKey(tenantID, identifier string) string {
	return "rl:login:fail:" + safeID(tenantID) + ":" + safeID(identifier)
}
