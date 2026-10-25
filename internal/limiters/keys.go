package limiters

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashPart renders a caller-influenced key segment as fixed-length hex, so a
// limiter key never grows with the input it counts: an identifier or an ID
// sent by an anonymous caller would otherwise be stored verbatim in Redis for
// the whole limiter window.
func hashPart(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
