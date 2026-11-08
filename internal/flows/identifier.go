package flows

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MaxIdentifierBytes is the longest identifier (login name, email address) the
// unauthenticated entry points accept. It is the length of the longest valid
// email address, 254 bytes of address plus slack for display forms, rounded
// to 320. A longer identifier is refused before any lookup, limiter or audit
// event can copy it, with the answer an unusable input always gets.
const MaxIdentifierBytes = 320

// identifierTooLong reports whether an identifier exceeds MaxIdentifierBytes.
func identifierTooLong(identifier string) bool {
	return len(identifier) > MaxIdentifierBytes
}

// auditIdentifier bounds caller-supplied text before it is copied into an audit
// event, so a queued event never holds more than MaxIdentifierBytes of caller
// input however large the request was.
//
// A value over the cap is cut and the cut is copied: a slice of the original
// keeps the caller's whole backing array alive for as long as the event waits
// in the audit queue, which is the memory the cap is meant to bound. A value
// within the cap is returned as it came, with no copy.
func auditIdentifier(identifier string) string {
	if len(identifier) <= MaxIdentifierBytes {
		return identifier
	}
	return strings.Clone(strings.ToValidUTF8(identifier[:MaxIdentifierBytes], ""))
}

// AuditIdentifier is [auditIdentifier] for the packages that build audit
// metadata outside this one.
func AuditIdentifier(value string) string {
	return auditIdentifier(value)
}

// challengeIDMeta is the audit metadata for the ID of a challenge record, under
// field ("reset_id", "verification_id").
//
// With a token or OTP strategy the ID names the record and the secret is a
// separate value, so the ID is recorded as it is (bounded like any caller
// text). With a UUID strategy the ID is the whole secret: whoever reads the
// audit stream could redeem it while the record is live. Then the event
// carries a fingerprint under field+"_fp" instead, the first 12 hex characters
// of SHA-256 over the tenant, a zero byte and the ID: enough to match two
// events about the same record, useless for redeeming it.
func challengeIDMeta(field string, secretID bool, tenantID, id string) map[string]string {
	if !secretID {
		return map[string]string{field: auditIdentifier(id)}
	}
	return map[string]string{field + "_fp": ChallengeFingerprint(tenantID, id)}
}

// ChallengeFingerprint returns the short, non-reversible audit fingerprint of a
// challenge ID: the first 12 hex characters of SHA-256(tenantID, 0x00, id).
func ChallengeFingerprint(tenantID, id string) string {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))[:12]
}
