package flows

import "strings"

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
