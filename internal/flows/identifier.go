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

// auditIdentifier bounds an unauthenticated identifier before it is copied into
// an audit event, so a queued event never holds more than MaxIdentifierBytes of
// caller input however large the request was.
func auditIdentifier(identifier string) string {
	if len(identifier) <= MaxIdentifierBytes {
		return identifier
	}
	return strings.ToValidUTF8(identifier[:MaxIdentifierBytes], "")
}
