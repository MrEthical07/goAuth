package internal

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/google/uuid"
)

// The text shapes of the identifiers the challenge generators produce. They
// are the one place that says what a well-formed challenge ID looks like, so
// every entry point that takes one from a caller can refuse a malformed value
// before it reaches Redis, a limiter key or an audit event.
//
// A caller-supplied ID that does not have the shape of what the generator
// emits cannot name a live record, so refusing it changes no outcome except
// the cost: it is the answer the record lookup would have given, without the
// work and without copying the value anywhere.

// MaxTenantIDBytes is the longest tenant ID a challenge may carry. It is the
// limit the verification generator enforces on the tenant it embeds.
const MaxTenantIDBytes = 256

const (
	// uuidTextLen is the length of a hyphenated UUID, the form uuid.New().String()
	// produces and the UUID strategies use as the whole secret.
	uuidTextLen = 36
	// signupHandleBytes is the entropy of an external sign-up handle.
	signupHandleBytes = 32
)

// ValidSessionIDText reports whether id is what [SessionID.String] produces: 22
// base64url characters, canonically encoded. It is the record ID of the token
// and OTP strategies.
func ValidSessionIDText(id string) bool {
	if len(id) != base64.RawURLEncoding.EncodedLen(len(SessionID{})) {
		return false
	}
	sid, err := ParseSessionID(id)
	return err == nil && sid.String() == id
}

// ValidUUIDText reports whether id is what uuid.New().String() produces: a
// lower-case, hyphenated UUID. It is the record ID of the UUID strategies.
func ValidUUIDText(id string) bool {
	if len(id) != uuidTextLen {
		return false
	}
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}

// ValidUUIDCode reports whether code is a hyphenated UUID in any letter case,
// the form a UUID-strategy code is accepted in (the code is normalized to lower
// case before it is hashed).
func ValidUUIDCode(code string) bool {
	if len(code) != uuidTextLen {
		return false
	}
	_, err := uuid.Parse(code)
	return err == nil
}

// ValidResetTokenText reports whether token has the shape [EncodeResetToken]
// produces: 64 base64url characters carrying a 16-byte ID and a 32-byte
// secret. Every 64-character base64url string decodes to such a pair, so the
// length and alphabet are the whole rule.
func ValidResetTokenText(token string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(resetTokenRawSize) {
		return false
	}
	_, _, err := DecodeResetToken(token)
	return err == nil
}

// ValidSignupHandleText reports whether handle is what an external sign-up
// ticket carries: 32 random bytes as 43 canonical base64url characters.
func ValidSignupHandleText(handle string) bool {
	if len(handle) != base64.RawURLEncoding.EncodedLen(signupHandleBytes) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(handle)
	return err == nil && len(raw) == signupHandleBytes && base64.RawURLEncoding.EncodeToString(raw) == handle
}

// NewSignupHandle generates an external sign-up handle: 32 random bytes,
// base64url without padding.
func NewSignupHandle() (string, error) {
	var raw [signupHandleBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
