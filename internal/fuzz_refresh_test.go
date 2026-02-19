package internal

import (
	"testing"
)

// FuzzDecodeRefreshToken exercises refresh token decoding with arbitrary strings.
// Goal: no panics; invalid inputs should return errors cleanly.
func FuzzDecodeRefreshToken(f *testing.F) {
	// Seed with valid-looking base64url strings of various lengths.
	f.Add("")
	f.Add("abc")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 64 chars base64

	// Generate a valid token to use as seed.
	sid, err := NewSessionID()
	if err == nil {
		secret, err := NewRefreshSecret()
		if err == nil {
			token, err := EncodeRefreshToken(sid.String(), secret)
			if err == nil {
				f.Add(token)
			}
		}
	}

	// Malformed base64.
	f.Add("!!!not-base64!!!")
	f.Add("aGVsbG8=")
	f.Add("dG9vLXNob3J0")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Errors are fine for invalid inputs.
		sessionID, secret, err := DecodeRefreshToken(input)
		if err != nil {
			return
		}

		// If decode succeeded, re-encode should produce a valid token.
		reEncoded, err := EncodeRefreshToken(sessionID, secret)
		if err != nil {
			// Could fail if sessionID doesn't parse back as a valid base64 session ID.
			return
		}

		// Roundtrip decode to verify consistency.
		sid2, secret2, err := DecodeRefreshToken(reEncoded)
		if err != nil {
			t.Fatalf("roundtrip decode failed: %v", err)
		}
		if sid2 != sessionID {
			t.Errorf("roundtrip session ID mismatch: %q vs %q", sid2, sessionID)
		}
		if secret2 != secret {
			t.Error("roundtrip secret mismatch")
		}
	})
}
