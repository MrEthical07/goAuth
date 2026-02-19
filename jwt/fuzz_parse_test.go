package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// FuzzJWTParseAccess exercises the JWT parser with arbitrary token strings.
// Goal: no panics; invalid inputs must be rejected with errors.
func FuzzJWTParseAccess(f *testing.F) {
	// Set up a real manager for parsing.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	mgr, err := NewManager(Config{
		AccessTTL:     5 * time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		Issuer:        "fuzz-test",
		Leeway:        30 * time.Second,
		RequireIAT:    true,
		MaxFutureIAT:  10 * time.Minute,
		KeyID:         "k1",
		VerifyKeys:    map[string][]byte{"k1": pub},
	})
	if err != nil {
		f.Fatal(err)
	}

	// Generate a valid token as seed.
	validToken, err := mgr.CreateAccess("uid1", 1, "sid1", []byte{0xFF}, 1, 1, 1, true, true, true, true, false)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(validToken)
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("eyJhbGciOiJFZERTQSJ9.eyJ1aWQiOiJ0ZXN0In0.invalid")
	f.Add("eyJhbGciOiJub25lIn0.eyJ1aWQiOiJ0ZXN0In0.")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Errors are expected for malformed input.
		claims, err := mgr.ParseAccess(input)
		if err != nil {
			return
		}
		// If parsing succeeded, claims should not be nil.
		if claims == nil {
			t.Fatal("ParseAccess returned nil claims without error")
		}
	})
}
