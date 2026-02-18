package session

import (
	"testing"

	"github.com/MrEthical07/goAuth/permission"
)

// FuzzSessionDecode exercises the binary session decoder with arbitrary inputs.
// Goal: no panics, no unexpected nil dereferences, graceful error handling.
func FuzzSessionDecode(f *testing.F) {
	// Seed with a valid v5 encoded session.
	mask := permission.Mask64(0xFF)
	sess := &Session{
		SessionID:         "sid-fuzz",
		UserID:            "user1",
		TenantID:          "tenant1",
		Role:              "admin",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		CreatedAt:         1700000000,
		ExpiresAt:         1700003600,
	}
	encoded, err := Encode(sess)
	if err == nil {
		f.Add(encoded)
	}

	// Empty and short inputs.
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{5})
	f.Add([]byte{255, 255, 255})

	// Truncated at various offsets.
	if len(encoded) > 10 {
		f.Add(encoded[:10])
	}
	if len(encoded) > 30 {
		f.Add(encoded[:30])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are expected for malformed input.
		s, err := Decode(data)
		if err != nil {
			return
		}

		// If decode succeeded, re-encode should not panic either.
		if s.SchemaVersion == CurrentSchemaVersion {
			_, _ = Encode(s)
		}
	})
}
