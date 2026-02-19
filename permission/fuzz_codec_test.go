package permission

import (
	"testing"
)

// FuzzMaskCodecRoundTrip exercises the mask encode/decode path with arbitrary bytes.
// Goal: no panics; valid-length inputs should roundtrip.
func FuzzMaskCodecRoundTrip(f *testing.F) {
	// Seed with valid mask sizes (8, 16, 32, 64 bytes).
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	// Invalid sizes.
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 9))
	f.Add(make([]byte, 65))

	f.Fuzz(func(t *testing.T, data []byte) {
		// DecodeMask must not panic.
		mask, err := DecodeMask(data)
		if err != nil {
			return
		}

		// Re-encode must not panic.
		encoded, err := EncodeMask(mask)
		if err != nil {
			t.Fatalf("EncodeMask failed after successful DecodeMask: %v", err)
		}

		// Roundtrip: re-decode must produce identical bytes.
		reDecoded, err := DecodeMask(encoded)
		if err != nil {
			t.Fatalf("DecodeMask roundtrip failed: %v", err)
		}

		reEncoded, err := EncodeMask(reDecoded)
		if err != nil {
			t.Fatalf("EncodeMask roundtrip failed: %v", err)
		}

		if len(encoded) != len(reEncoded) {
			t.Fatalf("roundtrip length mismatch: %d vs %d", len(encoded), len(reEncoded))
		}
		for i := range encoded {
			if encoded[i] != reEncoded[i] {
				t.Fatalf("roundtrip byte mismatch at %d: %02x vs %02x", i, encoded[i], reEncoded[i])
			}
		}
	})
}
