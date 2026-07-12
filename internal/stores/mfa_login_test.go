package stores

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMFALoginChallengeEncodeDecodeRoundTrip(t *testing.T) {
	for _, rememberMe := range []bool{false, true} {
		record := &MFALoginChallenge{
			UserID:     "user-1",
			TenantID:   "tenant-1",
			ExpiresAt:  1234567890,
			Attempts:   3,
			RememberMe: rememberMe,
		}

		encoded, err := encodeMFALoginChallenge(record)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		if encoded[0] != mfaLoginRecordVersion2 {
			t.Fatalf("expected version 2 record, got %d", encoded[0])
		}

		decoded, err := decodeMFALoginChallenge(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if *decoded != *record {
			t.Fatalf("round trip mismatch: got %+v, want %+v", decoded, record)
		}
	}
}

func TestMFALoginChallengeDecodesVersion1Records(t *testing.T) {
	// Hand-build a v1 record (pre-remember-me layout, no trailing flags byte)
	// as written by older binaries still present in Redis during a rollout.
	var buf bytes.Buffer
	buf.WriteByte(mfaLoginRecordVersion1)
	_ = binary.Write(&buf, binary.BigEndian, uint16(2))          // Attempts
	_ = binary.Write(&buf, binary.BigEndian, int64(1234567890))  // ExpiresAt
	_ = binary.Write(&buf, binary.BigEndian, uint16(len("u-1"))) // UserID
	buf.WriteString("u-1")
	_ = binary.Write(&buf, binary.BigEndian, uint16(len("t-1"))) // TenantID
	buf.WriteString("t-1")

	decoded, err := decodeMFALoginChallenge(buf.Bytes())
	if err != nil {
		t.Fatalf("decode v1 failed: %v", err)
	}
	if decoded.UserID != "u-1" || decoded.TenantID != "t-1" || decoded.Attempts != 2 || decoded.ExpiresAt != 1234567890 {
		t.Fatalf("v1 fields mismatch: %+v", decoded)
	}
	if decoded.RememberMe {
		t.Fatal("v1 records must decode as remember-me = false")
	}
}

func TestMFALoginChallengeRejectsUnknownVersion(t *testing.T) {
	if _, err := decodeMFALoginChallenge([]byte{9, 0, 0}); err == nil {
		t.Fatal("expected error for unknown record version")
	}
}
