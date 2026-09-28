package session

import (
	"encoding/hex"
	"testing"

	"github.com/MrEthical07/goAuth/permission"
)

// TestEncodeGoldenBytesStableAcrossGoVersions proves that the current Go
// toolchain's encoding/binary output for a v5 session record is byte-for-byte
// identical to what v0.5.1 (built with Go 1.26.5, the toolchain pinned in its
// go.mod) produced for the same fields. A rolling deploy that spans a Go
// version upgrade must not invalidate live sessions.
//
// The golden hex was captured by running Encode with these exact field
// values against the v0.5.1 tag under Go 1.26.5. Session encoding uses only
// encoding/binary (fixed-width big-endian integers and length-prefixed
// strings), which the Go 1.27 release notes do not touch — this test proves
// that empirically rather than by assumption.
func TestEncodeGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const wantHex = "050b757365722d676f6c64656e0d74656e616e742d676f6c64656e066d656d62657200000007000000030000000901080102030405060708aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc000000006553f100000000006553ff10"

	mask := permission.Mask64(0x0102030405060708)
	sess := &Session{
		SessionID:         "sid-golden",
		UserID:            "user-golden",
		TenantID:          "tenant-golden",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 7,
		RoleVersion:       3,
		AccountVersion:    9,
		Status:            1,
		RefreshHash:       fixedBytes32(0xAA),
		IPHash:            fixedBytes32(0xBB),
		UserAgentHash:     fixedBytes32(0xCC),
		CreatedAt:         1700000000,
		ExpiresAt:         1700003600,
	}

	got, err := Encode(sess)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	gotHex := hex.EncodeToString(got)
	if gotHex != wantHex {
		t.Fatalf("session wire bytes changed across Go versions:\n got:  %s\n want: %s", gotHex, wantHex)
	}

	decoded, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode of the golden-matching bytes failed: %v", err)
	}
	if decoded.UserID != sess.UserID || decoded.TenantID != sess.TenantID {
		t.Fatalf("decode mismatch: got %+v", decoded)
	}
}

func fixedBytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}
