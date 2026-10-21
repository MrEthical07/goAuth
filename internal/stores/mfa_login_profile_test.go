package stores

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// goldenMFAv2 is the record from TestMFALoginChallengeGoldenBytesStableAcrossGoVersions.
// The v3 fixture is derived from it by hand: the version byte becomes 03 and
// the profile "mobile" follows the flags byte, prefixed with its one-byte
// length (06, then 6d6f62696c65).
const (
	goldenMFAv2 = "020004000000006553ff10000b757365722d676f6c64656e000d74656e616e742d676f6c64656e01"
	goldenMFAv3 = "030004000000006553ff10000b757365722d676f6c64656e000d74656e616e742d676f6c64656e01" + "066d6f62696c65"
)

func goldenMFARecord() *MFALoginChallenge {
	return &MFALoginChallenge{
		UserID:     "user-golden",
		TenantID:   "tenant-golden",
		ExpiresAt:  1700003600,
		Attempts:   4,
		RememberMe: true,
	}
}

func TestMFALoginChallengeV3GoldenBytes(t *testing.T) {
	record := goldenMFARecord()
	record.Profile = "mobile"
	got, err := encodeMFALoginChallenge(record)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != goldenMFAv3 {
		t.Fatalf("v3 challenge bytes changed:\n got:  %s\n want: %s", gotHex, goldenMFAv3)
	}
	decoded, err := decodeMFALoginChallenge(got)
	if err != nil || *decoded != *record {
		t.Fatalf("round trip = %+v, %v", decoded, err)
	}
}

// Without a profile the record is still v2, byte for byte.
func TestMFALoginChallengeWithoutProfileStaysV2(t *testing.T) {
	got, err := encodeMFALoginChallenge(goldenMFARecord())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != goldenMFAv2 {
		t.Fatalf("v2 challenge bytes changed:\n got:  %s\n want: %s", gotHex, goldenMFAv2)
	}
}

func TestMFALoginChallengeProfileValidation(t *testing.T) {
	v3, _ := hex.DecodeString(goldenMFAv3)
	tail := len(v3) - 7 // offset of the profile length byte

	if _, err := encodeMFALoginChallenge(&MFALoginChallenge{UserID: "u", Profile: strings.Repeat("a", 33)}); err == nil {
		t.Fatal("a 33-character profile name was accepted")
	}
	for name, raw := range map[string][]byte{
		"empty profile":     append(append([]byte(nil), v3[:tail]...), 0),
		"oversized profile": append(append([]byte(nil), v3[:tail]...), append([]byte{33}, bytes.Repeat([]byte{'a'}, 33)...)...),
		"truncated profile": v3[:len(v3)-2],
		"missing profile":   v3[:tail],
	} {
		if _, err := decodeMFALoginChallenge(raw); err == nil {
			t.Errorf("%s: decode succeeded", name)
		}
	}
	if _, err := decodeMFALoginChallenge(append([]byte{4}, v3[1:]...)); err == nil {
		t.Error("an unknown version decoded")
	}
}

// The decoder accepts v2 and v3, and a record's profile survives the failure
// re-write path (decode, bump attempts, encode).
func TestMFALoginChallengeDecodesAllVersions(t *testing.T) {
	for name, tc := range map[string]struct {
		hex     string
		profile string
	}{"v2": {goldenMFAv2, ""}, "v3": {goldenMFAv3, "mobile"}} {
		raw, _ := hex.DecodeString(tc.hex)
		record, err := decodeMFALoginChallenge(raw)
		if err != nil || record.Profile != tc.profile || !record.RememberMe || record.UserID != "user-golden" {
			t.Fatalf("%s: %+v, %v", name, record, err)
		}
		record.Attempts++
		again, err := encodeMFALoginChallenge(record)
		if err != nil {
			t.Fatalf("%s re-encode: %v", name, err)
		}
		back, _ := decodeMFALoginChallenge(again)
		if back.Profile != tc.profile || back.Attempts != 5 {
			t.Fatalf("%s did not survive the failure re-write: %+v", name, back)
		}
		if (tc.profile == "") != (again[0] == mfaLoginRecordVersion2) {
			t.Fatalf("%s re-encoded as version %d", name, again[0])
		}
	}
}
