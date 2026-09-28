package stores

import (
	"encoding/hex"
	"testing"
)

// These tests prove that the current Go toolchain's encoding/binary output
// for every binary-encoded Redis record goAuth writes is byte-for-byte
// identical to what v0.5.1 (built with Go 1.26.5, its pinned toolchain)
// produced for the same fields. A rolling deploy across a Go version
// upgrade must not invalidate live password-reset links, email-verification
// links, MFA login challenges, or WebAuthn ceremony sessions.
//
// Each golden hex was captured by running the package's encode function with
// these exact field values against the v0.5.1 tag under Go 1.26.5. None of
// these encoders use encoding/json; all use fixed-width big-endian integers
// and length-prefixed strings via encoding/binary, which the Go 1.27 release
// notes do not touch. These tests prove that empirically.

func fixedHashBytes(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestPasswordResetRecordGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const wantHex = "01010002000000006553ff10000b757365722d676f6c64656e1111111111111111111111111111111111111111111111111111111111111111"

	record := &PasswordResetRecord{
		UserID:     "user-golden",
		SecretHash: fixedHashBytes(0x11),
		ExpiresAt:  1700003600,
		Attempts:   2,
		Strategy:   1,
	}
	got, err := encodePasswordResetRecord(record)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("password-reset record wire bytes changed across Go versions:\n got:  %s\n want: %s", gotHex, wantHex)
	}

	decoded, err := decodePasswordResetRecord(got)
	if err != nil {
		t.Fatalf("decode of the golden-matching bytes failed: %v", err)
	}
	if decoded.UserID != record.UserID || decoded.Attempts != record.Attempts {
		t.Fatalf("decode mismatch: got %+v", decoded)
	}
}

func TestEmailVerificationRecordGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const wantHex = "01020001000000006553ff10000b757365722d676f6c64656e2222222222222222222222222222222222222222222222222222222222222222"

	record := &EmailVerificationRecord{
		UserID:     "user-golden",
		SecretHash: fixedHashBytes(0x22),
		ExpiresAt:  1700003600,
		Attempts:   1,
		Strategy:   2,
	}
	got, err := encodeEmailVerificationRecord(record)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("email-verification record wire bytes changed across Go versions:\n got:  %s\n want: %s", gotHex, wantHex)
	}

	decoded, err := decodeEmailVerificationRecord(got)
	if err != nil {
		t.Fatalf("decode of the golden-matching bytes failed: %v", err)
	}
	if decoded.UserID != record.UserID || decoded.Attempts != record.Attempts {
		t.Fatalf("decode mismatch: got %+v", decoded)
	}
}

func TestMFALoginChallengeGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const wantHex = "020004000000006553ff10000b757365722d676f6c64656e000d74656e616e742d676f6c64656e01"

	record := &MFALoginChallenge{
		UserID:     "user-golden",
		TenantID:   "tenant-golden",
		ExpiresAt:  1700003600,
		Attempts:   4,
		RememberMe: true,
	}
	got, err := encodeMFALoginChallenge(record)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("MFA login challenge wire bytes changed across Go versions:\n got:  %s\n want: %s", gotHex, wantHex)
	}

	decoded, err := decodeMFALoginChallenge(got)
	if err != nil {
		t.Fatalf("decode of the golden-matching bytes failed: %v", err)
	}
	if decoded.UserID != record.UserID || decoded.RememberMe != record.RememberMe {
		t.Fatalf("decode mismatch: got %+v", decoded)
	}
}

func TestWebAuthnSessionGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const wantHex = "0102000b757365722d676f6c64656e000d74656e616e742d676f6c64656e0000002f7b226368616c6c656e6765223a22616263222c22757365725f6964223a2264584e6c6369316e6232786b5a5734227d"

	record := &WebAuthnSession{
		UserID:      "user-golden",
		TenantID:    "tenant-golden",
		Purpose:     2,
		SessionJSON: []byte(`{"challenge":"abc","user_id":"dXNlci1nb2xkZW4"}`),
	}
	got, err := encodeWebAuthnSession(record)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("WebAuthn ceremony session wire bytes changed across Go versions:\n got:  %s\n want: %s", gotHex, wantHex)
	}

	decoded, err := decodeWebAuthnSession(got)
	if err != nil {
		t.Fatalf("decode of the golden-matching bytes failed: %v", err)
	}
	if decoded.UserID != record.UserID || string(decoded.SessionJSON) != string(record.SessionJSON) {
		t.Fatalf("decode mismatch: got %+v", decoded)
	}
}
