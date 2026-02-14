package goAuth

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTOTPVerifyRFCVectorsSHA1(t *testing.T) {
	m := newTOTPManager(TOTPConfig{
		Issuer:    "goAuth",
		Digits:    8,
		Period:    30,
		Algorithm: "SHA1",
		Skew:      0,
	})
	secret := []byte("12345678901234567890")
	cases := []struct {
		ts   int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range cases {
		ok, _, err := m.VerifyCode(secret, tc.code, time.Unix(tc.ts, 0))
		if err != nil || !ok {
			t.Fatalf("SHA1 vector failed at t=%d, ok=%v err=%v", tc.ts, ok, err)
		}
	}
}

func TestTOTPVerifyRFCVectorsSHA256(t *testing.T) {
	m := newTOTPManager(TOTPConfig{
		Issuer:    "goAuth",
		Digits:    8,
		Period:    30,
		Algorithm: "SHA256",
		Skew:      0,
	})
	secret := []byte("12345678901234567890123456789012")
	cases := []struct {
		ts   int64
		code string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	for _, tc := range cases {
		ok, _, err := m.VerifyCode(secret, tc.code, time.Unix(tc.ts, 0))
		if err != nil || !ok {
			t.Fatalf("SHA256 vector failed at t=%d, ok=%v err=%v", tc.ts, ok, err)
		}
	}
}

func TestTOTPVerifyRFCVectorsSHA512(t *testing.T) {
	m := newTOTPManager(TOTPConfig{
		Issuer:    "goAuth",
		Digits:    8,
		Period:    30,
		Algorithm: "SHA512",
		Skew:      0,
	})
	secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	cases := []struct {
		ts   int64
		code string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}

	for _, tc := range cases {
		ok, _, err := m.VerifyCode(secret, tc.code, time.Unix(tc.ts, 0))
		if err != nil || !ok {
			t.Fatalf("SHA512 vector failed at t=%d, ok=%v err=%v", tc.ts, ok, err)
		}
	}
}

func TestTOTPDriftWindowAcceptsAdjacentStep(t *testing.T) {
	m := newTOTPManager(TOTPConfig{
		Issuer:    "goAuth",
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Skew:      1,
	})
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	prevCounter := (now.Unix() / 30) - 1
	code, err := hotpCode(secret, prevCounter, 6, "SHA1")
	if err != nil {
		t.Fatalf("hotpCode failed: %v", err)
	}

	ok, _, err := m.VerifyCode(secret, code, now)
	if err != nil || !ok {
		t.Fatalf("expected skew code accepted, ok=%v err=%v", ok, err)
	}
}

func TestTOTPWrongDigitsRejected(t *testing.T) {
	m := newTOTPManager(TOTPConfig{
		Issuer:    "goAuth",
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Skew:      1,
	})
	secret := []byte("12345678901234567890")
	ok, _, err := m.VerifyCode(secret, "12345678", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected wrong-length code to be rejected")
	}
}

func TestVerifyTOTPRejectsDisabledRecord(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	up.totpRecords["u1"] = TOTPRecord{
		Secret:   []byte("12345678901234567890"),
		Enabled:  false,
		Verified: false,
	}

	err := engine.VerifyTOTP(context.Background(), "u1", "123456")
	if !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("expected ErrTOTPNotConfigured, got %v", err)
	}
}

func TestVerifyTOTPReplayRejected(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.EnforceReplayProtection = true
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	setup, err := engine.GenerateTOTPSetup(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateTOTPSetup failed: %v", err)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(setup.SecretBase32))
	if err != nil {
		t.Fatalf("decode secret failed: %v", err)
	}

	up.totpRecords["u1"] = TOTPRecord{
		Secret:          decoded,
		Enabled:         true,
		Verified:        true,
		LastUsedCounter: -1,
	}

	code := codeForNow(t, setup.SecretBase32, cfg.TOTP)
	if err := engine.VerifyTOTP(context.Background(), "u1", code); err != nil {
		t.Fatalf("first VerifyTOTP failed: %v", err)
	}
	if err := engine.VerifyTOTP(context.Background(), "u1", code); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("expected replay to fail with ErrTOTPInvalid, got %v", err)
	}
}
