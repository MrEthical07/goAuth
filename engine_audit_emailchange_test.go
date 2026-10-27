package goAuth

import (
	"strings"
	"testing"
)

// FAILED-BEFORE (R2-03): with EmailChange.Strategy = VerificationUUID the Code
// mailed to the new address was byte-identical to the id part of the
// VerificationID, which docs/email_change.md says the host may hand to the
// browser. The strategy is rejected at Build, and no allowed strategy lets the
// Code be derived from the VerificationID.
func TestEmailChangeRejectsTheUUIDStrategyAtBuild(t *testing.T) {
	cfg := Config{EmailChange: EmailChangeConfig{Enabled: true, Strategy: VerificationUUID}}
	err := cfg.validateEmailChange()
	if err == nil {
		t.Fatal("VerificationUUID was accepted for email change")
	}
	for _, want := range []string{"VerificationUUID", "VerificationToken", "VerificationOTP"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error should name %s: %v", want, err)
		}
	}

	// With the feature off the strategy is not read.
	cfg.EmailChange.Enabled = false
	if err := cfg.validateEmailChange(); err != nil {
		t.Fatalf("a disabled feature must not be validated: %v", err)
	}
	for _, ok := range []VerificationStrategyType{VerificationToken, VerificationOTP} {
		cfg := Config{EmailChange: EmailChangeConfig{Enabled: true, Strategy: ok, OTPDigits: 6, MaxAttempts: 3}}
		if err := cfg.validateEmailChange(); err != nil {
			t.Fatalf("strategy %v: %v", ok, err)
		}
	}
}

func TestEmailChangeCodeIsNotDerivableFromTheVerificationID(t *testing.T) {
	for name, strategy := range map[string]VerificationStrategyType{"token": VerificationToken, "otp": VerificationOTP} {
		t.Run(name, func(t *testing.T) {
			env := newECEnv(t, func(c *EmailChangeConfig) { c.Strategy = strategy })
			req := env.mustRequest(ecNewEmail)

			// VerificationID is "<tenant>:<id>".
			_, id, ok := strings.Cut(req.VerificationID, ":")
			if !ok || id == "" {
				t.Fatalf("unexpected VerificationID %q", req.VerificationID)
			}
			if req.Code == id || strings.Contains(req.VerificationID, req.Code) || strings.Contains(req.Code, id) {
				t.Fatalf("Code %q can be read from VerificationID %q", req.Code, req.VerificationID)
			}
			// Another request for the same address gets an unrelated Code and ID.
			again := env.mustRequest(ecNewEmail + ".uk")
			if again.Code == req.Code || again.VerificationID == req.VerificationID {
				t.Fatal("two requests share a Code or a VerificationID")
			}
		})
	}
}
