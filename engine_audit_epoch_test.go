package goAuth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FAILED-BEFORE (R2-08 follow-up): the epoch key lived one hour after the last
// bump, so an MFA challenge that outlived it was confirmed against an epoch that
// had read as 0 again.
func TestMFAConfirmAfterAnHourIsStillFencedByTheRevocation(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.TOTP.MFALoginChallengeTTL = 3 * time.Hour
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	// Enrolling the factor revoked once; let that epoch age out so the
	// challenge pins 0.
	mr.FastForward(25 * time.Hour)

	challenge := mfaChallenge(t, engine)
	if err := engine.LogoutAll(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	// Past the old one-hour life of the key, well within the new one.
	mr.FastForward(90 * time.Minute)
	if _, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP)); err == nil {
		t.Fatal("the confirmation stored a session after a revocation whose epoch key had expired")
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("user holds %d sessions, want 0", n)
	}
}

func TestBuildBoundsTheMFAChallengeTTLByTheEpochWindow(t *testing.T) {
	build := func(ttl time.Duration) error {
		cfg := mfaLoginConfig()
		cfg.TOTP.MFALoginChallengeTTL = ttl
		_, rdb := newTestRedis(t)
		_, err := New().
			WithConfig(cfg).
			WithRedis(rdb).
			WithPermissions([]string{"perm.read"}).
			WithRoles(map[string][]string{"member": {}}).
			WithUserProvider(newHardeningUserProvider(t)).
			Build()
		return err
	}
	if err := build(13 * time.Hour); err == nil || !strings.Contains(err.Error(), "MFALoginChallengeTTL") {
		t.Fatalf("Build with a 13h challenge TTL: %v, want a MFALoginChallengeTTL error", err)
	}
	if err := build(12 * time.Hour); err != nil {
		t.Fatalf("Build with a 12h challenge TTL: %v", err)
	}
}
