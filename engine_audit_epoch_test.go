package goAuth

import (
	"context"
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

// A long challenge lifetime is allowed: the epoch is kept longer than the
// longest challenge, so Build has nothing to reject.
func TestBuildAcceptsALongMFAChallengeTTL(t *testing.T) {
	for _, ttl := range []time.Duration{3 * time.Minute, 13 * time.Hour, 30 * time.Hour} {
		cfg := mfaLoginConfig()
		cfg.TOTP.MFALoginChallengeTTL = ttl
		_, rdb := newTestRedis(t)
		if _, err := New().
			WithConfig(cfg).
			WithRedis(rdb).
			WithPermissions([]string{"perm.read"}).
			WithRoles(map[string][]string{"member": {}}).
			WithUserProvider(newHardeningUserProvider(t)).
			Build(); err != nil {
			t.Fatalf("Build with a %v challenge TTL: %v", ttl, err)
		}
	}
}

// FAILED-BEFORE (PR 5 review fold-in): Build refused a challenge TTL above 12
// hours, which is a breaking change in a patch release. The epoch now lives
// longer than the longest challenge instead.
func TestMFAConfirmIsFencedPastTheDefaultEpochLifeWithALongChallengeTTL(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.TOTP.MFALoginChallengeTTL = 30 * time.Hour
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	mr.FastForward(32 * time.Hour) // the epoch bumped by the enrolment ages out

	challenge := mfaChallenge(t, engine) // pins epoch 0
	if err := engine.LogoutAll(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	// Past the default 24 h life of the epoch key, inside the challenge's 30 h.
	mr.FastForward(25 * time.Hour)
	if _, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP)); err == nil {
		t.Fatal("the confirmation stored a session after a revocation whose epoch key would have expired under the default life")
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("user holds %d sessions, want 0", n)
	}
}
