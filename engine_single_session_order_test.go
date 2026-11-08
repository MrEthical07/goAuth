package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
)

// R2-28 residual: in single-session mode the fenced save ended the user's other
// sessions before it checked the tenant cap, so a confirmation refused for the
// cap had already signed the owner out. The refusal must leave them alone.
//
// The password step only passes while the tenant has room, so the tenant is
// filled after it, between the challenge and its confirmation.
func TestSingleSessionConfirmRefusedForTheTenantCapKeepsTheExistingSession(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	cfg.SessionHardening.MaxSessionsPerTenant = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	first, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), codeForNow(t, secret, cfg.TOTP))
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	firstSID, _, err := internal.DecodeRefreshToken(first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	pending := mfaChallenge(t, engine) // the tenant holds 1 session, the cap is 2

	// Two other users' sessions arrive meanwhile: the tenant is full even once
	// this user's own session is replaced.
	template, err := engine.sessionStore.GetReadOnly(ctx, "0", firstSID)
	if err != nil {
		t.Fatalf("read the session: %v", err)
	}
	for _, id := range []string{"other-1", "other-2"} {
		other := *template
		other.SessionID, other.UserID = id, "someone-"+id
		if err := engine.sessionStore.Save(ctx, &other, time.Hour); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	_, err = engine.ConfirmLoginMFA(ctx, pending, codeForNow(t, secret, cfg.TOTP))
	if !errors.Is(err, ErrTenantSessionLimitExceeded) {
		t.Fatalf("confirm with the tenant full: %v, want ErrTenantSessionLimitExceeded", err)
	}
	if _, err := engine.Validate(ctx, first.AccessToken, ModeStrict); err != nil {
		t.Fatalf("a confirmation refused for the tenant cap ended the owner's session: %v", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("user holds %d sessions, want the 1 that was there", n)
	}
}
