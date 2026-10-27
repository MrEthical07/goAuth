package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/stores"
)

// A MFA confirmation used to accept any factor the user had enrolled when it
// ran, whether or not the challenge had offered it: a factor enrolled after the
// password step (or one the policy did not advertise) answered a challenge that
// never asked for it. The password step now stores the factors it advertised
// next to the challenge, and the confirmation refuses others.

// plantChallenge stores a challenge for u1 that advertises the given factors
// (0 = a challenge from an earlier version, with nothing recorded).
func plantChallenge(t *testing.T, engine *Engine, id string, advertised uint8) {
	t.Helper()
	ctx := context.Background()
	ttl := 3 * time.Minute
	rec := &stores.MFALoginChallenge{UserID: "u1", TenantID: "0", ExpiresAt: time.Now().Add(ttl).Unix()}
	if err := engine.mfaLoginStore.Save(ctx, id, rec, ttl); err != nil {
		t.Fatal(err)
	}
	if advertised != 0 {
		epoch, err := engine.sessionStore.RevocationEpoch(ctx, "0", "u1")
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.mfaLoginStore.SaveContext(ctx, id, epoch, advertised, ttl); err != nil {
			t.Fatal(err)
		}
	}
}

// FAILED-BEFORE: the TOTP the user enrolled answered a challenge that had
// advertised only WebAuthn.
func TestConfirmRefusesAFactorTheChallengeDidNotAdvertise(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	for _, mfaType := range []string{"totp", "backup", ""} {
		plantChallenge(t, engine, "webauthn-only-"+mfaType, internalflows.AdvertisesWebAuthn)
		_, err := engine.ConfirmLoginMFAWithType(ctx, "webauthn-only-"+mfaType, codeForNow(t, secret, cfg.TOTP), mfaType)
		if !errors.Is(err, ErrMFALoginInvalid) {
			t.Fatalf("type %q on a webauthn-only challenge: %v, want ErrMFALoginInvalid", mfaType, err)
		}
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("a factor that was not advertised produced %d session(s)", n)
	}
}

func TestConfirmAcceptsTheAdvertisedFactorAndLegacyChallenges(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	// A challenge the password step created advertises TOTP, and TOTP works.
	res, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), codeForNow(t, secret, cfg.TOTP))
	if err != nil || res.AccessToken == "" {
		t.Fatalf("the advertised factor: %v", err)
	}
	// A challenge without a recorded set (created by an earlier version) still
	// accepts what the user has enrolled.
	plantChallenge(t, engine, "legacy", 0)
	if _, err := engine.ConfirmLoginMFA(ctx, "legacy", codeForNow(t, secret, cfg.TOTP)); err != nil {
		t.Fatalf("a challenge with nothing recorded: %v", err)
	}
	// TOTP advertised: its backup-code fallback is within it.
	codes := mustBackupCodes(t, engine, "u1", secret, cfg)
	plantChallenge(t, engine, "totp-adv", internalflows.AdvertisesTOTP)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, "totp-adv", codes[0], "backup"); err != nil {
		t.Fatalf("a backup code on a challenge that advertised TOTP: %v", err)
	}
}

func mustBackupCodes(t *testing.T, engine *Engine, userID, secret string, cfg Config) []string {
	t.Helper()
	codes, err := engine.RegenerateBackupCodes(context.Background(), userID, codeForOffset(t, secret, cfg.TOTP, 1))
	if err != nil {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	return codes
}
