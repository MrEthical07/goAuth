package goAuth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// newBoundaryEnv is an email-change engine on a clock that never moves on its
// own, so a "same second" is exact and not a race against the wall clock.
func newBoundaryEnv(t *testing.T, opts ...rsOption) (*ecEnv, *manualClock) {
	t.Helper()
	clk := newManualClock(clockStart)
	env := newECEnv(t, nil, append([]rsOption{rsClock(clk)}, opts...)...)
	env.mr.SetTime(clockStart)
	return env, clk
}

func (env *ecEnv) setStatus(status AccountStatus) {
	env.t.Helper()
	u := env.user(rsUserID)
	u.Status = status
	env.setUser(u)
}

// A reset requested for the new address in the very second the change was
// committed is valid. Before, the time-based marker refused every record issued
// at or before the commit second, so the code was mailed and then refused.
func TestEmailChangeResetRequestedInTheSameSecondRedeems(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

	fresh, err := env.engine.RequestPasswordReset(env.ctx(), ecNewEmail)
	if err != nil {
		t.Fatalf("RequestPasswordReset(new address): %v", err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), fresh, "brand-new-password-9"); err != nil {
		t.Fatalf("a reset requested in the commit's own second must redeem: %v", err)
	}
}

// A reset requested before the change is refused after it, in the same second
// too: the decision is write order, not time.
func TestEmailChangeResetRequestedBeforeTheChangeIsRefused(t *testing.T) {
	env, clk := newBoundaryEnv(t)
	oldReset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

	err = env.engine.ConfirmPasswordReset(env.ctx(), oldReset, "brand-new-password-9")
	if !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a reset requested before the change = %v, want ErrPasswordResetInvalid", err)
	}

	// Later still, and across a second boundary, a new code works and an old
	// one stays dead.
	clk.Advance(5 * time.Second)
	fresh, err := env.engine.RequestPasswordReset(env.ctx(), ecNewEmail)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), fresh, "brand-new-password-9"); err != nil {
		t.Fatalf("fresh reset: %v", err)
	}
}

// The same two for email verification: a code requested for the new address in
// the commit's second redeems; one requested before the change is refused.
func TestEmailChangeVerificationBoundary(t *testing.T) {
	t.Run("requested before the change is refused", func(t *testing.T) {
		env, _ := newBoundaryEnv(t)
		env.setStatus(AccountPendingVerification)
		challenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatalf("RequestEmailVerification: %v", err)
		}
		parts := strings.SplitN(challenge, ":", 3)
		env.setStatus(AccountActive) // an administrator activated the account
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

		err = env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2])
		if !errors.Is(err, ErrEmailVerificationInvalid) {
			t.Fatalf("a verification code requested before the change = %v, want ErrEmailVerificationInvalid", err)
		}
	})

	t.Run("requested in the commit's second redeems", func(t *testing.T) {
		env, _ := newBoundaryEnv(t)
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		env.setStatus(AccountPendingVerification) // the new address is not proven yet
		challenge, err := env.engine.RequestEmailVerification(env.ctx(), ecNewEmail)
		if err != nil {
			t.Fatalf("RequestEmailVerification(new address): %v", err)
		}
		parts := strings.SplitN(challenge, ":", 3)
		if err := env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2]); err != nil {
			t.Fatalf("a verification code requested in the commit's second must redeem: %v", err)
		}
		if got := env.user(rsUserID).Status; got != AccountActive {
			t.Fatalf("status after verification = %v, want Active", got)
		}
	})
}

// Verification records now carry a pointer like reset records: only the newest
// request's code redeems.
func TestEmailVerificationNewestRequestWins(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	env.setStatus(AccountPendingVerification)
	first, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	p1, p2 := strings.SplitN(first, ":", 3), strings.SplitN(second, ":", 3)

	if err := env.engine.ConfirmEmailVerificationCode(env.ctx(), p1[1], p1[2]); !errors.Is(err, ErrEmailVerificationInvalid) {
		t.Fatalf("the older code = %v, want ErrEmailVerificationInvalid", err)
	}
	if err := env.engine.ConfirmEmailVerificationCode(env.ctx(), p2[1], p2[2]); err != nil {
		t.Fatalf("the newest code: %v", err)
	}
}

// The pointer is written with the record's own lifetime.
func TestEmailVerificationPointerKey(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	env.setStatus(AccountPendingVerification)
	if _, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier); err != nil {
		t.Fatal(err)
	}
	key := "aevg:" + env.tenant + ":" + rsUserID
	if !env.mr.Exists(key) {
		t.Fatalf("pointer %s was not written", key)
	}
	want := env.cfg.EmailVerification.VerificationTTL
	if got := env.mr.TTL(key); got <= 0 || got > want {
		t.Fatalf("pointer TTL = %v, want within (0, %v]", got, want)
	}
}

// The identifier-change marker stays as the fallback for a record whose owner
// has no pointer (issued by an instance older than v0.8.1): issued at or before
// the change it is refused, issued after it is accepted.
func TestEmailChangeMarkerIsTheFallbackForRecordsWithoutAPointer(t *testing.T) {
	env, clk := newBoundaryEnv(t)
	oldReset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Second)
	env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
	clk.Advance(2 * time.Second)
	newReset, err := env.engine.RequestPasswordReset(env.ctx(), ecNewEmail)
	if err != nil {
		t.Fatal(err)
	}

	env.mr.Del("aprg:" + env.tenant + ":" + rsUserID) // no pointer: an older instance's records
	if err := env.engine.ConfirmPasswordReset(env.ctx(), oldReset, "brand-new-password-9"); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("pointerless record issued before the change = %v, want ErrPasswordResetInvalid", err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), newReset, "brand-new-password-9"); err != nil {
		t.Fatalf("pointerless record issued after the change: %v", err)
	}
}

// supersedeResetCodes is the reusable piece: it kills what exists and leaves
// room for what is requested afterwards, in every tenant a revocation covers.
func TestSupersedeResetCodes(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	before, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.supersedeResetCodes(env.ctx(), env.tenant, rsUserID); err != nil {
		t.Fatalf("supersedeResetCodes: %v", err)
	}
	after, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), before, "brand-new-password-9"); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("code issued before = %v, want ErrPasswordResetInvalid", err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), after, "brand-new-password-9"); err != nil {
		t.Fatalf("code issued after: %v", err)
	}
}

func TestSupersedeResetCodesCoversTheRecordTenant(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	if err := env.engine.supersedeResetCodes(env.ctx(), "other-tenant", rsUserID); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{env.tenant, "other-tenant"} {
		if !env.mr.Exists("aprg:" + tenant + ":" + rsUserID) {
			t.Errorf("no tombstone written under tenant %q", tenant)
		}
	}
}

func TestSupersedeIsANoOpWhileTheFlowIsDisabled(t *testing.T) {
	env, _ := newBoundaryEnv(t, rsConfig(func(c *Config) {
		c.PasswordReset.Enabled = false
		c.EmailVerification.Enabled = false
	}))
	if err := env.engine.supersedeResetCodes(env.ctx(), env.tenant, rsUserID); err != nil {
		t.Fatal(err)
	}
	if err := env.engine.supersedeVerificationCodes(env.ctx(), env.tenant, rsUserID); err != nil {
		t.Fatal(err)
	}
	if got := append(env.keys("aprg:*"), env.keys("aevg:*")...); len(got) != 0 {
		t.Fatalf("keys written while both flows are disabled: %v", got)
	}
}
