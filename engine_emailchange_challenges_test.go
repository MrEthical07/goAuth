package goAuth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Before this change nothing tied an outstanding password-reset or
// email-verification challenge to the address it was sent to, and the
// AccountVersion bump did not invalidate them either (their records hold no
// version). A confirmed email change now refuses every challenge issued before
// it.
func TestEmailChangeInvalidatesChallengesIssuedToTheOldAddress(t *testing.T) {
	t.Run("password reset", func(t *testing.T) {
		env := newECEnv(t, nil)
		oldReset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatalf("RequestPasswordReset: %v", err)
		}
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

		err = env.engine.ConfirmPasswordReset(env.ctx(), oldReset, "brand-new-password-9")
		if !errors.Is(err, ErrPasswordResetInvalid) {
			t.Fatalf("a reset code issued before the change = %v, want ErrPasswordResetInvalid", err)
		}
		if got := env.user(rsUserID); got.PasswordHash == "" {
			t.Fatal("password hash lost")
		}
		if ttl := env.mr.TTL("aeci:" + env.tenant + ":" + rsUserID); ttl < 25*time.Minute {
			t.Fatalf("marker TTL = %v, want it to outlive a challenge", ttl)
		}

		// A code requested afterwards, for the new address, works.
		time.Sleep(1100 * time.Millisecond)
		fresh, err := env.engine.RequestPasswordReset(env.ctx(), ecNewEmail)
		if err != nil {
			t.Fatalf("RequestPasswordReset(new): %v", err)
		}
		if err := env.engine.ConfirmPasswordReset(env.ctx(), fresh, "brand-new-password-9"); err != nil {
			t.Fatalf("a reset code issued after the change: %v", err)
		}
	})

	t.Run("without a change an old reset code keeps working (and a version bump alone does not stop it)", func(t *testing.T) {
		env := newECEnv(t, nil)
		oldReset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatal(err)
		}
		u := env.user(rsUserID)
		u.AccountVersion++
		u.Identifier = "changed.elsewhere@example.com" // a change made outside goAuth
		env.setUser(u)
		if err := env.engine.ConfirmPasswordReset(env.ctx(), oldReset, "brand-new-password-9"); err != nil {
			t.Fatalf("expected the reset to go through (the gap the marker closes): %v", err)
		}
	})

	t.Run("email verification", func(t *testing.T) {
		env := newECEnv(t, nil)
		u := env.user(rsUserID)
		u.Status = AccountPendingVerification
		env.setUser(u)
		challenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatalf("RequestEmailVerification: %v", err)
		}
		parts := strings.SplitN(challenge, ":", 3)
		// An administrator activates the account by other means; then it
		// changes its address.
		if err := env.engine.EnableAccount(env.ctx(), rsUserID); err != nil {
			t.Fatalf("EnableAccount: %v", err)
		}
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

		err = env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2])
		if !errors.Is(err, ErrEmailVerificationInvalid) {
			t.Fatalf("a verification code issued before the change = %v, want ErrEmailVerificationInvalid", err)
		}
	})

	t.Run("email verification without a change is a no-op success", func(t *testing.T) {
		env := newECEnv(t, nil)
		u := env.user(rsUserID)
		u.Status = AccountPendingVerification
		env.setUser(u)
		challenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(challenge, ":", 3)
		if err := env.engine.EnableAccount(env.ctx(), rsUserID); err != nil {
			t.Fatal(err)
		}
		if err := env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2]); err != nil {
			t.Fatalf("control: %v", err)
		}
	})

	t.Run("another user's challenges are unaffected", func(t *testing.T) {
		env := newECEnv(t, nil)
		env.addOther("u2", "second@example.com")
		reset, err := env.engine.RequestPasswordReset(env.ctx(), "second@example.com")
		if err != nil {
			t.Fatal(err)
		}
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		if err := env.engine.ConfirmPasswordReset(env.ctx(), reset, "brand-new-password-9"); err != nil {
			t.Fatalf("another user's reset: %v", err)
		}
	})

	t.Run("a marker that cannot be read refuses the challenge", func(t *testing.T) {
		env := newECEnv(t, nil)
		reset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatal(err)
		}
		// The marker is only read for a record without a pointer (one an older
		// instance issued): drop the pointer to be that record.
		env.mr.Del("aprg:" + env.tenant + ":" + rsUserID)
		hook := &keyFailHook{substr: "aeci:"}
		env.rdb.AddHook(hook)
		hook.on.Store(true)
		err = env.engine.ConfirmPasswordReset(env.ctx(), reset, "brand-new-password-9")
		if !errors.Is(err, ErrPasswordResetUnavailable) {
			t.Fatalf("= %v, want ErrPasswordResetUnavailable", err)
		}
	})
}

// With the feature on but no change ever made, a reset or verification confirm
// whose record has a pointer reads no marker; one without a pointer (issued by
// an older instance) reads the one extra key.
func TestEmailChangeOnCostsOneReadOnTheConfirmPaths(t *testing.T) {
	env := newECEnv(t, nil)
	reset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	env.mr.Del("aprg:" + env.tenant + ":" + rsUserID)
	env.cmds.reset()
	if err := env.engine.ConfirmPasswordReset(env.ctx(), reset, "brand-new-password-9"); err != nil {
		t.Fatal(err)
	}
	var markerReads int
	for _, name := range env.cmds.names() {
		if name == "get" {
			markerReads++
		}
	}
	if !env.cmds.touches("aeci:") {
		t.Fatal("expected the marker to be read")
	}
	if markerReads == 0 {
		t.Fatal("no GET recorded")
	}
}

// A reset code requested for the old address while the provider call is running
// is issued after the marker's first write; the marker is written again once
// the provider commits, so that code is refused too.
func TestEmailChangeRefusesACodeRequestedWhileTheChangeCommits(t *testing.T) {
	env := newECEnv(t, nil)
	req := env.mustRequest(ecNewEmail)

	var during string
	env.up.beforeUpdateIdentifier = func() {
		time.Sleep(1100 * time.Millisecond) // a later second than the first marker write
		code, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Errorf("RequestPasswordReset during the change: %v", err)
		}
		during = code
	}
	env.mustConfirm(req, ConfirmEmailChangeOptions{})
	if during == "" {
		t.Fatal("the hook did not run")
	}

	err := env.engine.ConfirmPasswordReset(env.ctx(), during, "brand-new-password-9")
	if !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a reset code requested during the commit = %v, want ErrPasswordResetInvalid", err)
	}
}
