package goAuth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// Regression tests for the session-lifecycle findings of the v0.8.0 security
// audit (run 2). Each one is labelled FAILED-BEFORE with the finding ID: it
// fails on the commit the audit was run against and passes with the fix.

// loginParker parks the first password verification of the real account until
// release is called, which is the moment between "the login has read the
// account" and "the login stores its session".
type loginParker struct {
	armed  atomic.Bool
	parked chan struct{}
	gate   chan struct{}
}

func installLoginParker(engine *Engine, realHash string) *loginParker {
	p := &loginParker{parked: make(chan struct{}), gate: make(chan struct{})}
	p.armed.Store(true)
	engine.verifyHashFn = func(password, encodedHash string) (bool, error) {
		if encodedHash == realHash && p.armed.CompareAndSwap(true, false) {
			close(p.parked)
			<-p.gate
		}
		return engine.passwordHash.Verify(password, encodedHash)
	}
	return p
}

func (p *loginParker) release() { close(p.gate) }

// parkedLogin starts a login that parks in password verification and returns
// once it has parked, plus the channel its outcome arrives on.
func parkedLogin(t *testing.T, engine *Engine, p *loginParker, password string) <-chan error {
	t.Helper()
	out := make(chan error, 1)
	go func() {
		_, _, err := engine.Login(context.Background(), "alice", password)
		out <- err
	}()
	<-p.parked
	return out
}

func activeSessions(t *testing.T, engine *Engine) int {
	t.Helper()
	n, err := engine.sessionStore.ActiveSessionCount(context.Background(), "0", "u1")
	if err != nil {
		t.Fatalf("ActiveSessionCount: %v", err)
	}
	return n
}

// FAILED-BEFORE (R2-08): a login that had read the account before a password
// change still stored a live, refreshable session after the change had revoked
// everything.
func TestLoginRacingAPasswordChangeLeavesNoSession(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.ChangePassword(context.Background(), "u1", "correct-password-123", "another-password-456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	p.release()

	if err := <-outcome; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the racing login returned %v, want ErrInvalidCredentials", err)
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("%d session(s) survived the password change", n)
	}
}

// FAILED-BEFORE (R2-08): the same for DisableAccount.
func TestLoginRacingADisableLeavesNoSession(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}
	p.release()

	if err := <-outcome; !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("the racing login returned %v, want ErrAccountDisabled", err)
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("%d session(s) survived DisableAccount", n)
	}
}

// A logout-all that is unrelated to the login (the account is still usable and
// the password is the one that was verified) does not fail the login: it
// retries once on the account as it is now.
func TestLoginRacingAnUnrelatedLogoutAllStillSucceeds(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.LogoutAll(context.Background(), "u1"); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	p.release()

	if err := <-outcome; err != nil {
		t.Fatalf("the racing login returned %v, want success", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("%d sessions, want the login's own", n)
	}
}

// FAILED-BEFORE (R2-08): the unparked schedule of the audit. Several loops of
// logins with the old password run while the owner changes it; when they stop
// no session may remain.
func TestOverlappingLoginsDoNotSurviveAPasswordChange(t *testing.T) {
	for round := 0; round < 4; round++ {
		cfg := accountTestConfig()
		cfg.Security.EnableLoginFailureLimiter = false
		up := newHardeningUserProvider(t)
		engine, _ := newAuditEngine(t, cfg, up)

		var wg sync.WaitGroup
		stop := make(chan struct{})
		started := make(chan struct{}, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started <- struct{}{}
				for {
					select {
					case <-stop:
						return
					default:
						_, _, _ = engine.Login(context.Background(), "alice", "correct-password-123")
					}
				}
			}()
		}
		for i := 0; i < 8; i++ {
			<-started
		}
		if err := engine.ChangePassword(context.Background(), "u1", "correct-password-123", "another-password-456"); err != nil {
			t.Fatalf("round %d: ChangePassword: %v", round, err)
		}
		close(stop)
		wg.Wait()

		if n := activeSessions(t, engine); n != 0 {
			t.Fatalf("round %d: %d session(s) created with the old password survived the change", round, n)
		}
		if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("round %d: the old password still logs in: %v", round, err)
		}
	}
}

// FAILED-BEFORE (R2-27): the session caps were checked at the password step
// only, so confirming several MFA challenges stored more sessions than the cap.
func TestMFAConfirmCannotExceedThePerUserSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 4)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	succeeded := 0
	for _, challenge := range challenges {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP))
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrSessionLimitExceeded):
		default:
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != cfg.SessionHardening.MaxSessionsPerUser {
		t.Fatalf("%d MFA logins stored a session, the cap is %d", succeeded, cfg.SessionHardening.MaxSessionsPerUser)
	}
	if n := activeSessions(t, engine); n != cfg.SessionHardening.MaxSessionsPerUser {
		t.Fatalf("user holds %d sessions, want %d", n, cfg.SessionHardening.MaxSessionsPerUser)
	}
}

// FAILED-BEFORE (R2-27): the shared tenant cap.
func TestMFAConfirmCannotExceedTheTenantSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerTenant = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 4)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	succeeded := 0
	for _, challenge := range challenges {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP))
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTenantSessionLimitExceeded):
		default:
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != 2 {
		t.Fatalf("%d MFA logins stored a session, the tenant cap is 2", succeeded)
	}
	if n, _ := engine.sessionStore.TenantSessionCount(context.Background(), "0"); n != 2 {
		t.Fatalf("tenant holds %d sessions, want 2", n)
	}
}

// FAILED-BEFORE (R2-27): and in parallel, where check-then-write cannot hold.
func TestParallelMFAConfirmsCannotExceedTheSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 8)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	code := codeForNow(t, secret, cfg.TOTP)
	errs := burst(t, len(challenges), 0, nil, func(i int) error {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenges[i], code)
		return err
	})
	succeeded := 0
	for _, err := range errs {
		// Confirmations beyond the account's TOTP budget in flight at once are
		// refused by that budget before their code is checked.
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrSessionLimitExceeded) && !errors.Is(err, ErrTOTPRateLimited) {
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != 2 || activeSessions(t, engine) != 2 {
		t.Fatalf("%d confirmations stored a session (%d held), the cap is 2", succeeded, activeSessions(t, engine))
	}
}

// FAILED-BEFORE (R2-28): with EnforceSingleSession the password step ended all
// of the account's sessions before the second factor, so a first-factor-only
// caller could sign the owner out repeatedly.
func TestPasswordStepOfAnMFALoginDoesNotEndExistingSessions(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	first, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), codeForNow(t, secret, cfg.TOTP))
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Someone who only knows the password.
	pending := mfaChallenge(t, engine)
	if _, err := engine.Validate(ctx, first.AccessToken, ModeStrict); err != nil {
		t.Fatalf("the password step ended the owner's session: %v", err)
	}

	// The login that completes replaces it, as single-session mode promises.
	second, err := engine.ConfirmLoginMFA(ctx, pending, codeForNow(t, secret, cfg.TOTP))
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if _, err := engine.Validate(ctx, first.AccessToken, ModeStrict); err == nil {
		t.Fatal("single-session mode left the previous session alive after the new login completed")
	}
	if _, err := engine.Validate(ctx, second.AccessToken, ModeStrict); err != nil {
		t.Fatalf("the new session does not validate: %v", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}

// Single-session mode without MFA keeps its behavior: the new login replaces
// the old session.
func TestSingleSessionPasswordLoginStillReplacesThePreviousSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	ctx := context.Background()

	first, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Validate(ctx, first, ModeStrict); err == nil {
		t.Fatal("the previous session survived")
	}
	if _, err := engine.Validate(ctx, second, ModeStrict); err != nil {
		t.Fatalf("the new session does not validate: %v", err)
	}
}
