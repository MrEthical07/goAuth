package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// lockoutTestConfig returns a base config with auto-lockout enabled and a low threshold for testing.
func lockoutTestConfig() Config {
	cfg := accountTestConfig()
	cfg.Security.AutoLockoutEnabled = true
	cfg.Security.AutoLockoutThreshold = 3
	cfg.Security.AutoLockoutDuration = 0 // manual unlock only by default
	return cfg
}

func TestAutoLockout_ThresholdTriggersLock(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	wrongPwd := "wrong-password"

	// First N-1 failures should return InvalidCredentials.
	for i := 0; i < cfg.Security.AutoLockoutThreshold-1; i++ {
		_, _, err := engine.Login(ctx, "alice", wrongPwd)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// The Nth failure locks the account but is answered like any other wrong
	// password; the lock shows once the right password is given.
	_, _, err := engine.Login(ctx, "alice", wrongPwd)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("threshold attempt: expected ErrInvalidCredentials, got %v", err)
	}
	if up.users["u1"].Status != AccountLocked {
		t.Fatalf("expected the account to be locked, status %d", up.users["u1"].Status)
	}
}

func TestAutoLockout_LockedUserCannotLogin(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Exhaust threshold to lock the account.
	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		engine.Login(ctx, "alice", "wrong-password")
	}

	// Even with the correct password, login should fail — account is locked.
	_, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked for locked user, got %v", err)
	}
}

func TestAutoLockout_UnlockAccountRestoresAccess(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Lock the account.
	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		engine.Login(ctx, "alice", "wrong-password")
	}

	// Verify locked.
	_, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}

	// Unlock the account.
	if err := engine.UnlockAccount(ctx, "u1"); err != nil {
		t.Fatalf("UnlockAccount failed: %v", err)
	}

	// Login should now succeed.
	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login after unlock failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected tokens after successful login")
	}
}

func TestAutoLockout_EnableAccountResetsLockout(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Lock via threshold.
	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		engine.Login(ctx, "alice", "wrong-password")
	}

	// Use EnableAccount (not UnlockAccount) — it should also reset the lockout counter.
	if err := engine.EnableAccount(ctx, "u1"); err != nil {
		t.Fatalf("EnableAccount failed: %v", err)
	}

	// Login should succeed.
	_, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login after EnableAccount failed: %v", err)
	}
}

func TestAutoLockout_CounterResetsOnSuccessfulLogin(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Accumulate failures just under the threshold.
	for i := 0; i < cfg.Security.AutoLockoutThreshold-1; i++ {
		_, _, err := engine.Login(ctx, "alice", "wrong-password")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// Successful login to reset counter.
	_, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("successful login failed: %v", err)
	}

	// Now N-1 more failures should not trigger lockout.
	for i := 0; i < cfg.Security.AutoLockoutThreshold-1; i++ {
		_, _, err := engine.Login(ctx, "alice", "wrong-password")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("post-reset attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// Login should still work (counter was reset, we only did N-1 more failures).
	_, _, err = engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("second successful login failed: %v", err)
	}
}

func TestAutoLockout_DurationZeroRequiresManualUnlock(t *testing.T) {
	cfg := lockoutTestConfig()
	cfg.Security.AutoLockoutDuration = 0 // manual only
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Lock the account.
	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		engine.Login(ctx, "alice", "wrong-password")
	}

	// Account stays locked because Duration=0 means no auto-expiry.
	_, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked (manual unlock only), got %v", err)
	}

	// Manual unlock required.
	if err := engine.UnlockAccount(ctx, "u1"); err != nil {
		t.Fatalf("UnlockAccount failed: %v", err)
	}

	_, _, err = engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login after manual unlock failed: %v", err)
	}
}

func TestAutoLockout_OtherUsersNotAffected(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Lock alice.
	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		engine.Login(ctx, "alice", "wrong-password")
	}

	// Bob should still be able to login.
	access, refresh, err := engine.Login(ctx, "bob", "correct-password-123")
	if err != nil {
		t.Fatalf("bob login failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected tokens for bob")
	}
}

func TestAutoLockout_DisabledDoesNotLock(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.AutoLockoutEnabled = false
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Many failures — should never trigger lockout.
	for i := 0; i < 20; i++ {
		_, _, err := engine.Login(ctx, "alice", "wrong-password")
		if errors.Is(err, ErrAccountLocked) {
			t.Fatalf("attempt %d: got unexpected ErrAccountLocked with lockout disabled", i+1)
		}
	}
}

func TestAutoLockout_StillTriggersWhenLoginFailureLimiterDisabled(t *testing.T) {
	cfg := lockoutTestConfig()
	cfg.Security.EnableLoginFailureLimiter = false
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	for i := 0; i < cfg.Security.AutoLockoutThreshold-1; i++ {
		_, _, err := engine.Login(ctx, "alice", "wrong-password")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	_, _, err := engine.Login(ctx, "alice", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("threshold attempt: expected ErrInvalidCredentials, got %v", err)
	}
	if up.users["u1"].Status != AccountLocked {
		t.Fatalf("expected the account to be locked, status %d", up.users["u1"].Status)
	}
}

func TestAutoLockout_LockedAccountStrictValidateFails(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Login successfully first to get tokens.
	access, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("initial login failed: %v", err)
	}

	// Lock the account manually.
	if err := engine.LockAccount(ctx, "u1"); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	// Strict-mode validation should fail for a locked account.
	_, err = engine.Validate(ctx, access, ModeStrict)
	if err == nil {
		t.Fatal("expected error from Validate(ModeStrict) for locked account")
	}
}

func TestAutoLockout_LockedAccountRefreshFails(t *testing.T) {
	cfg := lockoutTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Login successfully first to get tokens.
	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("initial login failed: %v", err)
	}

	// Lock the account.
	if err := engine.LockAccount(ctx, "u1"); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	// Refresh should fail for a locked account.
	_, _, err = engine.Refresh(ctx, refresh)
	if err == nil {
		t.Fatal("expected error from Refresh for locked account")
	}
}

// FAILED-BEFORE (R2-15): AutoLockoutDuration was documented as the duration of
// the lock, but it only sizes the window failures are counted in. The account
// stays Locked until it is unlocked, and Lint now says so.
func TestAutoLockoutDurationDoesNotUnlockAndIsLinted(t *testing.T) {
	cfg := lockoutTestConfig()
	cfg.Security.AutoLockoutDuration = 2 * time.Second
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	ctx := context.Background()

	for i := 0; i < cfg.Security.AutoLockoutThreshold; i++ {
		_, _, _ = engine.Login(ctx, "alice", "wrong-password")
	}
	mr.FastForward(24 * time.Hour)
	if up.users["u1"].Status != AccountLocked {
		t.Fatalf("status %d: the account must stay locked after the window", up.users["u1"].Status)
	}
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("got %v, want ErrAccountLocked until the account is unlocked", err)
	}
	if err := engine.UnlockAccount(ctx, "u1"); err != nil {
		t.Fatalf("UnlockAccount: %v", err)
	}
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
		t.Fatalf("after UnlockAccount: %v", err)
	}

	on := lockoutTestConfig()
	on.Security.AutoLockoutDuration = time.Minute
	if !hasLintCode((&on).Lint(), "auto_lockout_duration_noop") {
		t.Fatal("expected auto_lockout_duration_noop while auto-lockout has a duration")
	}
	manual := lockoutTestConfig()
	manual.Security.AutoLockoutDuration = 0
	if hasLintCode((&manual).Lint(), "auto_lockout_duration_noop") {
		t.Fatal("no note without a duration")
	}
	off := lockoutTestConfig()
	off.Security.AutoLockoutEnabled = false
	off.Security.AutoLockoutDuration = time.Minute
	if hasLintCode((&off).Lint(), "auto_lockout_duration_noop") {
		t.Fatal("no note while auto-lockout is off")
	}
}
