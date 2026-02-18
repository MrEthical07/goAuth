package goAuth

import (
	"context"
	"errors"
	"testing"
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

	// The Nth failure should trigger lockout and return ErrAccountLocked.
	_, _, err := engine.Login(ctx, "alice", wrongPwd)
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("threshold attempt: expected ErrAccountLocked, got %v", err)
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
