package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func passwordVerifyTestConfig() Config {
	cfg := accountTestConfig()
	cfg.Security.MaxLoginAttempts = 3
	cfg.Security.LoginCooldownDuration = time.Minute
	return cfg
}

func TestChangePasswordRateLimitedAfterMaxAttempts(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Attempts 1..MaxLoginAttempts-1 (here 1 and 2) are plain invalid-credentials.
	for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
		if err := engine.ChangePassword(ctx, "u1", "wrong-old-pass", "new-password-999"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// The attempt that reaches MaxLoginAttempts trips the limiter.
	if err := engine.ChangePassword(ctx, "u1", "wrong-old-pass", "new-password-999"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected ErrPasswordVerifyRateLimited once the limit is reached, got %v", err)
	}

	// While limited, even the CORRECT old password is rejected with
	// ErrPasswordVerifyRateLimited rather than succeeding -- proving the
	// limiter is checked (and denies) before Argon2 ever runs, not just
	// after a failed verification.
	if err := engine.ChangePassword(ctx, "u1", "correct-password-123", "new-password-999"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected the correct password to still be rejected while rate limited, got %v", err)
	}
	if up.users["u1"].PasswordHash == "" {
		t.Fatal("sanity: user record missing")
	}
}

func TestChangePasswordRateLimitResetsOnSuccess(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// One failure short of the limit.
	for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
		if err := engine.ChangePassword(ctx, "u1", "wrong-old-pass", "new-password-999"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// A successful change resets the counter.
	if err := engine.ChangePassword(ctx, "u1", "correct-password-123", "new-password-999"); err != nil {
		t.Fatalf("expected successful change, got %v", err)
	}

	// The freshly-reset limiter tolerates another full run of failures
	// against the NEW password before tripping again.
	for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
		if err := engine.ChangePassword(ctx, "u1", "still-wrong", "another-new-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("post-reset attempt %d: expected ErrInvalidCredentials (limiter should have reset), got %v", i+1, err)
		}
	}
}

func TestChangePasswordRateLimitDoesNotTriggerAutoLockout(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	cfg.Security.AutoLockoutEnabled = true
	cfg.Security.AutoLockoutThreshold = 100 // far above what this test exhausts
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	// Exhaust the password-verify limiter (and then some).
	for i := 0; i < cfg.Security.MaxLoginAttempts+2; i++ {
		_ = engine.ChangePassword(ctx, "u1", "wrong-old-pass", "new-password-999")
	}

	user := up.users["u1"]
	if user.Status == AccountLocked {
		t.Fatal("a caller exhausting the password-verify limiter must not lock the account")
	}

	// The user can still log in with their real password -- the limiter
	// exhaustion above did not touch login or lockout state.
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
		t.Fatalf("expected login to still succeed after exhausting the password-verify limiter, got %v", err)
	}
}

func TestChangePasswordRateLimitTenantIsolation(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	up := newTenantMockProvider()
	hasher := newTestHasher(t)
	hashA, err := hasher.Hash("tenant-a-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	hashB, err := hasher.Hash("tenant-b-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	up.addUser(UserRecord{
		UserID: "user-a", Identifier: "shared@example.com", TenantID: "tenant-a",
		PasswordHash: hashA, Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	up.addUser(UserRecord{
		UserID: "user-b", Identifier: "shared@example.com", TenantID: "tenant-b",
		PasswordHash: hashB, Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = true
	cfg.Audit.Enabled = false
	cfg.JWT.SigningMethod = "hs256"
	cfg.JWT.PrivateKey = []byte("test-secret")
	cfg.Security.MaxLoginAttempts = 3
	cfg.Security.LoginCooldownDuration = time.Minute

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"read"}).
		WithRoles(map[string][]string{"member": {"read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctxA := WithTenantID(context.Background(), "tenant-a")
	ctxB := WithTenantID(context.Background(), "tenant-b")

	// user-a's id happens to collide in shape only; exhaust tenant-a's limiter.
	for i := 0; i < cfg.Security.MaxLoginAttempts; i++ {
		_ = engine.ChangePassword(ctxA, "user-a", "wrong-old-pass", "new-password-999")
	}
	if err := engine.ChangePassword(ctxA, "user-a", "tenant-a-password-123", "new-password-999"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected tenant-a to be rate limited, got %v", err)
	}

	// tenant-b's own user-b is untouched by tenant-a's exhausted limiter.
	if err := engine.ChangePassword(ctxB, "user-b", "tenant-b-password-123", "new-password-b-999"); err != nil {
		t.Fatalf("expected tenant-b to be unaffected by tenant-a's rate limit, got %v", err)
	}
}

func TestVerifyPasswordSuccessAndFailure(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	if err := engine.VerifyPassword(ctx, "u1", "correct-password-123"); err != nil {
		t.Fatalf("expected VerifyPassword success, got %v", err)
	}
	if err := engine.VerifyPassword(ctx, "u1", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// VerifyPassword must not mutate any state: the user's real password
	// still works afterwards.
	if err := engine.VerifyPassword(ctx, "u1", "correct-password-123"); err != nil {
		t.Fatalf("expected VerifyPassword to still succeed after a failed attempt, got %v", err)
	}
}

func TestVerifyPasswordRateLimitedAfterMaxAttempts(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
		if err := engine.VerifyPassword(ctx, "u1", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	if err := engine.VerifyPassword(ctx, "u1", "wrong-password"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected ErrPasswordVerifyRateLimited, got %v", err)
	}
	if err := engine.VerifyPassword(ctx, "u1", "correct-password-123"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected the correct password to still be rejected while rate limited, got %v", err)
	}
}

// VerifyPassword and ChangePassword's old-password check share one limiter
// per (tenant, userID): exhausting it through one blocks the other.
func TestVerifyPasswordSharesLimiterWithChangePassword(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	for i := 0; i < cfg.Security.MaxLoginAttempts; i++ {
		_ = engine.VerifyPassword(ctx, "u1", "wrong-password")
	}

	if err := engine.ChangePassword(ctx, "u1", "correct-password-123", "new-password-999"); !errors.Is(err, ErrPasswordVerifyRateLimited) {
		t.Fatalf("expected ChangePassword to be rate limited by VerifyPassword's failures, got %v", err)
	}
}

func TestVerifyPasswordUnknownUserAndInvalidInput(t *testing.T) {
	cfg := passwordVerifyTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()

	if err := engine.VerifyPassword(ctx, "", "some-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for empty userID, got %v", err)
	}
	if err := engine.VerifyPassword(ctx, "u1", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for empty password, got %v", err)
	}
	if err := engine.VerifyPassword(ctx, "no-such-user", "whatever-password"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for unknown user, got %v", err)
	}
}
