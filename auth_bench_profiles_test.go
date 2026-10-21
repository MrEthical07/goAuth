package goAuth

import (
	"context"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// The Profile benchmarks mirror BenchmarkLogin, BenchmarkRefresh and
// BenchmarkValidateStrict with session profiles configured, so the cost of the
// feature can be read against the unprofiled numbers (the profile-less
// benchmarks themselves double as the "feature unused" measurement).

func newProfileBenchmarkEngine(tb testing.TB, mode ValidationMode) (*Engine, func()) {
	tb.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		tb.Fatalf("miniredis.Run failed: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cfg := accountTestConfig()
	cfg.ValidationMode = mode
	cfg.Security.EnableAccountVersionCheck = mode != ModeJWTOnly
	cfg.Security.EnableLoginFailureLimiter = false
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Session.SlidingExpiration = false
	cfg.Session.JitterEnabled = false
	cfg.Metrics.Enabled = false
	cfg.Audit.Enabled = false
	cfg.SessionHardening.MaxSessionsPerUser = 0
	cfg.SessionHardening.MaxSessionsPerTenant = 0
	cfg.JWT.AccessTTL = 10 * time.Minute
	cfg.JWT.RefreshTTL = 10 * time.Minute
	cfg.SessionProfiles.Profiles = map[string]SessionProfile{
		"web":    {AbsoluteLifetime: 15 * 24 * time.Hour},
		"mobile": {IdleTimeout: 90 * 24 * time.Hour, AbsoluteLifetime: 365 * 24 * time.Hour, RenewOnUse: true},
	}
	cfg.SessionProfiles.DefaultProfile = "mobile"

	hasher, err := password.NewArgon2(password.Config{
		Memory:      cfg.Password.Memory,
		Time:        cfg.Password.Time,
		Parallelism: cfg.Password.Parallelism,
		SaltLength:  cfg.Password.SaltLength,
		KeyLength:   cfg.Password.KeyLength,
	})
	if err != nil {
		tb.Fatalf("argon2 init failed: %v", err)
	}
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		tb.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID: "u1", Identifier: "alice", TenantID: "0", PasswordHash: hash,
				Status: AccountActive, Role: "member",
				PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		tb.Fatalf("Build failed: %v", err)
	}
	return engine, func() {
		engine.Close()
		_ = rdb.Close()
		mr.Close()
	}
}

func BenchmarkValidateStrictProfile(b *testing.B) {
	engine, cleanup := newProfileBenchmarkEngine(b, ModeStrict)
	defer cleanup()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
			b.Fatalf("validate failed: %v", err)
		}
	}
}

func BenchmarkRefreshProfile(b *testing.B) {
	engine, cleanup := newProfileBenchmarkEngine(b, ModeHybrid)
	defer cleanup()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, nextRefresh, err := engine.Refresh(context.Background(), refresh)
		if err != nil {
			b.Fatalf("refresh failed: %v", err)
		}
		refresh = nextRefresh
	}
}

func BenchmarkLoginProfile(b *testing.B) {
	engine, cleanup := newProfileBenchmarkEngine(b, ModeHybrid)
	defer cleanup()

	ctx := WithSessionProfile(context.Background(), "mobile")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		access, _, err := engine.Login(ctx, "alice", "correct-password-123")
		if err != nil {
			b.Fatalf("login failed: %v", err)
		}
		_ = engine.LogoutByAccessToken(context.Background(), access)
	}
}
