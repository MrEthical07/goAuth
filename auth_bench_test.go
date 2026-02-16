package goAuth

import (
	"context"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func BenchmarkValidateJWTOnly(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeJWTOnly)
	defer cleanup()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
			b.Fatalf("validate failed: %v", err)
		}
	}
}

func BenchmarkValidateStrict(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeStrict)
	defer cleanup()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
			b.Fatalf("validate failed: %v", err)
		}
	}
}

func BenchmarkRefresh(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeHybrid)
	defer cleanup()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, nextRefresh, err := engine.Refresh(context.Background(), refresh)
		if err != nil {
			b.Fatalf("refresh failed: %v", err)
		}
		refresh = nextRefresh
	}
}

func BenchmarkLogin(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeHybrid)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
		if err != nil {
			b.Fatalf("login failed: %v", err)
		}
		_ = engine.LogoutByAccessToken(context.Background(), access)
	}
}

func newBenchmarkEngine(tb testing.TB, mode ValidationMode) (*Engine, func()) {
	tb.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		tb.Fatalf("miniredis.Run failed: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cfg := accountTestConfig()
	cfg.ValidationMode = mode
	cfg.Security.EnableAccountVersionCheck = mode != ModeJWTOnly
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Metrics.Enabled = false
	cfg.Audit.Enabled = false
	cfg.SessionHardening.MaxSessionsPerUser = 0
	cfg.SessionHardening.MaxSessionsPerTenant = 0
	cfg.JWT.AccessTTL = 10 * time.Minute
	cfg.JWT.RefreshTTL = 10 * time.Minute

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
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "0",
				PasswordHash:      hash,
				Status:            AccountActive,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{
			"alice": "u1",
		},
	}

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{
			"member": {},
			"admin":  {"perm.read"},
		}).
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
