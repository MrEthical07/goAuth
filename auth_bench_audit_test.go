package goAuth

import (
	"context"
	"encoding/base32"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// These benchmarks cover the paths the security fixes touched, with the login
// failure limiter ON (the other benchmarks switch it off). They use only API
// that exists on v0.7.0 and v0.8.0, so the same file compiles on both sides of
// an A/B run:
//
//	go test -run '^$' -bench BenchmarkAudit -benchmem -count=5 .
//
// They run against miniredis; with REDIS_ADDR set they run against that Redis
// instead, where the extra round trips of a limiter script or a DEL show up.

func newAuditBenchEngine(b *testing.B, mfa bool) (*Engine, func()) {
	b.Helper()

	var rdb *redis.Client
	cleanup := func() {}
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: addr})
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			b.Skipf("Redis not available at %s: %v", addr, err)
		}
		rdb.FlushDB(context.Background())
		cleanup = func() { rdb.FlushDB(context.Background()); _ = rdb.Close() }
	} else {
		mr, err := miniredis.Run()
		if err != nil {
			b.Fatalf("miniredis.Run failed: %v", err)
		}
		rdb = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		cleanup = func() { _ = rdb.Close(); mr.Close() }
	}

	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.Security.EnableLoginFailureLimiter = true
	cfg.Security.MaxLoginAttempts = 1000
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Session.SlidingExpiration = false
	cfg.Session.JitterEnabled = false
	cfg.Metrics.Enabled = false
	cfg.Audit.Enabled = false
	cfg.JWT.AccessTTL = 10 * time.Minute
	cfg.JWT.RefreshTTL = 10 * time.Minute
	cfg.TOTP.Enabled = true
	cfg.TOTP.Issuer = "goAuth"
	cfg.TOTP.EnforceReplayProtection = false
	cfg.TOTP.RequireForLogin = mfa
	cfg.TOTP.MFALoginMaxAttempts = 1000

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		b.Fatalf("argon2 init failed: %v", err)
	}
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		b.Fatalf("hash failed: %v", err)
	}
	up := &mockUserProvider{
		users: map[string]UserRecord{"u1": {
			UserID: "u1", Identifier: "alice", TenantID: "0", PasswordHash: hash,
			Status: AccountActive, Role: "member",
			PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
		}},
		byIdentifier: map[string]string{"alice": "u1"},
		totpRecords:  map[string]TOTPRecord{},
	}
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		b.Fatalf("Build failed: %v", err)
	}
	return engine, func() { engine.Close(); cleanup() }
}

// auditBenchTOTP enrols the benchmark user and returns a function that yields
// the current code.
func auditBenchTOTP(b *testing.B, engine *Engine) func() string {
	b.Helper()
	setup, err := engine.GenerateTOTPSetup(context.Background(), "u1")
	if err != nil {
		b.Fatalf("GenerateTOTPSetup failed: %v", err)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(setup.SecretBase32))
	if err != nil {
		b.Fatalf("decode secret failed: %v", err)
	}
	code := func() string {
		c, err := hotpCode(key, time.Now().Unix()/int64(engine.config.TOTP.Period), engine.config.TOTP.Digits, engine.config.TOTP.Algorithm)
		if err != nil {
			b.Fatalf("hotpCode failed: %v", err)
		}
		return c
	}
	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", code()); err != nil {
		b.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}
	return code
}

func BenchmarkAuditLogin(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		access, _, err := engine.Login(ctx, "alice", "correct-password-123")
		if err != nil {
			b.Fatalf("login failed: %v", err)
		}
		b.StopTimer()
		_ = engine.LogoutByAccessToken(ctx, access)
		b.StartTimer()
	}
}

func BenchmarkAuditLoginMFA(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, true)
	defer cleanup()
	code := auditBenchTOTP(b, engine)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
		if err != nil || !res.MFARequired {
			b.Fatalf("login failed: %+v, %v", res, err)
		}
		done, err := engine.ConfirmLoginMFA(ctx, res.MFASession, code())
		if err != nil {
			b.Fatalf("confirm failed: %v", err)
		}
		b.StopTimer()
		_ = engine.LogoutByAccessToken(ctx, done.AccessToken)
		b.StartTimer()
	}
}

func BenchmarkAuditRefresh(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()
	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, next, err := engine.Refresh(ctx, refresh)
		if err != nil {
			b.Fatalf("refresh failed: %v", err)
		}
		refresh = next
	}
}

func BenchmarkAuditValidateStrict(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()
	access, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := engine.Validate(ctx, access, ModeStrict); err != nil {
			b.Fatalf("validate failed: %v", err)
		}
	}
}

func BenchmarkAuditValidateJWTOnly(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()
	access, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := engine.Validate(ctx, access, ModeJWTOnly); err != nil {
			b.Fatalf("validate failed: %v", err)
		}
	}
}

func BenchmarkAuditLogout(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
		if err != nil {
			b.Fatalf("login failed: %v", err)
		}
		sid, _, err := internal.DecodeRefreshToken(refresh)
		if err != nil {
			b.Fatalf("decode refresh failed: %v", err)
		}
		b.StartTimer()
		if err := engine.Logout(ctx, sid); err != nil {
			b.Fatalf("logout failed: %v", err)
		}
	}
}

func BenchmarkAuditLogoutAll(b *testing.B) {
	engine, cleanup := newAuditBenchEngine(b, false)
	defer cleanup()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		for i := 0; i < 3; i++ {
			if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
				b.Fatalf("login failed: %v", err)
			}
		}
		b.StartTimer()
		if err := engine.LogoutAll(ctx, "u1"); err != nil {
			b.Fatalf("logout all failed: %v", err)
		}
	}
}
