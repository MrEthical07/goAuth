package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/session"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func newTestResetEngine(
	t *testing.T,
	rdb *redis.Client,
	up UserProvider,
	hasher *password.Argon2,
	cfg PasswordResetConfig,
) *Engine {
	t.Helper()

	return &Engine{
		config: Config{
			PasswordReset: cfg,
		},
		userProvider: up,
		passwordHash: hasher,
		sessionStore: session.NewStore(rdb, "as", false, false, 0),
		resetStore:   stores.NewPasswordResetStore(rdb, "apr"),
		resetLimiter: limiters.NewPasswordResetLimiter(rdb, limiters.PasswordResetConfig{
			EnableIdentifierThrottle: cfg.EnableIdentifierThrottle,
			EnableIPThrottle:         cfg.EnableIPThrottle,
			ResetTTL:                 cfg.ResetTTL,
			MaxAttempts:              cfg.MaxAttempts,
		}),
	}
}

func testResetConfig(strategy ResetStrategyType) PasswordResetConfig {
	cfg := PasswordResetConfig{
		Enabled:                  true,
		Strategy:                 strategy,
		ResetTTL:                 15 * time.Minute,
		MaxAttempts:              5,
		EnableIPThrottle:         true,
		EnableIdentifierThrottle: true,
		OTPDigits:                6,
	}
	if strategy != ResetOTP {
		cfg.EnableIPThrottle = false
		cfg.EnableIdentifierThrottle = false
	}
	return cfg
}

func TestPasswordResetTokenFlow(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	challenge, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if challenge == "" {
		t.Fatal("expected non-empty reset challenge")
	}

	if err := rdb.SAdd(ctx, "au:0:u1", "s1").Err(); err != nil {
		t.Fatalf("seed session index failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:0:s1", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session failed: %v", err)
	}

	if err := engine.ConfirmPasswordReset(ctx, challenge, "new-password-123"); err != nil {
		t.Fatalf("ConfirmPasswordReset failed: %v", err)
	}

	updated := up.users["u1"]
	ok, err := hasher.Verify("new-password-123", updated.PasswordHash)
	if err != nil || !ok {
		t.Fatalf("expected updated password hash verification to succeed, ok=%v err=%v", ok, err)
	}

	if rdb.Exists(ctx, "as:0:s1").Val() != 0 || rdb.Exists(ctx, "au:0:u1").Val() != 0 {
		t.Fatal("expected sessions to be invalidated after reset confirmation")
	}

	if err := engine.ConfirmPasswordReset(ctx, challenge, "newer-password-123"); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("expected replayed challenge to fail with ErrPasswordResetInvalid, got %v", err)
	}
}

func TestPasswordResetUUIDFlow(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetUUID))

	challenge, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if _, err := uuid.Parse(challenge); err != nil {
		t.Fatalf("expected UUID challenge, got %q", challenge)
	}

	if err := engine.ConfirmPasswordReset(ctx, challenge, "new-password-123"); err != nil {
		t.Fatalf("ConfirmPasswordReset failed: %v", err)
	}
}

func TestPasswordResetOTPAttemptsExceeded(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	cfg := testResetConfig(ResetOTP)
	engine := newTestResetEngine(t, rdb, up, hasher, cfg)

	challenge, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	parts := strings.SplitN(challenge, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected OTP challenge with resetID prefix, got %q", challenge)
	}
	if len(parts[1]) != cfg.OTPDigits {
		t.Fatalf("expected OTP length %d, got %d", cfg.OTPDigits, len(parts[1]))
	}

	wrongOTP := makeDifferentOTP(parts[1])
	wrongChallenge := parts[0] + "." + wrongOTP

	for i := 1; i < cfg.MaxAttempts; i++ {
		err := engine.ConfirmPasswordReset(ctx, wrongChallenge, "new-password-123")
		if !errors.Is(err, ErrPasswordResetInvalid) {
			t.Fatalf("attempt %d expected ErrPasswordResetInvalid, got %v", i, err)
		}
	}

	err = engine.ConfirmPasswordReset(ctx, wrongChallenge, "new-password-123")
	if !errors.Is(err, ErrPasswordResetAttempts) {
		t.Fatalf("expected ErrPasswordResetAttempts on max attempt, got %v", err)
	}
}

func TestPasswordResetRequestEnumerationSafe(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	challenge, err := engine.RequestPasswordReset(ctx, "missing@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset should be enumeration-safe success, got %v", err)
	}
	if challenge == "" {
		t.Fatal("expected non-empty challenge for enumeration-safe response")
	}

	resetID, _, parseErr := parsePasswordResetChallenge(ResetToken, challenge, 0)
	if parseErr != nil {
		t.Fatalf("expected parseable token challenge, got %v", parseErr)
	}
	if rdb.Exists(ctx, "apr:0:"+resetID).Val() != 0 {
		t.Fatal("expected no reset record for unknown user")
	}
}

func TestPasswordResetConfigOTPValidation(t *testing.T) {
	cfg := defaultConfig()
	cfg.PasswordReset.Enabled = true
	cfg.PasswordReset.Strategy = ResetOTP
	cfg.PasswordReset.ResetTTL = 20 * time.Minute
	cfg.PasswordReset.MaxAttempts = 6
	cfg.PasswordReset.EnableIPThrottle = false
	cfg.PasswordReset.EnableIdentifierThrottle = false
	cfg.PasswordReset.OTPDigits = 4

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected OTP security validation error")
	}
}

func TestPasswordResetReplayRaceSingleSuccess(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	challenge, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	results := make(chan error, 2)

	runConfirm := func() {
		defer wg.Done()
		<-start
		results <- engine.ConfirmPasswordReset(ctx, challenge, "new-password-123")
	}

	go runConfirm()
	go runConfirm()
	close(start)
	wg.Wait()
	close(results)

	success := 0
	invalid := 0
	for err := range results {
		if err == nil {
			success++
			continue
		}
		if errors.Is(err, ErrPasswordResetInvalid) {
			invalid++
			continue
		}
		t.Fatalf("expected nil or ErrPasswordResetInvalid, got %v", err)
	}

	if success != 1 || invalid != 1 {
		t.Fatalf("expected one success and one invalid replay, got success=%d invalid=%d", success, invalid)
	}
}

func TestPasswordResetRequestFailsWhenRedisUnavailable(t *testing.T) {
	mr, rdb := newTestRedis(t)
	ctx := context.Background()
	hasher := newTestHasher(t)

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: "x", TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	mr.Close()

	_, err := engine.RequestPasswordReset(ctx, "alice")
	if !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("expected ErrPasswordResetUnavailable, got %v", err)
	}
}

func TestPasswordResetConfirmFailsWhenRedisUnavailable(t *testing.T) {
	mr, rdb := newTestRedis(t)
	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	challenge, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	mr.Close()

	err = engine.ConfirmPasswordReset(ctx, challenge, "new-password-123")
	if !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("expected ErrPasswordResetUnavailable, got %v", err)
	}
}

func makeDifferentOTP(current string) string {
	if current == "" {
		return "000000"
	}

	first := current[0]
	replacement := byte('0')
	if first == '0' {
		replacement = '1'
	}

	return string(replacement) + current[1:]
}
