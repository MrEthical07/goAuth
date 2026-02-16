package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/session"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func testEmailVerificationConfig(strategy VerificationStrategyType) EmailVerificationConfig {
	cfg := EmailVerificationConfig{
		Enabled:                  true,
		Strategy:                 strategy,
		VerificationTTL:          15 * time.Minute,
		MaxAttempts:              5,
		RequireForLogin:          false,
		EnableIPThrottle:         true,
		EnableIdentifierThrottle: true,
		OTPDigits:                6,
	}

	if strategy != VerificationOTP {
		cfg.EnableIPThrottle = false
		cfg.EnableIdentifierThrottle = false
	}

	return cfg
}

func newTestEmailVerificationEngine(
	t *testing.T,
	rdb *redis.Client,
	up UserProvider,
	cfg EmailVerificationConfig,
) *Engine {
	t.Helper()

	return &Engine{
		config: Config{
			EmailVerification: cfg,
		},
		userProvider:        up,
		sessionStore:        session.NewStore(rdb, "as", false, false, 0),
		verificationStore:   stores.NewEmailVerificationStore(rdb, "apv"),
		verificationLimiter: limiters.NewEmailVerificationLimiter(rdb, limiters.EmailVerificationConfig{
			EnableIdentifierThrottle: cfg.EnableIdentifierThrottle,
			EnableIPThrottle:         cfg.EnableIPThrottle,
			VerificationTTL:          cfg.VerificationTTL,
			MaxAttempts:              cfg.MaxAttempts,
		}),
	}
}

func verificationLoginConfig(mode ValidationMode) Config {
	cfg := accountTestConfig()
	cfg.ValidationMode = mode
	if mode == ModeJWTOnly {
		cfg.Security.EnableAccountVersionCheck = false
	}
	cfg.EmailVerification.Enabled = true
	cfg.EmailVerification.Strategy = VerificationToken
	cfg.EmailVerification.VerificationTTL = 15 * time.Minute
	cfg.EmailVerification.MaxAttempts = 5
	cfg.EmailVerification.OTPDigits = 6
	cfg.EmailVerification.EnableIPThrottle = true
	cfg.EmailVerification.EnableIdentifierThrottle = true
	cfg.EmailVerification.RequireForLogin = true
	return cfg
}

func testPendingUser(hasher *password.Argon2) (UserRecord, error) {
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		return UserRecord{}, err
	}

	return UserRecord{
		UserID:            "u1",
		Identifier:        "alice",
		TenantID:          "0",
		PasswordHash:      hash,
		Status:            AccountPendingVerification,
		Role:              "member",
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
	}, nil
}

func TestEmailVerificationTokenFlowSuccess(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}
	if challenge == "" {
		t.Fatal("expected non-empty challenge")
	}

	verificationID, _, err := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
	if err != nil {
		t.Fatalf("parse challenge failed: %v", err)
	}
	if rdb.Exists(ctx, "apv:0:"+verificationID).Val() != 1 {
		t.Fatal("expected verification record key to exist")
	}

	if err := engine.ConfirmEmailVerification(ctx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v", err)
	}

	updated := up.users["u1"]
	if updated.Status != AccountActive {
		t.Fatalf("expected status AccountActive, got %v", updated.Status)
	}
}

func TestEmailVerificationOTPFlowSuccess(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	cfg := testEmailVerificationConfig(VerificationOTP)
	cfg.EnableIPThrottle = false
	cfg.EnableIdentifierThrottle = false
	engine := newTestEmailVerificationEngine(t, rdb, up, cfg)

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	parts := strings.SplitN(challenge, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected OTP challenge format, got %q", challenge)
	}
	if len(parts[1]) != cfg.OTPDigits {
		t.Fatalf("expected OTP length %d, got %d", cfg.OTPDigits, len(parts[1]))
	}

	if err := engine.ConfirmEmailVerification(ctx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v", err)
	}
}

func TestEmailVerificationUUIDFlowSuccess(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationUUID))

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}
	if _, err := uuid.Parse(challenge); err != nil {
		t.Fatalf("expected UUID challenge, got %q", challenge)
	}

	if err := engine.ConfirmEmailVerification(ctx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v", err)
	}
}

func TestEmailVerificationReplayRejected(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	if err := engine.ConfirmEmailVerification(ctx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification first call failed: %v", err)
	}

	if err := engine.ConfirmEmailVerification(ctx, challenge); !errors.Is(err, ErrEmailVerificationInvalid) {
		t.Fatalf("expected ErrEmailVerificationInvalid on replay, got %v", err)
	}
}

func TestEmailVerificationAttemptsExceeded(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	cfg := testEmailVerificationConfig(VerificationOTP)
	cfg.MaxAttempts = 2
	cfg.EnableIPThrottle = false
	cfg.EnableIdentifierThrottle = false
	engine := newTestEmailVerificationEngine(t, rdb, up, cfg)

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	parts := strings.SplitN(challenge, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected OTP challenge with verificationID prefix, got %q", challenge)
	}
	wrongChallenge := parts[0] + "." + makeDifferentOTP(parts[1])

	err = engine.ConfirmEmailVerification(ctx, wrongChallenge)
	if !errors.Is(err, ErrEmailVerificationInvalid) {
		t.Fatalf("expected ErrEmailVerificationInvalid on first bad attempt, got %v", err)
	}

	err = engine.ConfirmEmailVerification(ctx, wrongChallenge)
	if !errors.Is(err, ErrEmailVerificationAttempts) {
		t.Fatalf("expected ErrEmailVerificationAttempts on max attempt, got %v", err)
	}
}

func TestEmailVerificationEnumerationSafeNoRecordWrite(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge, err := engine.RequestEmailVerification(ctx, "missing@example.com")
	if err != nil {
		t.Fatalf("RequestEmailVerification should be enumeration-safe success, got %v", err)
	}
	if challenge == "" {
		t.Fatal("expected non-empty challenge for enumeration-safe response")
	}

	verificationID, _, parseErr := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
	if parseErr != nil {
		t.Fatalf("expected parseable token challenge, got %v", parseErr)
	}
	if rdb.Exists(ctx, "apv:0:"+verificationID).Val() != 0 {
		t.Fatal("expected no verification record for unknown user")
	}
}

func TestRequireForLoginBlocksLoginForPendingAccount(t *testing.T) {
	cfg := verificationLoginConfig(ModeHybrid)
	hasher := newTestHasher(t)
	pendingUser, err := testPendingUser(hasher)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": pendingUser,
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, _, err = engine.Login(context.Background(), "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("expected ErrAccountUnverified, got %v", err)
	}
}

func TestEmailVerificationSuccessEnablesLogin(t *testing.T) {
	cfg := verificationLoginConfig(ModeHybrid)
	hasher := newTestHasher(t)
	pendingUser, err := testPendingUser(hasher)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": pendingUser,
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, _, err = engine.Login(context.Background(), "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("expected pre-verification login block, got %v", err)
	}

	challenge, err := engine.RequestEmailVerification(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	if err := engine.ConfirmEmailVerification(context.Background(), challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v", err)
	}

	access, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("expected login to succeed after verification, got %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected access and refresh tokens after verification")
	}
}

func TestEmailVerificationStatusChangeIncrementsAccountVersion(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:         "u1",
				Identifier:     "alice",
				TenantID:       "0",
				Status:         AccountPendingVerification,
				AccountVersion: 7,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge, err := engine.RequestEmailVerification(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	before := up.users["u1"].AccountVersion

	if err := engine.ConfirmEmailVerification(ctx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v", err)
	}

	updated := up.users["u1"]
	if updated.Status != AccountActive {
		t.Fatalf("expected status AccountActive, got %v", updated.Status)
	}
	if updated.AccountVersion <= before {
		t.Fatalf("expected AccountVersion to increment, before=%d after=%d", before, updated.AccountVersion)
	}
}

func TestEmailVerificationRequestFailsWhenRedisUnavailable(t *testing.T) {
	mr, rdb := newTestRedis(t)
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}
	engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	mr.Close()

	_, err := engine.RequestEmailVerification(context.Background(), "alice")
	if !errors.Is(err, ErrEmailVerificationUnavailable) {
		t.Fatalf("expected ErrEmailVerificationUnavailable, got %v", err)
	}
}

func TestEmailVerificationStrictModeBlocksPendingAccessImmediately(t *testing.T) {
	cfg := verificationLoginConfig(ModeStrict)
	hasher := newTestHasher(t)
	pendingUser, err := testPendingUser(hasher)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": pendingUser,
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.issueSessionTokens(context.Background(), pendingUser)
	if err != nil {
		t.Fatalf("issueSessionTokens failed: %v", err)
	}

	_, err = engine.Validate(context.Background(), access, ModeInherit)
	if !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("expected strict mode pending account rejection, got %v", err)
	}
}

func TestEmailVerificationJWTOnlyAllowsPendingUntilAccessTTL(t *testing.T) {
	cfg := verificationLoginConfig(ModeJWTOnly)
	hasher := newTestHasher(t)
	pendingUser, err := testPendingUser(hasher)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": pendingUser,
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.issueSessionTokens(context.Background(), pendingUser)
	if err != nil {
		t.Fatalf("issueSessionTokens failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected jwt-only path to continue until token expiry, got %v", err)
	}
}
