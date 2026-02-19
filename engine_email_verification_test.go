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

	_, verificationID, _, err := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
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

	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected tenant:verificationID:code challenge format, got %q", challenge)
	}
	if len(parts[2]) != cfg.OTPDigits {
		t.Fatalf("expected OTP length %d, got %d", cfg.OTPDigits, len(parts[2]))
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
	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected tenant:verificationID:code challenge format, got %q", challenge)
	}
	if _, err := uuid.Parse(parts[2]); err != nil {
		t.Fatalf("expected UUID code segment, got %q", parts[2])
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

	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected tenant:verificationID:code OTP challenge, got %q", challenge)
	}
	wrongChallenge := parts[0] + ":" + parts[1] + ":" + makeDifferentOTP(parts[2])

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

	_, verificationID, _, parseErr := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
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

// --- EV-1: Enumeration resistance table test ---

func TestEmailVerificationEnumerationResistance(t *testing.T) {
	tests := []struct {
		name        string
		status      AccountStatus
		exists      bool
		wantNonEmpty bool
		wantErr     error
	}{
		{
			name:        "not_found",
			exists:      false,
			wantNonEmpty: true,
			wantErr:     nil,
		},
		{
			name:        "active",
			status:      AccountActive,
			exists:      true,
			wantNonEmpty: true,
			wantErr:     nil,
		},
		{
			name:        "pending_verification",
			status:      AccountPendingVerification,
			exists:      true,
			wantNonEmpty: true,
			wantErr:     nil,
		},
		{
			name:        "disabled_returns_fake_challenge",
			status:      AccountDisabled,
			exists:      true,
			wantNonEmpty: true,
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr, rdb := newTestRedis(t)
			defer mr.Close()

			ctx := context.Background()
			up := &mockUserProvider{
				users:        map[string]UserRecord{},
				byIdentifier: map[string]string{},
			}
			if tt.exists {
				up.users["u1"] = UserRecord{
					UserID:         "u1",
					Identifier:     "alice",
					TenantID:       "0",
					Status:         tt.status,
					AccountVersion: 1,
				}
				up.byIdentifier["alice"] = "u1"
			}

			engine := newTestEmailVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

			challenge, err := engine.RequestEmailVerification(ctx, "alice")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNonEmpty && challenge == "" {
				t.Fatal("expected non-empty challenge for enumeration resistance")
			}
		})
	}
}

// --- EV-2: Tenant binding test ---

func TestEmailVerificationTenantBinding(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	// Context tenant is "t_ctx", but user's tenant is "t_user"
	ctx := WithTenantID(context.Background(), "t_ctx")
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:         "u1",
				Identifier:     "alice",
				TenantID:       "t_user",
				Status:         AccountPendingVerification,
				AccountVersion: 1,
			},
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

	// Parse challenge to verify tenant is encoded
	parsedTenant, verificationID, _, parseErr := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
	if parseErr != nil {
		t.Fatalf("parse challenge failed: %v", parseErr)
	}
	if parsedTenant != "t_user" {
		t.Fatalf("expected parsed tenant 't_user', got %q", parsedTenant)
	}

	// Verify record is saved under the user's tenant
	if rdb.Exists(ctx, "apv:t_user:"+verificationID).Val() != 1 {
		t.Fatal("expected verification record key under user tenant 't_user'")
	}
	if rdb.Exists(ctx, "apv:t_ctx:"+verificationID).Val() != 0 {
		t.Fatal("did not expect verification record key under context tenant 't_ctx'")
	}

	// Confirm should succeed even though context tenant differs from stored tenant
	// because the challenge encodes the correct tenant
	confirmCtx := WithTenantID(context.Background(), "t_ctx")
	if err := engine.ConfirmEmailVerification(confirmCtx, challenge); err != nil {
		t.Fatalf("ConfirmEmailVerification failed: %v (should use tenant from challenge, not context)", err)
	}

	updated := up.users["u1"]
	if updated.Status != AccountActive {
		t.Fatalf("expected status AccountActive, got %v", updated.Status)
	}
}

// --- EV-3: ConfirmEmailVerificationCode test ---

func TestEmailVerificationConfirmByCode(t *testing.T) {
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

	// Parse out the verificationID and code from the challenge
	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected tenant:verificationID:code format, got %q", challenge)
	}
	verificationID := parts[1]
	code := parts[2]

	// Use the new preferred API
	if err := engine.ConfirmEmailVerificationCode(ctx, verificationID, code); err != nil {
		t.Fatalf("ConfirmEmailVerificationCode failed: %v", err)
	}

	updated := up.users["u1"]
	if updated.Status != AccountActive {
		t.Fatalf("expected status AccountActive, got %v", updated.Status)
	}
}

func TestEmailVerificationConfirmByCodeTokenStrategy(t *testing.T) {
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

	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected tenant:verificationID:code format, got %q", challenge)
	}
	verificationID := parts[1]
	code := parts[2]

	if err := engine.ConfirmEmailVerificationCode(ctx, verificationID, code); err != nil {
		t.Fatalf("ConfirmEmailVerificationCode (Token) failed: %v", err)
	}

	updated := up.users["u1"]
	if updated.Status != AccountActive {
		t.Fatalf("expected status AccountActive, got %v", updated.Status)
	}
}

// --- EV-4: Parallel confirm attempts (Lua CAS correctness) ---

func TestEmailVerificationParallelConfirmOnlyOneSucceeds(t *testing.T) {
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

	const goroutines = 10
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			results <- engine.ConfirmEmailVerification(ctx, challenge)
		}()
	}

	var successes int
	var failures int
	for i := 0; i < goroutines; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrEmailVerificationInvalid) {
			failures++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successes)
	}
	if failures != goroutines-1 {
		t.Fatalf("expected %d failures, got %d", goroutines-1, failures)
	}
}

// --- EV-3: Challenge format test ---

func TestEmailVerificationChallengeFormat(t *testing.T) {
	strategies := []struct {
		name     string
		strategy VerificationStrategyType
	}{
		{"Token", VerificationToken},
		{"OTP", VerificationOTP},
		{"UUID", VerificationUUID},
	}

	for _, s := range strategies {
		t.Run(s.name, func(t *testing.T) {
			mr, rdb := newTestRedis(t)
			defer mr.Close()

			ctx := WithTenantID(context.Background(), "test_tenant")
			up := &mockUserProvider{
				users: map[string]UserRecord{
					"u1": {UserID: "u1", Identifier: "alice", TenantID: "test_tenant", Status: AccountPendingVerification, AccountVersion: 1},
				},
				byIdentifier: map[string]string{"alice": "u1"},
			}

			cfg := testEmailVerificationConfig(s.strategy)
			cfg.EnableIPThrottle = false
			cfg.EnableIdentifierThrottle = false
			engine := newTestEmailVerificationEngine(t, rdb, up, cfg)

			challenge, err := engine.RequestEmailVerification(ctx, "alice")
			if err != nil {
				t.Fatalf("RequestEmailVerification failed: %v", err)
			}

			// All strategies should produce tenant:verificationID:code
			parts := strings.SplitN(challenge, ":", 3)
			if len(parts) != 3 {
				t.Fatalf("expected tenant:verificationID:code format, got %q", challenge)
			}

			if parts[0] != "test_tenant" {
				t.Fatalf("expected tenant 'test_tenant', got %q", parts[0])
			}
			if parts[1] == "" {
				t.Fatal("expected non-empty verificationID")
			}
			if parts[2] == "" {
				t.Fatal("expected non-empty code")
			}
		})
	}
}
