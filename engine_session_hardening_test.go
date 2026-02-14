package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	authjwt "github.com/MrEthical07/goAuth/jwt"
	gjwt "github.com/golang-jwt/jwt/v5"
)

func newHardeningUserProvider(t *testing.T) *mockUserProvider {
	t.Helper()

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	return &mockUserProvider{
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
			"u2": {
				UserID:            "u2",
				Identifier:        "bob",
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
			"bob":   "u2",
		},
		totpRecords: map[string]TOTPRecord{},
	}
}

func TestSessionHardeningMaxSessionsPerUserEnforced(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 1
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("expected ErrSessionLimitExceeded, got %v", err)
	}
}

func TestSessionHardeningMaxSessionsPerTenantEnforced(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.MaxSessionsPerTenant = 1
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	if _, _, err := engine.Login(context.Background(), "bob", "correct-password-123"); !errors.Is(err, ErrTenantSessionLimitExceeded) {
		t.Fatalf("expected ErrTenantSessionLimitExceeded, got %v", err)
	}
}

func TestSessionHardeningSingleSessionModeReplacesPriorSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	up := newHardeningUserProvider(t)

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, refresh1, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	sid1, _, err := internal.DecodeRefreshToken(refresh1)
	if err != nil {
		t.Fatalf("decode refresh1 failed: %v", err)
	}

	_, refresh2, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("second login failed: %v", err)
	}
	sid2, _, err := internal.DecodeRefreshToken(refresh2)
	if err != nil {
		t.Fatalf("decode refresh2 failed: %v", err)
	}
	if sid1 == sid2 {
		t.Fatal("expected new session id after second login")
	}

	if exists := rdb.Exists(context.Background(), "as:0:"+sid1).Val(); exists != 0 {
		t.Fatal("expected first session to be removed in single-session mode")
	}
	if exists := rdb.Exists(context.Background(), "as:0:"+sid2).Val(); exists != 1 {
		t.Fatal("expected second session to exist in single-session mode")
	}
}

func TestSessionHardeningConcurrentLoginLimitEnforced(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.ConcurrentLoginLimit = 1
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("expected ErrSessionLimitExceeded, got %v", err)
	}
}

func TestSessionHardeningReplayMetricIncrements(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Metrics.Enabled = true
	cfg.SessionHardening.EnableReplayTracking = true
	up := newHardeningUserProvider(t)

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	if _, _, err := engine.Refresh(context.Background(), refresh); err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if _, _, err := engine.Refresh(context.Background(), refresh); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("expected ErrRefreshReuse on replay, got %v", err)
	}

	if got := engine.metrics.Value(MetricReplayDetected); got != 1 {
		t.Fatalf("expected MetricReplayDetected=1, got %d", got)
	}
	if v := rdb.Get(context.Background(), "arp:"+sid).Val(); v != "1" {
		t.Fatalf("expected replay counter key value 1, got %q", v)
	}
}

func TestSessionHardeningClockSkewRejectsFarFutureToken(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false
	cfg.SessionHardening.MaxClockSkew = 30 * time.Second
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	token, err := signManualAccessTokenHS256(cfg.JWT.PrivateKey, time.Now().Add(2*time.Minute), time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), token, ModeInherit); !errors.Is(err, ErrTokenClockSkew) {
		t.Fatalf("expected ErrTokenClockSkew, got %v", err)
	}
}

func TestSessionHardeningClockSkewAcceptsWithinTolerance(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false
	cfg.SessionHardening.MaxClockSkew = 30 * time.Second
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	token, err := signManualAccessTokenHS256(cfg.JWT.PrivateKey, time.Now().Add(10*time.Second), time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), token, ModeInherit); err != nil {
		t.Fatalf("expected validation success within skew tolerance, got %v", err)
	}
}

func TestSessionHardeningValidateNoProviderCallsRegression(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.SessionHardening.MaxClockSkew = 30 * time.Second
	cfg.SessionHardening.MaxSessionsPerUser = 1
	cfg.SessionHardening.MaxSessionsPerTenant = 2
	cfg.SessionHardening.ConcurrentLoginLimit = 1
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	up.getByIdentifierCalls = 0
	up.getByIDCalls = 0
	up.createCalls = 0
	up.updatePasswordCalls = 0
	up.updateStatusCalls = 0

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if up.getByIdentifierCalls != 0 || up.getByIDCalls != 0 || up.createCalls != 0 || up.updatePasswordCalls != 0 || up.updateStatusCalls != 0 {
		t.Fatalf("expected validate to avoid provider calls, got counts: %+v", *up)
	}
}

func signManualAccessTokenHS256(secret []byte, issuedAt time.Time, exp time.Time) (string, error) {
	claims := authjwt.AccessClaims{
		UID: "u1",
		TID: 0,
		SID: "manual-session",
		RegisteredClaims: gjwt.RegisteredClaims{
			ExpiresAt: gjwt.NewNumericDate(exp),
			IssuedAt:  gjwt.NewNumericDate(issuedAt),
		},
	}
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}
