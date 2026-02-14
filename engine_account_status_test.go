package goAuth

import (
	"context"
	"errors"
	"testing"

	"github.com/MrEthical07/goAuth/internal"
)

func newStatusEngine(
	t *testing.T,
	status AccountStatus,
	mode ValidationMode,
) (*Engine, *mockUserProvider, func()) {
	t.Helper()

	cfg := accountTestConfig()
	cfg.ValidationMode = mode
	if mode == ModeJWTOnly {
		cfg.Security.EnableAccountVersionCheck = false
	}

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "0",
				PasswordHash:      hash,
				Status:            status,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	return engine, up, done
}

func TestAccountStatusDisabledCannotLogin(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountDisabled, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}
}

func TestAccountStatusLockedCannotLogin(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountLocked, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}

func TestAccountStatusDeletedCannotLogin(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountDeleted, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if !errors.Is(err, ErrAccountDeleted) {
		t.Fatalf("expected ErrAccountDeleted, got %v", err)
	}
}

func TestDisableAccountInvalidatesExistingSessions(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount failed: %v", err)
	}

	_, err = engine.sessionStore.Get(context.Background(), "0", sid, engine.sessionLifetime())
	if err == nil {
		t.Fatal("expected session to be invalidated after disable")
	}
}

func TestLockAccountInvalidatesExistingSessions(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	if err := engine.LockAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	_, err = engine.sessionStore.Get(context.Background(), "0", sid, engine.sessionLifetime())
	if err == nil {
		t.Fatal("expected session to be invalidated after lock")
	}
}

func TestRefreshBlockedAfterDisable(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount failed: %v", err)
	}

	_, _, err = engine.Refresh(context.Background(), refresh)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after disable invalidation, got %v", err)
	}
}

func TestStrictModeBlocksImmediatelyAfterDisable(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeStrict)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount failed: %v", err)
	}

	_, err = engine.Validate(context.Background(), access, ModeInherit)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected strict validation to fail immediately, got %v", err)
	}
}

func TestJWTOnlyModeAllowsUntilTTLAfterDisable(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeJWTOnly)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount failed: %v", err)
	}

	_, err = engine.Validate(context.Background(), access, ModeInherit)
	if err != nil {
		t.Fatalf("expected jwt-only validation to continue until token expiry, got %v", err)
	}
}

func TestAccountStatusUpdateIncrementsAccountVersion(t *testing.T) {
	engine, up, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	before := up.users["u1"].AccountVersion

	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount failed: %v", err)
	}

	after := up.users["u1"].AccountVersion
	if after <= before {
		t.Fatalf("expected AccountVersion to increment, before=%d after=%d", before, after)
	}
	if up.users["u1"].Status != AccountDisabled {
		t.Fatalf("expected status disabled, got %v", up.users["u1"].Status)
	}
}

func TestValidateHotPathDoesNotCallProvider(t *testing.T) {
	engine, up, done := newStatusEngine(t, AccountActive, ModeStrict)
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

	_, err = engine.Validate(context.Background(), access, ModeInherit)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if up.getByIdentifierCalls != 0 || up.getByIDCalls != 0 || up.createCalls != 0 || up.updatePasswordCalls != 0 || up.updateStatusCalls != 0 {
		t.Fatalf("expected validate to avoid provider calls, got counts: %+v", *up)
	}
}

func TestStatusChangeMustAdvanceAccountVersion(t *testing.T) {
	engine, up, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	up.skipStatusVersionBump = true

	err := engine.DisableAccount(context.Background(), "u1")
	if !errors.Is(err, ErrAccountVersionNotAdvanced) {
		t.Fatalf("expected ErrAccountVersionNotAdvanced, got %v", err)
	}
}
