package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

func newCreateAccountEngine(t *testing.T, cfg Config, up UserProvider) (*Engine, *redis.Client, func()) {
	t.Helper()

	mr, rdb := newTestRedis(t)

	builder := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{
			"member": {},
			"admin":  {"perm.read"},
		}).
		WithUserProvider(up)

	engine, err := builder.Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}

	return engine, rdb, func() { mr.Close() }
}

func accountTestConfig() Config {
	cfg := defaultConfig()
	cfg.JWT.SigningMethod = "hs256"
	cfg.JWT.PrivateKey = []byte("test-secret")
	cfg.Account.Enabled = true
	cfg.Account.AutoLogin = false
	cfg.Account.EnableIPThrottle = true
	cfg.Account.EnableIdentifierThrottle = true
	cfg.Account.AccountCreationMaxAttempts = 5
	cfg.Account.AccountCreationCooldown = time.Minute
	cfg.Account.DefaultRole = "member"
	cfg.Account.AllowDuplicateIdentifierAcrossTenants = false
	cfg.Security.MaxLoginAttempts = 5
	cfg.Security.LoginCooldownDuration = time.Minute
	return cfg
}

func TestCreateAccountSuccess(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "alice",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if res.UserID == "" {
		t.Fatal("expected created user id")
	}
	if res.Role != "member" {
		t.Fatalf("expected role member, got %s", res.Role)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("expected no tokens when AutoLogin is disabled")
	}

	created := up.users[res.UserID]
	if created.PasswordHash == "" || created.PasswordHash == "new-password-123" {
		t.Fatal("expected stored password to be hashed")
	}
	ok, err := engine.passwordHash.Verify("new-password-123", created.PasswordHash)
	if err != nil || !ok {
		t.Fatalf("expected stored hash to verify, ok=%v err=%v", ok, err)
	}
}

func TestCreateAccountDuplicateRejected(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:       "u1",
				Identifier:   "alice",
				TenantID:     "0",
				PasswordHash: "x",
				Role:         "member",
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "alice",
		Password:   "new-password-123",
	})
	if !errors.Is(err, ErrAccountExists) {
		t.Fatalf("expected ErrAccountExists, got %v", err)
	}
}

func TestCreateAccountDefaultRoleApplied(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "bob",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if res.Role != cfg.Account.DefaultRole {
		t.Fatalf("expected default role %s, got %s", cfg.Account.DefaultRole, res.Role)
	}
}

func TestCreateAccountExplicitRoleOverride(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "charlie",
		Password:   "new-password-123",
		Role:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if res.Role != "admin" {
		t.Fatalf("expected role admin, got %s", res.Role)
	}
}

func TestCreateAccountInvalidRoleRejected(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "dana",
		Password:   "new-password-123",
		Role:       "missing-role",
	})
	if !errors.Is(err, ErrAccountRoleInvalid) {
		t.Fatalf("expected ErrAccountRoleInvalid, got %v", err)
	}
}

func TestCreateAccountAutoLoginIssuesTokens(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AutoLogin = true
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "eve",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens in auto-login mode")
	}

	sid, _, err := internal.DecodeRefreshToken(res.RefreshToken)
	if err != nil {
		t.Fatalf("failed to decode refresh token: %v", err)
	}
	if exists := rdb.Exists(context.Background(), "as:0:"+sid).Val(); exists != 1 {
		t.Fatal("expected session key to exist for auto-login")
	}
}

func TestCreateAccountAutoLoginFalseNoTokens(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AutoLogin = false
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "frank",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("expected no tokens when AutoLogin is disabled")
	}
}

func TestCreateAccountRateLimitEnforced(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AccountCreationMaxAttempts = 1
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := WithClientIP(context.Background(), "203.0.113.9")
	if _, err := engine.CreateAccount(ctx, CreateAccountRequest{
		Identifier: "g1",
		Password:   "new-password-123",
	}); err != nil {
		t.Fatalf("first account create should succeed, got %v", err)
	}

	_, err := engine.CreateAccount(ctx, CreateAccountRequest{
		Identifier: "g2",
		Password:   "new-password-123",
	})
	if !errors.Is(err, ErrAccountCreationRateLimited) {
		t.Fatalf("expected ErrAccountCreationRateLimited, got %v", err)
	}
}

func TestCreateAccountInvalidInputDoesNotConsumeLimiter(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AccountCreationMaxAttempts = 1
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := WithClientIP(context.Background(), "203.0.113.10")
	_, err := engine.CreateAccount(ctx, CreateAccountRequest{
		Identifier: "",
		Password:   "new-password-123",
	})
	if !errors.Is(err, ErrAccountCreationInvalid) {
		t.Fatalf("expected ErrAccountCreationInvalid, got %v", err)
	}

	_, err = engine.CreateAccount(ctx, CreateAccountRequest{
		Identifier: "valid-user",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("expected valid request to pass limiter after invalid input, got %v", err)
	}
}

func TestCreateAccountMultiTenantSeparation(t *testing.T) {
	cfg := accountTestConfig()
	cfg.MultiTenant.Enabled = true
	cfg.Account.AllowDuplicateIdentifierAcrossTenants = true
	up := &mockUserProvider{
		users:                       map[string]UserRecord{},
		byIdentifier:                map[string]string{},
		allowDuplicateAcrossTenants: true,
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctxTenantA := WithTenantID(context.Background(), "t1")
	ctxTenantB := WithTenantID(context.Background(), "t2")

	_, err := engine.CreateAccount(ctxTenantA, CreateAccountRequest{
		Identifier: "same-id",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("tenant A create failed: %v", err)
	}

	_, err = engine.CreateAccount(ctxTenantB, CreateAccountRequest{
		Identifier: "same-id",
		Password:   "new-password-123",
	})
	if err != nil {
		t.Fatalf("tenant B create failed: %v", err)
	}
}

func TestCreateAccountRedisUnavailable(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	done()

	_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "harry",
		Password:   "new-password-123",
	})
	if !errors.Is(err, ErrAccountCreationUnavailable) {
		t.Fatalf("expected ErrAccountCreationUnavailable, got %v", err)
	}
}

func TestCreateAccountAutoLoginSessionFailureReturnsTypedError(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AutoLogin = true
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	mrDead, deadRedis := newTestRedis(t)
	mrDead.Close()
	engine.sessionStore = session.NewStore(deadRedis, "as", false, false, 0)

	res, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "kate",
		Password:   "new-password-123",
	})
	if res == nil || res.UserID == "" {
		t.Fatalf("expected account to be created before session failure, got result=%v", res)
	}
	if !errors.Is(err, ErrSessionCreationFailed) {
		t.Fatalf("expected ErrSessionCreationFailed, got %v", err)
	}
}

func TestCreateAccountProviderErrorPropagation(t *testing.T) {
	cfg := accountTestConfig()
	providerErr := errors.New("db write failed")
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
		createErr:    providerErr,
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "ivy",
		Password:   "new-password-123",
	})
	if !errors.Is(err, providerErr) {
		t.Fatalf("expected provider error propagation, got %v", err)
	}
}

func TestCreateAccountPasswordTooShortRejected(t *testing.T) {
	cfg := accountTestConfig()
	up := &mockUserProvider{
		users:        map[string]UserRecord{},
		byIdentifier: map[string]string{},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "jane",
		Password:   "short",
	})
	if !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("expected ErrPasswordPolicy, got %v", err)
	}
}
