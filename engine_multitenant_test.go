package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
)

// tenantMockProvider is a UserProvider that also implements
// TenantAwareUserProvider. Records are keyed by (tenant, identifier) so the
// same email can exist in two tenants, which is the exact shape the
// isolation tests need.
type tenantMockProvider struct {
	mockUserProvider

	// tenantOf maps userID -> tenantID for the id lookups.
	tenantOf map[string]string

	tenantIdentifierCalls int
	tenantIDCalls         int

	// lastTenantArg records the tenant the engine last scoped a lookup to.
	lastTenantArg string

	// ignoreTenantScope simulates a provider that implements the interface
	// but ignores the tenant argument, so tests can reach the engine-side
	// backstop guard rather than only the provider's own scoping.
	ignoreTenantScope bool
}

func newTenantMockProvider() *tenantMockProvider {
	return &tenantMockProvider{
		mockUserProvider: mockUserProvider{
			users:        make(map[string]UserRecord),
			byIdentifier: make(map[string]string),
			totpRecords:  make(map[string]TOTPRecord),
			backupCodes:  make(map[string][]BackupCodeRecord),
		},
		tenantOf: make(map[string]string),
	}
}

// addUser registers a record under a specific tenant. It also populates the
// plain identifier key the inherited tenant-blind lookup reads, so the same
// provider can serve both the legacy and tenant-scoped paths. The plain key
// keeps the first registration, which is what makes the tenant-blind lookup
// resolve a foreign tenant's user — the bug the guards exist to stop.
func (p *tenantMockProvider) addUser(user UserRecord) {
	p.users[user.UserID] = user
	p.byIdentifier[tenantIdentifierKey(user.TenantID, user.Identifier)] = user.UserID
	if _, exists := p.byIdentifier[user.Identifier]; !exists {
		p.byIdentifier[user.Identifier] = user.UserID
	}
	p.tenantOf[user.UserID] = user.TenantID
}

func tenantIdentifierKey(tenantID, identifier string) string {
	return tenantID + "\x00" + identifier
}

func (p *tenantMockProvider) GetUserByIdentifierInTenant(ctx context.Context, tenantID, identifier string) (UserRecord, error) {
	p.tenantIdentifierCalls++
	p.lastTenantArg = tenantID

	if p.ignoreTenantScope {
		// Deliberately tenant-blind: resolve via the plain index the way a
		// broken implementation would.
		userID, ok := p.byIdentifier[identifier]
		if !ok {
			return UserRecord{}, errors.New("not found")
		}
		return p.users[userID], nil
	}

	userID, ok := p.byIdentifier[tenantIdentifierKey(tenantID, identifier)]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}
	user, ok := p.users[userID]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}
	return user, nil
}

func (p *tenantMockProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	p.tenantIDCalls++
	p.lastTenantArg = tenantID

	user, ok := p.users[userID]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}
	if user.TenantID != tenantID {
		return UserRecord{}, errors.New("not found")
	}
	return user, nil
}

// legacyOnlyProvider implements UserProvider but deliberately NOT
// TenantAwareUserProvider, to exercise the Build-time capability check. It
// cannot embed mockUserProvider, which now carries the tenant-aware methods
// and would satisfy the interface by promotion.
type legacyOnlyProvider struct{}

func (legacyOnlyProvider) GetUserByIdentifier(identifier string) (UserRecord, error) {
	return UserRecord{}, errors.New("not found")
}

func (legacyOnlyProvider) GetUserByID(userID string) (UserRecord, error) {
	return UserRecord{}, errors.New("not found")
}

func (legacyOnlyProvider) UpdatePasswordHash(userID string, newHash string) error { return nil }

func (legacyOnlyProvider) CreateUser(ctx context.Context, input CreateUserInput) (UserRecord, error) {
	return UserRecord{}, errors.New("not implemented")
}

func (legacyOnlyProvider) UpdateAccountStatus(ctx context.Context, userID string, status AccountStatus) (UserRecord, error) {
	return UserRecord{}, errors.New("not implemented")
}

func (legacyOnlyProvider) GetTOTPSecret(ctx context.Context, userID string) (*TOTPRecord, error) {
	return nil, errors.New("not implemented")
}

func (legacyOnlyProvider) EnableTOTP(ctx context.Context, userID string, secret []byte) error {
	return nil
}

func (legacyOnlyProvider) DisableTOTP(ctx context.Context, userID string) error { return nil }

func (legacyOnlyProvider) MarkTOTPVerified(ctx context.Context, userID string) error { return nil }

func (legacyOnlyProvider) UpdateTOTPLastUsedCounter(ctx context.Context, userID string, counter int64) error {
	return nil
}

func (legacyOnlyProvider) GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error) {
	return nil, nil
}

func (legacyOnlyProvider) ReplaceBackupCodes(ctx context.Context, userID string, codes []BackupCodeRecord) error {
	return nil
}

func (legacyOnlyProvider) ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error) {
	return false, nil
}

// Compile-time assertions pinning the capability split this design rests on.
var (
	_ UserProvider            = legacyOnlyProvider{}
	_ TenantAwareUserProvider = (*tenantMockProvider)(nil)
)

// collectingSink records events synchronously so a test can assert on the
// audit trail without racing the dispatcher.
type collectingSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *collectingSink) Emit(_ context.Context, event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *collectingSink) find(eventType, reason string) *AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		event := s.events[i]
		if event.EventType != eventType {
			continue
		}
		if reason == "" || event.Metadata["reason"] == reason {
			found := s.events[i]
			return &found
		}
	}
	return nil
}

// newTenantLoginEngine builds a multi-tenant engine holding the SAME
// identifier in two tenants with different passwords, the exact setup the
// cross-tenant credential attack needs.
func newTenantLoginEngine(t *testing.T) (*Engine, *tenantMockProvider, *collectingSink, func()) {
	t.Helper()

	mr, rdb := newTestRedis(t)

	hasher := newTestHasher(t)
	hashA, err := hasher.Hash("tenant-a-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	hashB, err := hasher.Hash("tenant-b-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := newTenantMockProvider()
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

	cfg := accountTestConfig()
	cfg.MultiTenant.Enabled = true
	cfg.Audit.Enabled = true

	sink := &collectingSink{}
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		WithAuditSink(sink).
		Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}

	return engine, up, sink, func() { mr.Close() }
}

// The same email in two tenants must resolve to that tenant's own account.
func TestLoginResolvesPerTenantUser(t *testing.T) {
	engine, _, _, done := newTenantLoginEngine(t)
	defer done()

	ctxA := WithTenantID(context.Background(), "tenant-a")
	access, _, err := engine.Login(ctxA, "shared@example.com", "tenant-a-password-123")
	if err != nil {
		t.Fatalf("tenant-A login failed: %v", err)
	}
	claims, err := engine.ValidateAccess(ctxA, access)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if claims.UserID != "user-a" {
		t.Fatalf("tenant-A login issued a token for %q, want user-a", claims.UserID)
	}
	if claims.TenantID != "tenant-a" {
		t.Fatalf("token stamped tenant %q, want tenant-a", claims.TenantID)
	}

	ctxB := WithTenantID(context.Background(), "tenant-b")
	access, _, err = engine.Login(ctxB, "shared@example.com", "tenant-b-password-123")
	if err != nil {
		t.Fatalf("tenant-B login failed: %v", err)
	}
	claims, err = engine.ValidateAccess(ctxB, access)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if claims.UserID != "user-b" {
		t.Fatalf("tenant-B login issued a token for %q, want user-b", claims.UserID)
	}
}

// The core cross-tenant credential attack: tenant-A credentials presented
// against tenant-B's context must not authenticate.
func TestLoginRejectsCrossTenantCredentials(t *testing.T) {
	engine, _, _, done := newTenantLoginEngine(t)
	defer done()

	ctxB := WithTenantID(context.Background(), "tenant-b")
	access, refresh, err := engine.Login(ctxB, "shared@example.com", "tenant-a-password-123")
	if err == nil {
		t.Fatal("tenant-A password authenticated under tenant-B context")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected the generic invalid-credentials error, got %v", err)
	}
	if access != "" || refresh != "" {
		t.Fatal("tokens were issued for a rejected cross-tenant login")
	}
}

// A user that exists only in another tenant must be indistinguishable from
// one that does not exist at all.
func TestLoginCrossTenantIsIndistinguishableFromUnknownUser(t *testing.T) {
	engine, _, _, done := newTenantLoginEngine(t)
	defer done()

	ctxC := WithTenantID(context.Background(), "tenant-c")

	_, _, foreignErr := engine.Login(ctxC, "shared@example.com", "tenant-a-password-123")
	_, _, unknownErr := engine.Login(ctxC, "nobody@example.com", "tenant-a-password-123")

	if foreignErr == nil || unknownErr == nil {
		t.Fatal("expected both logins to fail")
	}
	if foreignErr.Error() != unknownErr.Error() {
		t.Fatalf("cross-tenant login is distinguishable from an unknown user: %q vs %q",
			foreignErr.Error(), unknownErr.Error())
	}
}

// The rejection must still be visible to defenders, recorded against the
// context tenant.
func TestLoginCrossTenantAuditsTenantMismatch(t *testing.T) {
	engine, up, sink, done := newTenantLoginEngine(t)
	defer done()

	// Force the mismatch through the backstop guard by making the
	// tenant-scoped lookup misbehave the way a buggy provider would.
	up.ignoreTenantScope = true

	ctxB := WithTenantID(context.Background(), "tenant-b")
	if _, _, err := engine.Login(ctxB, "shared@example.com", "tenant-a-password-123"); err == nil {
		t.Fatal("expected the login to be rejected")
	}

	engine.Close()

	event := sink.find(auditEventLoginFailure, "tenant_mismatch")
	if event == nil {
		t.Fatal("no login failure audited with reason tenant_mismatch")
	}
	if event.TenantID != "tenant-b" {
		t.Fatalf("rejection audited against tenant %q, want the context tenant tenant-b", event.TenantID)
	}
}

func newMultiTenantBuilder(t *testing.T, rdb *redis.Client, up UserProvider) *Builder {
	t.Helper()

	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = true
	cfg.Audit.Enabled = false

	return New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"read", "write"}).
		WithRoles(map[string][]string{"member": {"read"}}).
		WithUserProvider(up)
}

func TestBuildFailsWhenMultiTenantEnabledWithoutTenantAwareProvider(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	_, err := newMultiTenantBuilder(t, rdb, legacyOnlyProvider{}).Build()
	if err == nil {
		t.Fatal("Build succeeded with a tenant-blind provider while MultiTenant is enabled; " +
			"this would silently resolve identifiers across tenants")
	}
	if !strings.Contains(err.Error(), "TenantAwareUserProvider") {
		t.Fatalf("error should name the missing interface, got: %v", err)
	}
}

func TestBuildSucceedsWhenMultiTenantEnabledWithTenantAwareProvider(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	engine, err := newMultiTenantBuilder(t, rdb, newTenantMockProvider()).Build()
	if err != nil {
		t.Fatalf("Build failed with a tenant-aware provider: %v", err)
	}
	if !engine.tenantScopedLookup() {
		t.Fatal("engine did not enable tenant-scoped lookup with MultiTenant enabled")
	}
}

// A tenant-blind provider must remain valid when multi-tenancy is off; this
// is the v0.4.0 compatibility contract for existing single-tenant consumers.
func TestBuildAllowsLegacyProviderWhenMultiTenantDisabled(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = false
	cfg.Audit.Enabled = false

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"read", "write"}).
		WithRoles(map[string][]string{"member": {"read"}}).
		WithUserProvider(legacyOnlyProvider{}).
		Build()
	if err != nil {
		t.Fatalf("Build failed for a single-tenant deployment with a legacy provider: %v", err)
	}
	if engine.tenantScopedLookup() {
		t.Fatal("tenant-scoped lookup must stay off when MultiTenant is disabled")
	}
}

// Even when the provider happens to implement the tenant-aware interface,
// leaving MultiTenant disabled must keep the legacy lookup path.
func TestTenantScopedLookupStaysOffWhenMultiTenantDisabled(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = false
	cfg.Audit.Enabled = false

	up := newTenantMockProvider()
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"read", "write"}).
		WithRoles(map[string][]string{"member": {"read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	up.addUser(UserRecord{UserID: "u1", Identifier: "alice@example.com", TenantID: "tenant-a"})

	if _, err := engine.lookupUserByIdentifier(context.Background(), "alice@example.com"); err != nil {
		t.Fatalf("legacy lookup failed: %v", err)
	}
	if up.tenantIdentifierCalls != 0 {
		t.Fatalf("tenant-aware lookup was used with MultiTenant disabled (%d calls)", up.tenantIdentifierCalls)
	}
	if up.getByIdentifierCalls != 1 {
		t.Fatalf("expected 1 legacy lookup, got %d", up.getByIdentifierCalls)
	}
}

func TestTenantScopedLookupUsesContextTenant(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	up := newTenantMockProvider()
	engine, err := newMultiTenantBuilder(t, rdb, up).Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	up.addUser(UserRecord{UserID: "ua", Identifier: "shared@example.com", TenantID: "tenant-a"})
	up.addUser(UserRecord{UserID: "ub", Identifier: "shared@example.com", TenantID: "tenant-b"})

	ctx := WithTenantID(context.Background(), "tenant-b")
	user, err := engine.lookupUserByIdentifier(ctx, "shared@example.com")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if user.UserID != "ub" {
		t.Fatalf("resolved the wrong tenant's user: got %q, want %q", user.UserID, "ub")
	}
	if up.lastTenantArg != "tenant-b" {
		t.Fatalf("lookup scoped to %q, want %q", up.lastTenantArg, "tenant-b")
	}
	if up.getByIdentifierCalls != 0 {
		t.Fatalf("tenant-blind lookup was used while MultiTenant is enabled (%d calls)", up.getByIdentifierCalls)
	}
}

func TestTenantScopedIDLookupRejectsForeignTenant(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	up := newTenantMockProvider()
	engine, err := newMultiTenantBuilder(t, rdb, up).Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	up.addUser(UserRecord{UserID: "ua", Identifier: "alice@example.com", TenantID: "tenant-a"})

	ctx := WithTenantID(context.Background(), "tenant-b")
	if _, err := engine.lookupUserByID(ctx, "ua"); err == nil {
		t.Fatal("tenant-B context resolved a tenant-A user by ID")
	}
}
