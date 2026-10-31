package goAuth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const (
	extGoogleClient = "web-client.apps.googleusercontent.com"
	extAppleClient  = "com.example.app"
	extKid          = "kid-1"
	extPassword     = "correct-password-123"
)

// extIdP is a local identity provider: a TLS key server and a token signer.
// Tests never touch the network.
type extIdP struct {
	t      testing.TB
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	mu           sync.Mutex
	fail         bool
	cacheControl string
	fetches      atomic.Int64
}

func newExtIdP(t testing.TB) *extIdP {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	idp := &extIdP{t: t, rsaKey: rk, ecKey: ek, cacheControl: "public, max-age=3600"}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.server.Close)
	return idp
}

func (i *extIdP) url() string { return i.server.URL + "/certs" }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (i *extIdP) serve(w http.ResponseWriter, r *http.Request) {
	i.fetches.Add(1)
	i.mu.Lock()
	fail, cc := i.fail, i.cacheControl
	i.mu.Unlock()
	if fail {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	e := make([]byte, 0, 4)
	for v := i.rsaKey.PublicKey.E; v > 0; v >>= 8 {
		e = append([]byte{byte(v)}, e...)
	}
	point, err := i.ecKey.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	set := map[string]interface{}{"keys": []interface{}{
		map[string]interface{}{"kty": "RSA", "kid": extKid, "use": "sig", "alg": "RS256", "n": b64u(i.rsaKey.PublicKey.N.Bytes()), "e": b64u(e)},
		map[string]interface{}{
			"kty": "EC", "kid": "ec-1", "use": "sig", "alg": "ES256", "crv": "P-256",
			"x": b64u(point[1:33]), "y": b64u(point[33:65]),
		},
	}}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (i *extIdP) setFail(v bool) {
	i.mu.Lock()
	i.fail = v
	i.mu.Unlock()
}

// extTokenSpec describes one ID token a test wants.
type extTokenSpec struct {
	provider string // config name; selects issuer and audience
	sub      string
	email    string
	verified interface{} // bool or string; nil omits the claim
	private  interface{}
	nonce    string // what the server issued; the token carries it (or its hash) unless overridden
	hashed   bool
	mutate   func(jwt.MapClaims)
	alg      string // "RS256" (default) or "ES256"
}

// extNonce returns a fresh random server nonce.
func extNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// token signs an ID token. It returns the token and the nonce the server
// would have issued.
func (i *extIdP) token(spec extTokenSpec) (string, string) {
	i.t.Helper()
	if spec.provider == "" {
		spec.provider = "google"
	}
	if spec.nonce == "" {
		spec.nonce = extNonce()
	}
	issuer, aud := "https://accounts.google.com", extGoogleClient
	switch spec.provider {
	case "apple":
		issuer, aud = "https://appleid.apple.com", extAppleClient
	case "corp":
		issuer, aud = "https://sso.example.test", "corp-client"
	}
	now := time.Now()
	tokenNonce := spec.nonce
	if spec.hashed {
		sum := sha256Hex(spec.nonce)
		tokenNonce = sum
	}
	claims := jwt.MapClaims{
		"iss": issuer, "aud": aud, "sub": spec.sub,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"nonce": tokenNonce,
	}
	if spec.email != "" {
		claims["email"] = spec.email
	}
	if spec.verified != nil {
		claims["email_verified"] = spec.verified
	}
	if spec.private != nil {
		claims["is_private_email"] = spec.private
	}
	if spec.mutate != nil {
		spec.mutate(claims)
	}
	var tok *jwt.Token
	var key interface{}
	if spec.alg == "ES256" {
		tok = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["kid"] = "ec-1"
		key = i.ecKey
	} else {
		tok = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = extKid
		key = i.rsaKey
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		i.t.Fatalf("sign: %v", err)
	}
	return signed, spec.nonce
}

func sha256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// extMockProvider
// ---------------------------------------------------------------------------

type extLink struct {
	userID   string
	identity ExternalIdentity
}

// extMockProvider is a tenant-aware user provider that also implements
// ExternalIdentityProvider with the uniqueness the contract demands:
// (tenant, provider, subject) and (tenant, identifier) are each unique, and a
// creation is atomic.
type extMockProvider struct {
	tenantMockProvider

	emu    sync.Mutex
	links  map[string]extLink
	nextID int

	// ignoreLinkTenant makes identity lookups ignore the tenant, the way a
	// provider that forgot the WHERE clause would.
	ignoreLinkTenant bool
	// beforeCreate runs at the start of CreateUserWithExternalIdentity, before
	// the uniqueness checks, to stage a concurrent winner.
	beforeCreate func(p *extMockProvider)
	// errors injected into the identity methods
	getErr, createErr, linkErr, listErr, unlinkErr error
	// identifierErr, when set, fails the by-identifier lookups (an outage).
	identifierErr error
	// idErr, when set, fails the by-ID lookups (an outage).
	idErr error

	gets, creates, linksMade, unlinks, lists int
	lastCreate                               CreateUserInput
	lastIdentity                             ExternalIdentity
}

func newExtMockProvider() *extMockProvider {
	return &extMockProvider{tenantMockProvider: *newTenantMockProvider(), links: map[string]extLink{}}
}

func extKey(tenant, provider, subject string) string {
	return tenant + "\x00" + provider + "\x00" + subject
}

// Locked wrappers: tests that run sign-ins concurrently reach these.
func (p *extMockProvider) GetUserByIdentifier(identifier string) (UserRecord, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	if p.identifierErr != nil {
		return UserRecord{}, p.identifierErr
	}
	user, err := p.tenantMockProvider.GetUserByIdentifier(identifier)
	if err != nil {
		return UserRecord{}, ErrUserNotFound
	}
	return user, nil
}

func (p *extMockProvider) GetUserByID(userID string) (UserRecord, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	if p.idErr != nil {
		return UserRecord{}, p.idErr
	}
	user, err := p.tenantMockProvider.GetUserByID(userID)
	if err != nil {
		return UserRecord{}, ErrUserNotFound
	}
	return user, nil
}

func (p *extMockProvider) GetUserByIdentifierInTenant(ctx context.Context, tenantID, identifier string) (UserRecord, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	if p.identifierErr != nil {
		return UserRecord{}, p.identifierErr
	}
	user, err := p.tenantMockProvider.GetUserByIdentifierInTenant(ctx, tenantID, identifier)
	if err != nil {
		return UserRecord{}, ErrUserNotFound
	}
	return user, nil
}

func (p *extMockProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	if p.idErr != nil {
		return UserRecord{}, p.idErr
	}
	user, err := p.tenantMockProvider.GetUserByIDInTenant(ctx, tenantID, userID)
	if err != nil {
		// A provider returns ErrUserNotFound for a missing user; the engine
		// reports any other error as an outage.
		return UserRecord{}, ErrUserNotFound
	}
	return user, nil
}

func (p *extMockProvider) GetUserByExternalIdentity(ctx context.Context, tenantID, provider, subject string) (UserRecord, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	p.gets++
	if p.getErr != nil {
		return UserRecord{}, p.getErr
	}
	link, ok := p.links[extKey(tenantID, provider, subject)]
	if !ok && p.ignoreLinkTenant {
		for k, l := range p.links {
			if strings.HasSuffix(k, "\x00"+provider+"\x00"+subject) {
				link, ok = l, true
				break
			}
		}
	}
	if !ok {
		return UserRecord{}, ErrUserNotFound
	}
	user, ok := p.users[link.userID]
	if !ok {
		return UserRecord{}, ErrUserNotFound
	}
	return user, nil
}

func (p *extMockProvider) CreateUserWithExternalIdentity(ctx context.Context, input CreateUserInput, identity ExternalIdentity) (UserRecord, error) {
	if p.beforeCreate != nil {
		p.beforeCreate(p)
	}
	p.emu.Lock()
	defer p.emu.Unlock()
	p.creates++
	p.lastCreate, p.lastIdentity = input, identity
	if p.createErr != nil {
		return UserRecord{}, p.createErr
	}
	if _, taken := p.links[extKey(input.TenantID, identity.Provider, identity.Subject)]; taken {
		return UserRecord{}, ErrExternalIdentityInUse
	}
	for _, u := range p.users {
		if u.TenantID == input.TenantID && u.Identifier == input.Identifier {
			return UserRecord{}, ErrProviderDuplicateIdentifier
		}
	}
	p.nextID++
	user := UserRecord{
		UserID: "ext-user-" + string(rune('0'+p.nextID)), Identifier: input.Identifier, TenantID: input.TenantID,
		PasswordHash: input.PasswordHash, Status: input.Status, Role: input.Role,
		PermissionVersion: input.PermissionVersion, RoleVersion: input.RoleVersion, AccountVersion: input.AccountVersion,
	}
	p.addUser(user)
	p.links[extKey(input.TenantID, identity.Provider, identity.Subject)] = extLink{userID: user.UserID, identity: identity}
	return user, nil
}

func (p *extMockProvider) LinkExternalIdentity(ctx context.Context, tenantID, userID string, identity ExternalIdentity) error {
	p.emu.Lock()
	defer p.emu.Unlock()
	p.linksMade++
	if p.linkErr != nil {
		return p.linkErr
	}
	key := extKey(tenantID, identity.Provider, identity.Subject)
	if existing, ok := p.links[key]; ok && existing.userID != userID {
		return ErrExternalIdentityInUse
	}
	p.links[key] = extLink{userID: userID, identity: identity}
	return nil
}

func (p *extMockProvider) UnlinkExternalIdentity(ctx context.Context, tenantID, userID, provider, subject string) error {
	p.emu.Lock()
	defer p.emu.Unlock()
	p.unlinks++
	if p.unlinkErr != nil {
		return p.unlinkErr
	}
	key := extKey(tenantID, provider, subject)
	if l, ok := p.links[key]; ok && l.userID == userID {
		delete(p.links, key)
	}
	return nil
}

func (p *extMockProvider) ListExternalIdentities(ctx context.Context, tenantID, userID string) ([]ExternalIdentity, error) {
	p.emu.Lock()
	defer p.emu.Unlock()
	p.lists++
	if p.listErr != nil {
		return nil, p.listErr
	}
	out := []ExternalIdentity{}
	for k, l := range p.links {
		if l.userID == userID && strings.HasPrefix(k, tenantID+"\x00") {
			out = append(out, l.identity)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Provider+out[i].Subject < out[j].Provider+out[j].Subject
	})
	return out, nil
}

func (p *extMockProvider) linkedTo(tenantID, provider, subject string) (string, bool) {
	p.emu.Lock()
	defer p.emu.Unlock()
	l, ok := p.links[extKey(tenantID, provider, subject)]
	return l.userID, ok
}

func (p *extMockProvider) linkCount() int {
	p.emu.Lock()
	defer p.emu.Unlock()
	return len(p.links)
}

func (p *extMockProvider) userCount() int {
	p.emu.Lock()
	defer p.emu.Unlock()
	return len(p.users)
}

// ---------------------------------------------------------------------------
// extEnv
// ---------------------------------------------------------------------------

const (
	extLocalUserID = "local1"
	extLocalEmail  = "alice@example.com"
)

type extEnv struct {
	t      testing.TB
	engine *Engine
	up     *extMockProvider
	idp    *extIdP
	mr     *miniredis.Miniredis
	rdb    *redis.Client
	sink   *collectingSink
	cmds   *redisCommandLog
	cfg    Config
	tenant string
	clk    Clock // nil unless a test installed one with extClock
}

type extOption func(*extEnv, *Config)

// extClock builds the engine with WithClock(c).
func extClock(c Clock) extOption {
	return func(env *extEnv, _ *Config) { env.clk = c }
}

func extConfig(mutate func(*Config)) extOption {
	return func(_ *extEnv, c *Config) { mutate(c) }
}

func extMultiTenant() extOption {
	return func(env *extEnv, c *Config) {
		c.MultiTenant.Enabled = true
		env.tenant = "tenant-a"
	}
}

// extAutoLink turns on auto-linking, which needs email verification.
func extAutoLink() extOption {
	return extConfig(func(c *Config) {
		c.EmailVerification.Enabled = true
		c.EmailVerification.Strategy = VerificationToken
		c.ExternalAuth.AutoLinkVerifiedEmail = true
	})
}

func extSignup() extOption {
	return extConfig(func(c *Config) { c.ExternalAuth.AllowSignup = true })
}

// newExtEnv builds an engine with external sign-in enabled for a Google, an
// Apple and a generic OIDC provider pointed at a local key server, and one
// existing local account with a password.
func newExtEnv(t testing.TB, opts ...extOption) *extEnv {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(mr.Close)
	t.Cleanup(func() { _ = rdb.Close() })

	env := &extEnv{t: t, mr: mr, rdb: rdb, sink: &collectingSink{}, cmds: &redisCommandLog{}, tenant: "0", idp: newExtIdP(t)}
	rdb.AddHook(env.cmds)

	cfg := totpTestConfig()
	cfg.Password.Memory = 8192
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Audit.Enabled = true
	cfg.Metrics.Enabled = true
	cfg.TOTP.EnforceReplayProtection = false
	cfg.Account.Enabled = true
	cfg.Account.DefaultRole = "member"
	cfg.Account.EnableCreationLimiter = false
	cfg.ExternalAuth = ExternalAuthConfig{
		Enabled: true,
		Providers: map[string]ExternalProviderConfig{
			"google": {Kind: ExternalKindGoogle, ClientIDs: []string{extGoogleClient}, JWKSURL: env.idp.url()},
			"apple":  {Kind: ExternalKindApple, ClientIDs: []string{extAppleClient}, JWKSURL: env.idp.url()},
			"corp": {
				Kind: ExternalKindOIDC, ClientIDs: []string{"corp-client"}, Issuer: "https://sso.example.test",
				JWKSURL: env.idp.url(), Algorithms: []string{"RS256", "ES256"},
			},
		},
	}
	for _, opt := range opts {
		opt(env, &cfg)
	}
	env.cfg = cfg

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		t.Fatalf("NewArgon2: %v", err)
	}
	hash, err := hasher.Hash(extPassword)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	env.up = newExtMockProvider()
	env.up.addUser(UserRecord{
		UserID: extLocalUserID, Identifier: extLocalEmail, TenantID: env.tenant,
		PasswordHash: hash, Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithHTTPClient(env.idp.server.Client()).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {"perm.read"}, "admin": {"perm.read"}}).
		WithUserProvider(env.up).
		WithAuditSink(env.sink).
		WithClock(env.clk).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	env.engine = engine
	t.Cleanup(engine.Close)
	return env
}

func (env *extEnv) ctx() context.Context {
	ctx := context.Background()
	if env.cfg.MultiTenant.Enabled {
		ctx = WithTenantID(ctx, env.tenant)
	}
	return ctx
}

// login signs in with a freshly signed token and returns the result and the
// token used.
func (env *extEnv) login(spec extTokenSpec) (*LoginResult, error) {
	env.t.Helper()
	if spec.provider == "" {
		spec.provider = "google"
	}
	token, nonce := env.idp.token(spec)
	return env.engine.LoginWithExternalIdentity(env.ctx(), spec.provider, token, ExternalLoginOptions{Nonce: nonce})
}

func (env *extEnv) addLocal(user UserRecord) {
	env.t.Helper()
	if user.TenantID == "" {
		user.TenantID = env.tenant
	}
	if user.Role == "" {
		user.Role = "member"
	}
	user.PermissionVersion, user.RoleVersion, user.AccountVersion = 1, 1, 1
	env.up.addUser(user)
}

func (env *extEnv) waitForAudit(eventType, reason string) *AuditEvent {
	env.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if ev := env.sink.find(eventType, reason); ev != nil {
			return ev
		}
		if time.Now().After(deadline) {
			env.t.Fatalf("audit event %q (reason %q) was never emitted", eventType, reason)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// events returns the audit events of a type once the dispatcher has drained.
func (env *extEnv) events(eventType string) []AuditEvent {
	env.t.Helper()
	time.Sleep(60 * time.Millisecond)
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	var out []AuditEvent
	for _, ev := range env.sink.events {
		if ev.EventType == eventType {
			out = append(out, ev)
		}
	}
	return out
}

func (env *extEnv) metric(id MetricID) uint64 {
	return env.engine.MetricsSnapshot().Counters[id]
}

func (env *extEnv) hasKey(substr string) bool {
	for _, k := range env.mr.Keys() {
		if strings.Contains(k, substr) {
			return true
		}
	}
	return false
}
