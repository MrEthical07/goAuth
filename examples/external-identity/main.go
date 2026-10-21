// Package main demonstrates goAuth external sign-in: verifying a Google (or
// Sign in with Apple) ID token the application already obtained, then
// creating, finding or linking the account and issuing a normal goAuth
// session.
//
// It runs a scripted walkthrough with no network access: a local test identity
// provider (a TLS key server plus a token signer) stands in for Google, and
// miniredis stands in for Redis.
//
//	go run ./examples/external-identity
//
// The walkthrough shows a first sign-in creating a password-less account, a
// repeat sign-in, a single-use token being refused the second time, an
// existing password account being asked to link (not silently taken over),
// the link made from a signed-in session after a password step-up, and what a
// password-less account cannot do.
//
// In production you set no JWKSURL: Google's published keys are the default.
// The nonce is issued by your server and put in the request the client makes
// to the provider; see newNonce.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"time"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/password"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const (
	googleClientID = "demo-web-client.apps.googleusercontent.com"
	aliceEmail     = "alice@example.com"
	alicePassword  = "correct-horse"
)

func main() {
	if err := run(os.Stdout); err != nil {
		// The error is not printed: nothing derived from a credential or a
		// token should reach a log. The test reports the full error.
		log.Fatal("external-identity example failed; run its test for details")
	}
}

func run(w io.Writer) error {
	idp, err := newLocalIdP()
	if err != nil {
		return err
	}
	defer idp.Close()

	mr, err := miniredis.Run()
	if err != nil {
		return err
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := goAuth.DefaultConfig()
	// Cheap Argon2 settings keep the demo fast; keep the defaults in production.
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Security.ProductionMode = false

	cfg.Account.Enabled = true
	cfg.Account.DefaultRole = "member"

	cfg.ExternalAuth = goAuth.ExternalAuthConfig{
		Enabled: true,
		Providers: map[string]goAuth.ExternalProviderConfig{
			"google": {
				Kind:      goAuth.ExternalKindGoogle,
				ClientIDs: []string{googleClientID},
				// Leave JWKSURL out in production: Google's own key set is the
				// default. It points at the local test provider here.
				JWKSURL: idp.keysURL(),
			},
		},
		// A first sign-in with no matching account creates a password-less
		// one. AutoLinkVerifiedEmail stays off: see the walkthrough.
		AllowSignup: true,
	}

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		return err
	}
	hash, err := hasher.Hash(alicePassword)
	if err != nil {
		return err
	}
	users := newUsers()
	users.put(goAuth.UserRecord{
		UserID: "user-alice", Identifier: aliceEmail, PasswordHash: hash, Role: "member",
		Status: goAuth.AccountActive, PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	engine, err := goAuth.New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithHTTPClient(idp.client()).
		WithPermissions([]string{"profile.read"}).
		WithRoles(map[string][]string{"member": {"profile.read"}}).
		WithUserProvider(users).
		Build()
	if err != nil {
		return err
	}
	defer engine.Close()

	// Optional: fetch the provider's keys now instead of on the first sign-in.
	if err := engine.WarmExternalKeys(context.Background()); err != nil {
		return fmt.Errorf("warm keys: %w", err)
	}
	ctx := goAuth.WithClientIP(context.Background(), "203.0.113.7")

	// signIn is what your HTTP handler does: the client sent the ID token it
	// got from Google; the nonce is the one your server issued for this
	// sign-in (here the "client" and "server" are the same function).
	signIn := func(claims claims) (res *goAuth.LoginResult, token, nonce string, err error) {
		nonce = newNonce()
		if token, err = idp.issue(claims, nonce); err != nil {
			return nil, "", "", err
		}
		res, err = engine.LoginWithExternalIdentity(ctx, "google", token, goAuth.ExternalLoginOptions{Nonce: nonce, DisplayName: claims.name})
		return res, token, nonce, err
	}

	// 1. A first sign-in: nobody has this identity or its email.
	carol := claims{sub: "google-sub-carol", email: "carol@example.com", name: "Carol"}
	res, carolToken, carolNonce, err := signIn(carol)
	if err != nil {
		return fmt.Errorf("first sign-in: %w", err)
	}
	fmt.Fprintf(w, "first sign-in with Google: new account=%v, session issued=%v\n", res.NewAccount, res.AccessToken != "")
	carolID := users.idOf("carol@example.com")

	// 2. The same person returns. The identity is linked now; no email needed.
	res, _, _, err = signIn(claims{sub: carol.sub})
	if err != nil {
		return fmt.Errorf("repeat sign-in: %w", err)
	}
	fmt.Fprintf(w, "returning sign-in: new account=%v, session issued=%v\n", res.NewAccount, res.AccessToken != "")

	// 3. An ID token is accepted once. Replaying it is refused.
	_, err = engine.LoginWithExternalIdentity(ctx, "google", carolToken, goAuth.ExternalLoginOptions{Nonce: carolNonce})
	if !errors.Is(err, goAuth.ErrExternalTokenReplayed) {
		return fmt.Errorf("expected ErrExternalTokenReplayed, got %v", err)
	}
	fmt.Fprintln(w, "replaying a used token: refused with ErrExternalTokenReplayed")

	// 4. Alice already has a password account under the same email. A verified
	// email from Google is NOT enough to take it over (pre-hijacking), so the
	// app is told to have her sign in and link instead.
	alice := claims{sub: "google-sub-alice", email: aliceEmail}
	_, _, _, err = signIn(alice)
	if !errors.Is(err, goAuth.ErrExternalAccountLinkRequired) {
		return fmt.Errorf("expected ErrExternalAccountLinkRequired, got %v", err)
	}
	fmt.Fprintln(w, "Google email matches a password account: refused with ErrExternalAccountLinkRequired")

	// 5. Alice signs in with her password, confirms it (the recommended
	// step-up), then links Google from her settings page.
	if _, _, err := engine.Login(ctx, aliceEmail, alicePassword); err != nil {
		return fmt.Errorf("password sign-in: %w", err)
	}
	if err := engine.VerifyPassword(ctx, "user-alice", alicePassword); err != nil {
		return fmt.Errorf("step-up: %w", err)
	}
	linkNonce := newNonce()
	linkToken, err := idp.issue(alice, linkNonce)
	if err != nil {
		return err
	}
	identity, err := engine.LinkExternalIdentity(ctx, "user-alice", "google", linkToken, linkNonce)
	if err != nil {
		return fmt.Errorf("link: %w", err)
	}
	fmt.Fprintf(w, "linked %s identity to alice (email verified=%v)\n", identity.Provider, identity.EmailVerified)

	res, _, _, err = signIn(claims{sub: alice.sub})
	if err != nil {
		return fmt.Errorf("sign-in after linking: %w", err)
	}
	fmt.Fprintf(w, "alice signs in with Google: session issued=%v\n", res.AccessToken != "")

	// 6. A password-less account has no password to verify or change, and
	// cannot drop its only way in.
	err = engine.VerifyPassword(ctx, carolID, "anything")
	if !errors.Is(err, goAuth.ErrPasswordNotSet) {
		return fmt.Errorf("expected ErrPasswordNotSet, got %v", err)
	}
	fmt.Fprintln(w, "carol (no password) VerifyPassword: refused with ErrPasswordNotSet")
	err = engine.UnlinkExternalIdentity(ctx, carolID, "google", carol.sub)
	if !errors.Is(err, goAuth.ErrLastLoginMethod) {
		return fmt.Errorf("expected ErrLastLoginMethod, got %v", err)
	}
	fmt.Fprintln(w, "carol unlinking her only identity: refused with ErrLastLoginMethod")

	// Alice has a password, so she may unlink.
	if err := engine.UnlinkExternalIdentity(ctx, "user-alice", "google", alice.sub); err != nil {
		return fmt.Errorf("unlink: %w", err)
	}
	fmt.Fprintln(w, "alice (has a password) unlinked Google")
	return nil
}

// newNonce returns the single-use value your server issues for one sign-in and
// remembers (for example in the user's pre-login session) until the ID token
// comes back. The client includes it in its request to the provider; the
// provider puts it in the token; goAuth compares them.
func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// A local stand-in for Google
// ---------------------------------------------------------------------------

type claims struct {
	sub, email, name string
}

type localIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newLocalIdP() (*localIdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	idp := &localIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(rw http.ResponseWriter, r *http.Request) {
		e := make([]byte, 0, 4)
		for v := key.PublicKey.E; v > 0; v >>= 8 {
			e = append([]byte{byte(v)}, e...)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{"keys": []interface{}{map[string]interface{}{
			"kty": "RSA", "kid": "demo-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	idp.server = httptest.NewTLSServer(mux)
	return idp, nil
}

func (i *localIdP) Close()               { i.server.Close() }
func (i *localIdP) keysURL() string      { return i.server.URL + "/certs" }
func (i *localIdP) client() *http.Client { return i.server.Client() }

// issue signs an ID token the way Google would for a user who just signed in.
func (i *localIdP) issue(c claims, nonce string) (string, error) {
	now := time.Now()
	body := jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": googleClientID, "sub": c.sub,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "nonce": nonce,
	}
	if c.email != "" {
		body["email"] = c.email
		body["email_verified"] = true
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, body)
	tok.Header["kid"] = "demo-key"
	return tok.SignedString(i.key)
}

// ---------------------------------------------------------------------------
// In-memory user provider: UserProvider plus ExternalIdentityProvider
// ---------------------------------------------------------------------------

type users struct {
	mu      sync.Mutex
	byID    map[string]goAuth.UserRecord
	byIdent map[string]string
	links   map[string]string                  // provider\x00subject -> user ID
	idents  map[string]goAuth.ExternalIdentity // same key -> identity
	next    int
}

func newUsers() *users {
	return &users{
		byID: map[string]goAuth.UserRecord{}, byIdent: map[string]string{},
		links: map[string]string{}, idents: map[string]goAuth.ExternalIdentity{},
	}
}

func (p *users) put(u goAuth.UserRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
}

func (p *users) idOf(identifier string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.byIdent[identifier]
}

func linkKey(provider, subject string) string { return provider + "\x00" + subject }

// The by-identifier lookups must return goAuth.ErrUserNotFound for a missing
// user: external sign-up only creates an account on that signal.
var errNotFound = goAuth.ErrUserNotFound

func (p *users) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.byIdent[identifier]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	return p.byID[id], nil
}

func (p *users) GetUserByID(userID string) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	return u, nil
}

func (p *users) UpdatePasswordHash(userID, newHash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return errNotFound
	}
	u.PasswordHash = newHash
	p.byID[userID] = u
	return nil
}

func (p *users) CreateUser(_ context.Context, in goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.createLocked(in)
}

func (p *users) createLocked(in goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	if _, taken := p.byIdent[in.Identifier]; taken {
		return goAuth.UserRecord{}, goAuth.ErrProviderDuplicateIdentifier
	}
	p.next++
	u := goAuth.UserRecord{
		UserID: fmt.Sprintf("user-%d", p.next), Identifier: in.Identifier, PasswordHash: in.PasswordHash,
		Role: in.Role, Status: in.Status, TenantID: in.TenantID,
		PermissionVersion: in.PermissionVersion, RoleVersion: in.RoleVersion, AccountVersion: in.AccountVersion,
	}
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
	return u, nil
}

func (p *users) UpdateAccountStatus(_ context.Context, userID string, status goAuth.AccountStatus) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	u.Status = status
	p.byID[userID] = u
	return u, nil
}

// ExternalIdentityProvider. A real implementation keeps a table with a unique
// index on (tenant_id, provider, subject) and creates the user and the link in
// one transaction. This demo has a single tenant.

func (p *users) GetUserByExternalIdentity(_ context.Context, _, provider, subject string) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.links[linkKey(provider, subject)]
	if !ok {
		return goAuth.UserRecord{}, goAuth.ErrUserNotFound
	}
	return p.byID[id], nil
}

func (p *users) CreateUserWithExternalIdentity(_ context.Context, in goAuth.CreateUserInput, identity goAuth.ExternalIdentity) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := linkKey(identity.Provider, identity.Subject)
	if _, linked := p.links[key]; linked {
		return goAuth.UserRecord{}, goAuth.ErrExternalIdentityInUse
	}
	u, err := p.createLocked(in)
	if err != nil {
		return goAuth.UserRecord{}, err
	}
	p.links[key] = u.UserID
	p.idents[key] = identity
	return u, nil
}

func (p *users) LinkExternalIdentity(_ context.Context, _, userID string, identity goAuth.ExternalIdentity) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := linkKey(identity.Provider, identity.Subject)
	if owner, linked := p.links[key]; linked && owner != userID {
		return goAuth.ErrExternalIdentityInUse
	}
	p.links[key] = userID
	p.idents[key] = identity
	return nil
}

func (p *users) UnlinkExternalIdentity(_ context.Context, _, userID, provider, subject string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := linkKey(provider, subject)
	if p.links[key] == userID {
		delete(p.links, key)
		delete(p.idents, key)
	}
	return nil
}

func (p *users) ListExternalIdentities(_ context.Context, _, userID string) ([]goAuth.ExternalIdentity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []goAuth.ExternalIdentity{}
	for key, owner := range p.links {
		if owner == userID {
			out = append(out, p.idents[key])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// MFA is not used in this walkthrough.
func (p *users) GetTOTPSecret(context.Context, string) (*goAuth.TOTPRecord, error) {
	return nil, errors.New("totp not configured")
}
func (p *users) EnableTOTP(context.Context, string, []byte) error               { return nil }
func (p *users) DisableTOTP(context.Context, string) error                      { return nil }
func (p *users) MarkTOTPVerified(context.Context, string) error                 { return nil }
func (p *users) UpdateTOTPLastUsedCounter(context.Context, string, int64) error { return nil }
func (p *users) GetBackupCodes(context.Context, string) ([]goAuth.BackupCodeRecord, error) {
	return nil, nil
}
func (p *users) ReplaceBackupCodes(context.Context, string, []goAuth.BackupCodeRecord) error {
	return nil
}
func (p *users) ConsumeBackupCode(context.Context, string, [32]byte) (bool, error) {
	return false, nil
}
