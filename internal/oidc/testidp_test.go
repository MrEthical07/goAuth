package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://idp.test"
	testClientID = "client-1"
	testNonce    = "raw-nonce-value"
)

// testKey is one signing key the test IdP can publish.
type testKey struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newRSAKey(t *testing.T, kid string) *testKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return &testKey{kid: kid, rsa: k}
}

func newECKey(t *testing.T, kid string) *testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	return &testKey{kid: kid, ec: k}
}

func (k *testKey) signer() crypto.Signer {
	if k.rsa != nil {
		return k.rsa
	}
	return k.ec
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *testKey) jwk() map[string]interface{} {
	if k.rsa != nil {
		pub := k.rsa.PublicKey
		e := make([]byte, 0, 4)
		for v := pub.E; v > 0; v >>= 8 {
			e = append([]byte{byte(v)}, e...)
		}
		return map[string]interface{}{"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256", "n": b64(pub.N.Bytes()), "e": b64(e)}
	}
	point, err := k.ec.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	return map[string]interface{}{
		"kty": "EC", "kid": k.kid, "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": b64(point[1:33]), "y": b64(point[33:65]),
	}
}

// testIdP is a key server over TLS that publishes a mutable key set.
type testIdP struct {
	t      *testing.T
	server *httptest.Server

	mu           sync.Mutex
	keys         []*testKey
	cacheControl string
	fail         bool
	body         []byte // when set, served instead of the key set
	delay        time.Duration

	fetches atomic.Int64
}

func newTestIdP(t *testing.T, keys ...*testKey) *testIdP {
	t.Helper()
	idp := &testIdP{t: t, keys: keys, cacheControl: "public, max-age=3600"}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.server.Close)
	return idp
}

func (i *testIdP) url() string { return i.server.URL + "/certs" }

func (i *testIdP) serve(w http.ResponseWriter, r *http.Request) {
	i.fetches.Add(1)
	i.mu.Lock()
	fail, body, cc, keys, delay := i.fail, i.body, i.cacheControl, i.keys, i.delay
	i.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("Content-Type", "application/json")
	if body != nil {
		_, _ = w.Write(body)
		return
	}
	set := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		set = append(set, k.jwk())
	}
	writeJSON(w, map[string]interface{}{"keys": set})
}

func (i *testIdP) setKeys(keys ...*testKey) {
	i.mu.Lock()
	i.keys = keys
	i.mu.Unlock()
}

func (i *testIdP) setFail(fail bool) {
	i.mu.Lock()
	i.fail = fail
	i.mu.Unlock()
}

func (i *testIdP) setCacheControl(v string) {
	i.mu.Lock()
	i.cacheControl = v
	i.mu.Unlock()
}

func (i *testIdP) setBody(b []byte) {
	i.mu.Lock()
	i.body = b
	i.mu.Unlock()
}

// memReplay is an in-memory single-use store that records the lifetimes it
// was asked for.
type memReplay struct {
	mu   sync.Mutex
	seen map[string]time.Duration
	err  error
}

func newMemReplay() *memReplay { return &memReplay{seen: map[string]time.Duration{}} }

func (m *memReplay) SetNX(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	if _, ok := m.seen[key]; ok {
		return false, nil
	}
	m.seen[key] = ttl
	return true, nil
}

// fixture bundles an IdP, a verifier pointed at it and a controllable clock.
type fixture struct {
	t      *testing.T
	idp    *testIdP
	key    *testKey
	v      *Verifier
	replay *memReplay
	clock  *clock.Fake
}

type fixtureOption func(*ProviderConfig, *Options)

func newFixture(t *testing.T, opts ...fixtureOption) *fixture {
	t.Helper()
	key := newRSAKey(t, "kid-1")
	idp := newTestIdP(t, key)
	cfg := ProviderConfig{
		Name: "test", Kind: KindOIDC, Issuers: []string{testIssuer}, ClientIDs: []string{testClientID},
		JWKSURL: idp.url(), Algorithms: []string{"RS256", "ES256"},
	}
	fake := clock.NewFake(time.Unix(1_900_000_000, 0))
	replay := newMemReplay()
	o := Options{Client: idp.server.Client(), Replay: replay, Now: fake.Now}
	for _, opt := range opts {
		opt(&cfg, &o)
	}
	v, err := NewVerifier([]ProviderConfig{cfg}, o)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return &fixture{t: t, idp: idp, key: key, v: v, replay: replay, clock: fake}
}

// claims returns a valid claim set relative to the fixture clock.
func (f *fixture) claims() jwt.MapClaims {
	now := f.clock.Now()
	return jwt.MapClaims{
		"iss": testIssuer, "aud": testClientID, "sub": "subject-1",
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"nonce": testNonce, "email": "user@example.com", "email_verified": true,
	}
}

// sign signs claims with the key, using alg and kid headers (kid "" omits it).
func sign(t *testing.T, key *testKey, alg string, headers map[string]interface{}, claims jwt.MapClaims) string {
	t.Helper()
	method := jwt.GetSigningMethod(alg)
	token := jwt.NewWithClaims(method, claims)
	if key.kid != "" {
		token.Header["kid"] = key.kid
	}
	for k, v := range headers {
		if v == nil {
			delete(token.Header, k)
			continue
		}
		token.Header[k] = v
	}
	signed, err := token.SignedString(key.signer())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func (f *fixture) token(claims jwt.MapClaims) string {
	return sign(f.t, f.key, "RS256", nil, claims)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	_ = json.NewEncoder(w).Encode(v)
}
