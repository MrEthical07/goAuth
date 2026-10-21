package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func (f *fixture) verifyNew(sub string) error {
	claims := f.claims()
	claims["sub"] = sub
	_, err := f.v.Verify(context.Background(), "test", f.token(claims), testNonce)
	return err
}

// Building a verifier performs no network call; keys are fetched on first use.
//
// NEW-API.
func TestKeysNotFetchedAtConstruction(t *testing.T) {
	f := newFixture(t)
	if got := f.idp.fetches.Load(); got != 0 {
		t.Fatalf("NewVerifier fetched keys %d times", got)
	}
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("first verification fetched %d times, want 1", got)
	}
}

// NEW-API.
func TestWarmFetchesAndSurfacesFailure(t *testing.T) {
	f := newFixture(t)
	if err := f.v.Warm(context.Background()); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("Warm fetched %d times, want 1", got)
	}
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("verification after Warm fetched again (%d)", got)
	}

	down := newFixture(t)
	down.idp.setFail(true)
	if err := down.v.Warm(context.Background()); err == nil {
		t.Fatal("Warm reported success against a failing key server")
	}
}

// The cache lifetime follows Cache-Control max-age, clamped to
// [KeyRefreshMin, 24h].
//
// NEW-API.
func TestKeyCacheHonorsMaxAgeWithinBounds(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		ttl          time.Duration
	}{
		{"within bounds", "public, max-age=600", 10 * time.Minute},
		{"below the minimum", "max-age=5", DefaultKeyRefreshMin},
		{"above the maximum", "max-age=999999", 24 * time.Hour},
		{"no-store", "no-store", DefaultKeyRefreshMin},
		{"no-cache", "no-cache", DefaultKeyRefreshMin},
		{"absent", "", time.Hour},
		{"garbage", "max-age=soon", time.Hour},
		{"negative", "max-age=-5", time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.idp.setCacheControl(tc.cacheControl)
			if err := f.verifyNew("a"); err != nil {
				t.Fatal(err)
			}
			f.clock.Advance(tc.ttl - time.Second)
			if err := f.verifyNew("b"); err != nil {
				t.Fatal(err)
			}
			if got := f.idp.fetches.Load(); got != 1 {
				t.Fatalf("a fetch happened before the cache lifetime ended (%d)", got)
			}
			f.clock.Advance(2 * time.Second)
			if err := f.verifyNew("c"); err != nil {
				t.Fatal(err)
			}
			if got := f.idp.fetches.Load(); got != 2 {
				t.Fatalf("no refetch after the cache lifetime ended (%d fetches)", got)
			}
		})
	}
}

// N concurrent first logins fetch the key set exactly once.
//
// NEW-API.
func TestKeyCacheSingleFlight(t *testing.T) {
	f := newFixture(t)
	f.idp.mu.Lock()
	f.idp.delay = 50 * time.Millisecond
	f.idp.mu.Unlock()

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- f.verifyNew("subject-" + string(rune('a'+i%26)) + string(rune('A'+i/26)))
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent verification: %v", err)
		}
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("%d concurrent first logins fetched %d times, want 1", n, got)
	}
}

// A kid the cache has never seen triggers one refetch; a second unknown kid
// inside KeyRefreshMin triggers none.
//
// NEW-API.
func TestKeyCacheUnknownKidRefetchRules(t *testing.T) {
	f := newFixture(t)
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("setup fetched %d times", got)
	}

	rotated := newRSEKeyForTest(t, "kid-2")
	unknown := func() error {
		_, err := f.v.Verify(context.Background(), "test", sign(t, rotated, "RS256", nil, f.claims()), testNonce)
		return err
	}

	// Inside KeyRefreshMin: no fetch at all.
	f.clock.Advance(time.Minute)
	if err := unknown(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kid inside KeyRefreshMin = %v, want ErrInvalid", err)
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("unknown kid inside KeyRefreshMin fetched (%d)", got)
	}

	// After KeyRefreshMin: one refetch, still unknown, so ErrInvalid.
	f.clock.Advance(DefaultKeyRefreshMin)
	if err := unknown(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kid after KeyRefreshMin = %v, want ErrInvalid", err)
	}
	if got := f.idp.fetches.Load(); got != 2 {
		t.Fatalf("expected exactly one refetch, fetches = %d", got)
	}

	// A second unknown kid right after: no further fetch.
	for i := 0; i < 5; i++ {
		if err := unknown(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("repeat unknown kid = %v", err)
		}
	}
	if got := f.idp.fetches.Load(); got != 2 {
		t.Fatalf("repeated unknown kids fetched again (%d)", got)
	}
}

// A genuinely rotated key is picked up by the single refetch.
//
// NEW-API.
func TestKeyCacheRotation(t *testing.T) {
	f := newFixture(t)
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}
	rotated := newRSEKeyForTest(t, "kid-2")
	f.idp.setKeys(f.key, rotated)
	f.clock.Advance(DefaultKeyRefreshMin + time.Second)

	claims := f.claims()
	if _, err := f.v.Verify(context.Background(), "test", sign(t, rotated, "RS256", nil, claims), testNonce); err != nil {
		t.Fatalf("token signed by the rotated-in key: %v", err)
	}
	if got := f.idp.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}
}

// NEW-API.
func TestKeyCacheUnknownKidWhileProviderDown(t *testing.T) {
	f := newFixture(t)
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}
	f.idp.setFail(true)
	f.clock.Advance(DefaultKeyRefreshMin + time.Second)
	rotated := newRSEKeyForTest(t, "kid-2")
	_, err := f.v.Verify(context.Background(), "test", sign(t, rotated, "RS256", nil, f.claims()), testNonce)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown kid with the provider down = %v, want ErrUnavailable", err)
	}
}

// During an outage the last good keys keep serving up to KeyMaxStale after
// they were fetched; then, and with no keys at all, nothing is accepted.
//
// NEW-API.
func TestKeyCacheOutage(t *testing.T) {
	f := newFixture(t, func(_ *ProviderConfig, o *Options) {
		o.KeyRefreshMin = time.Minute
		o.KeyMaxStale = 6 * time.Hour
	})
	f.idp.setCacheControl("max-age=60")
	if err := f.verifyNew("a"); err != nil {
		t.Fatal(err)
	}

	f.idp.setFail(true)
	// Cache lifetime over, provider down, still inside KeyMaxStale.
	f.clock.Advance(2 * time.Minute)
	if err := f.verifyNew("b"); err != nil {
		t.Fatalf("stale keys within KeyMaxStale: %v", err)
	}
	// Failures back off: many logins do not hammer the provider.
	before := f.idp.fetches.Load()
	for i := 0; i < 20; i++ {
		if err := f.verifyNew("c" + string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.idp.fetches.Load(); got != before {
		t.Fatalf("login attempts during backoff fetched %d more times", got-before)
	}

	f.clock.Advance(4 * time.Hour)
	if err := f.verifyNew("d"); err != nil {
		t.Fatalf("stale keys at 4h: %v", err)
	}

	f.clock.Advance(3 * time.Hour) // 7h after the last good fetch
	if err := f.verifyNew("e"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("beyond KeyMaxStale = %v, want ErrUnavailable", err)
	}

	// Recovery: the next fetch restores service.
	f.idp.setFail(false)
	f.clock.Advance(time.Minute)
	if err := f.verifyNew("f"); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

// With no key set ever fetched, an outage means ErrUnavailable, never an
// accepted token.
//
// NEW-API.
func TestKeyCacheNoKeysAtAll(t *testing.T) {
	f := newFixture(t)
	f.idp.setFail(true)
	if err := f.verifyNew("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no keys, provider down = %v, want ErrUnavailable", err)
	}
	if len(f.replay.seen) != 0 {
		t.Fatal("a token was accepted without verification")
	}
	// A burst during the outage costs one fetch, not one per login.
	for i := 0; i < 10; i++ {
		_ = f.verifyNew("b")
	}
	if got := f.idp.fetches.Load(); got != 1 {
		t.Fatalf("outage burst fetched %d times, want 1", got)
	}
	// Once the backoff passes and the provider is back, service resumes.
	f.idp.setFail(false)
	f.clock.Advance(20 * time.Second)
	if err := f.verifyNew("c"); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

// A response that is not a usable key set never replaces a good one.
//
// NEW-API.
func TestKeyCacheBadResponseKeepsGoodKeys(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty set":    []byte(`{"keys":[]}`),
		"not json":     []byte(`<html>`),
		"unusable":     mustJSON(t, map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "oct", "kid": "x", "k": "AAAA"}}}),
		"no kid":       mustJSON(t, map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "n": "AQAB", "e": "AQAB"}}}),
		"short rsa":    mustJSON(t, map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": "kid-1", "n": "AQAB", "e": "AQAB"}}}),
		"bad ec point": mustJSON(t, map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "EC", "kid": "kid-1", "crv": "P-256", "x": "AA", "y": "AA"}}}),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, func(_ *ProviderConfig, o *Options) { o.KeyRefreshMin = time.Minute })
			f.idp.setCacheControl("max-age=60")
			if err := f.verifyNew("a"); err != nil {
				t.Fatal(err)
			}
			f.idp.setBody(body)
			f.clock.Advance(2 * time.Minute)
			if err := f.verifyNew("b"); err != nil {
				t.Fatalf("good keys were lost to a bad response: %v", err)
			}
		})
	}
}

// A kid that appears twice is ambiguous and is not used.
//
// NEW-API.
func TestKeyCacheDuplicateKidIsDropped(t *testing.T) {
	f := newFixture(t)
	other := newRSEKeyForTest(t, "kid-1")
	extra := newRSEKeyForTest(t, "kid-2")
	f.idp.setBody(mustJSON(t, map[string]interface{}{"keys": []interface{}{f.key.jwk(), other.jwk(), extra.jwk()}}))
	if err := f.verifyNew("a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token for an ambiguous kid = %v, want ErrInvalid", err)
	}
	if _, err := f.v.Verify(context.Background(), "test", sign(t, extra, "RS256", nil, f.claims()), testNonce); err != nil {
		t.Fatalf("unambiguous key in the same set: %v", err)
	}
}

// NEW-API.
func TestKeyCacheResponseSizeCap(t *testing.T) {
	f := newFixture(t)
	// A valid document followed by whitespace, so that it stays valid JSON
	// even when a reader stops at the cap: only the size check can reject it.
	doc := append(mustJSON(t, map[string]interface{}{"keys": []interface{}{f.key.jwk()}}), bytes.Repeat([]byte(" "), maxKeySetBytes)...)
	if len(doc) <= maxKeySetBytes {
		t.Fatalf("test document is only %d bytes", len(doc))
	}
	f.idp.setBody(doc)
	if err := f.verifyNew("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized key set = %v, want ErrUnavailable", err)
	}

	// The same document under the cap is accepted.
	small := mustJSON(t, map[string]interface{}{"keys": []interface{}{f.key.jwk()}, "pad": strings.Repeat("x", 1000)})
	f.idp.setBody(small)
	f.clock.Advance(time.Minute)
	if err := f.verifyNew("b"); err != nil {
		t.Fatalf("key set under the cap: %v", err)
	}
}

// NEW-API.
func TestKeyCacheRequiresHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a plain-http key server was contacted")
	}))
	defer plain.Close()

	f := newFixture(t, func(c *ProviderConfig, _ *Options) { c.JWKSURL = plain.URL + "/certs" })
	if err := f.verifyNew("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("http key URL = %v, want ErrUnavailable", err)
	}
}

// NEW-API.
func TestKeyCacheRefusesRedirectToHTTP(t *testing.T) {
	var hit atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
	}))
	defer plain.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer redirector.Close()

	f := newFixture(t, func(c *ProviderConfig, o *Options) {
		c.JWKSURL = redirector.URL + "/certs"
		o.Client = redirector.Client()
	})
	if err := f.verifyNew("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("redirect to http = %v, want ErrUnavailable", err)
	}
	if hit.Load() {
		t.Fatal("the redirect to plain http was followed")
	}
}

// The injected client is used as given; a client that does not trust the
// server's certificate gets no keys.
//
// NEW-API.
func TestKeyCacheUsesInjectedClient(t *testing.T) {
	f := newFixture(t, func(_ *ProviderConfig, o *Options) {
		o.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}, Timeout: 2 * time.Second}
	})
	if err := f.verifyNew("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted certificate = %v, want ErrUnavailable", err)
	}
}

// The injected client's own redirect policy still applies.
//
// NEW-API.
func TestKeyCacheKeepsClientRedirectPolicy(t *testing.T) {
	var seen bytes.Buffer
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.WriteString("target")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	client := redirector.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("no redirects here") }
	f := newFixture(t, func(c *ProviderConfig, o *Options) {
		c.JWKSURL = redirector.URL + "/certs"
		o.Client = client
	})
	_ = f.verifyNew("a")
	if seen.Len() != 0 {
		t.Fatal("the client's CheckRedirect was bypassed")
	}
}

func newRSEKeyForTest(t *testing.T, kid string) *testKey { return newRSAKey(t, kid) }

var _ = jwt.MapClaims{}
