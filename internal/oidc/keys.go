package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxKeySetBytes caps a key-set response.
	maxKeySetBytes = 1 << 20
	// maxKeyTTL is the longest a fetched key set is trusted without a refetch,
	// whatever the provider's Cache-Control says.
	maxKeyTTL = 24 * time.Hour
	// defaultKeyTTL applies when the response carries no usable max-age.
	defaultKeyTTL = time.Hour
	// maxFailureBackoff bounds how soon after a failed fetch the next one may
	// be attempted, so an outage costs one request per interval, not one per
	// login.
	maxFailureBackoff = 15 * time.Second
	// fetchTimeout bounds one fetch even when the injected client has no
	// timeout of its own.
	fetchTimeout = 10 * time.Second
	// minRSABits is the smallest RSA modulus accepted from a key set.
	minRSABits = 2048
)

// jwk is one entry of a JSON Web Key Set, with only the members this package
// reads.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

// verificationKey is a parsed public key together with the constraints its
// JWK declared.
type verificationKey struct {
	kty    string
	crv    string
	use    string
	alg    string
	keyOps []string
	pub    crypto.PublicKey
}

// usableFor reports whether the key may verify a token signed with alg: its
// declared use, algorithm and operations must not contradict the token, and
// its type must be the one the algorithm needs.
func (k *verificationKey) usableFor(alg string) bool {
	if k.use != "" && k.use != "sig" {
		return false
	}
	if k.alg != "" && k.alg != alg {
		return false
	}
	if len(k.keyOps) > 0 {
		verify := false
		for _, op := range k.keyOps {
			if op == "verify" {
				verify = true
			}
		}
		if !verify {
			return false
		}
	}
	switch alg {
	case "RS256", "RS384", "RS512":
		_, ok := k.pub.(*rsa.PublicKey)
		return ok && k.kty == "RSA"
	case "ES256":
		return k.kty == "EC" && k.crv == "P-256"
	case "ES384":
		return k.kty == "EC" && k.crv == "P-384"
	}
	return false
}

func parseJWK(raw jwk) (*verificationKey, error) {
	key := &verificationKey{kty: raw.Kty, crv: raw.Crv, use: raw.Use, alg: raw.Alg, keyOps: raw.KeyOps}
	switch raw.Kty {
	case "RSA":
		n, err := decodeBigInt(raw.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeBigInt(raw.E)
		if err != nil {
			return nil, err
		}
		if n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Int64()%2 == 0 {
			return nil, errors.New("rsa key parameters out of range")
		}
		key.pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		var curve elliptic.Curve
		switch raw.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, errors.New("unsupported curve")
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err := decodeFixed(raw.X, size)
		if err != nil {
			return nil, err
		}
		y, err := decodeFixed(raw.Y, size)
		if err != nil {
			return nil, err
		}
		point := append([]byte{4}, append(x, y...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, err
		}
		key.pub = pub
	default:
		return nil, errors.New("unsupported key type")
	}
	return key, nil
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("bad base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeFixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, errors.New("bad base64url coordinate")
	}
	return b, nil
}

// parseKeySet reads a JWKS document. Keys that cannot be used are skipped, a
// kid that appears twice is dropped entirely (which of the two is meant is
// ambiguous), and a document with no usable key is an error: it must never
// replace a good key set.
func parseKeySet(body []byte) (map[string]*verificationKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode key set: %w", err)
	}
	keys := make(map[string]*verificationKey, len(doc.Keys))
	duplicate := map[string]bool{}
	for _, raw := range doc.Keys {
		if raw.Kid == "" {
			continue
		}
		if _, seen := keys[raw.Kid]; seen || duplicate[raw.Kid] {
			delete(keys, raw.Kid)
			duplicate[raw.Kid] = true
			continue
		}
		key, err := parseJWK(raw)
		if err != nil {
			continue
		}
		keys[raw.Kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("key set has no usable key")
	}
	return keys, nil
}

// cacheTTL derives how long a response's keys are trusted from its
// Cache-Control header, clamped to [min, maxKeyTTL].
func cacheTTL(h http.Header, min time.Duration) time.Duration {
	ttl := defaultKeyTTL
	for _, value := range h.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			directive = strings.ToLower(strings.TrimSpace(directive))
			switch {
			case directive == "no-store" || directive == "no-cache":
				ttl = 0
			case strings.HasPrefix(directive, "max-age="):
				if secs, err := strconv.ParseInt(strings.TrimPrefix(directive, "max-age="), 10, 64); err == nil && secs >= 0 {
					if secs > int64(maxKeyTTL/time.Second) {
						secs = int64(maxKeyTTL / time.Second)
					}
					ttl = time.Duration(secs) * time.Second
				}
			}
		}
	}
	if ttl < min {
		ttl = min
	}
	if ttl > maxKeyTTL {
		ttl = maxKeyTTL
	}
	return ttl
}

// flight is one in-progress key-set fetch that every concurrent caller waits
// on.
type flight struct {
	done chan struct{}
	err  error
}

// keyCache holds one provider's key set.
type keyCache struct {
	url        string
	client     *http.Client
	refreshMin time.Duration
	maxStale   time.Duration
	now        func() time.Time

	mu         sync.Mutex
	keys       map[string]*verificationKey
	fetchedAt  time.Time // when the keys were last fetched successfully
	expiresAt  time.Time // fetchedAt plus the response's cache lifetime
	retryAfter time.Time // no fetch before this after a failure
	gen        uint64    // counts finished fetches, successful or not
	lastErr    error
	inflight   *flight
}

func newKeyCache(rawURL string, client *http.Client, refreshMin, maxStale time.Duration, now func() time.Time) *keyCache {
	return &keyCache{url: rawURL, client: client, refreshMin: refreshMin, maxStale: maxStale, now: now}
}

type cacheState struct {
	keys       map[string]*verificationKey
	fetchedAt  time.Time
	expiresAt  time.Time
	retryAfter time.Time
	gen        uint64
}

func (c *keyCache) snapshot() cacheState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cacheState{keys: c.keys, fetchedAt: c.fetchedAt, expiresAt: c.expiresAt, retryAfter: c.retryAfter, gen: c.gen}
}

// key returns the key named kid, usable for alg, fetching the key set when
// the cache says it must.
//
// A cached set is used until its cache lifetime ends. A kid that is not in
// it triggers at most one refetch per refreshMin, so tokens naming random
// kids cannot make the server fetch. When a fetch fails, the last good set
// keeps serving for maxStale after it was fetched; after that, or with no set
// at all, the provider is unavailable and no token is accepted.
func (c *keyCache) key(ctx context.Context, kid, alg string) (*verificationKey, error) {
	state := c.snapshot()
	now := c.now()
	fresh := state.keys != nil && now.Before(state.expiresAt)

	needFetch := false
	var fetchErr error
	switch {
	case fresh:
		if _, known := state.keys[kid]; !known {
			if now.Sub(state.fetchedAt) < c.refreshMin || now.Before(state.retryAfter) {
				return nil, fmt.Errorf("%w: unknown key id", ErrInvalid)
			}
			needFetch = true
		}
	default:
		needFetch = !now.Before(state.retryAfter)
	}
	if needFetch {
		// A failure is reflected in the cache state below; whether the old
		// keys may still serve is decided there.
		fetchErr = c.refresh(ctx, state.gen)
		state = c.snapshot()
		now = c.now()
		fresh = state.keys != nil && now.Before(state.expiresAt)
	}

	if state.keys == nil {
		return nil, fmt.Errorf("%w: no key set", ErrUnavailable)
	}
	key, known := state.keys[kid]
	if fresh {
		if !known {
			if fetchErr != nil {
				// The kid may be a freshly rotated key we could not fetch.
				return nil, fmt.Errorf("%w: unknown key id and the key set could not be refreshed", ErrUnavailable)
			}
			return nil, fmt.Errorf("%w: unknown key id", ErrInvalid)
		}
		return c.checked(key, alg)
	}
	if now.Sub(state.fetchedAt) > c.maxStale {
		return nil, fmt.Errorf("%w: key set is stale", ErrUnavailable)
	}
	if !known {
		return nil, fmt.Errorf("%w: unknown key id and the key set could not be refreshed", ErrUnavailable)
	}
	return c.checked(key, alg)
}

func (c *keyCache) checked(key *verificationKey, alg string) (*verificationKey, error) {
	if !key.usableFor(alg) {
		return nil, fmt.Errorf("%w: key does not match the token algorithm", ErrInvalid)
	}
	return key, nil
}

// warm fetches the key set now, regardless of the cache state.
func (c *keyCache) warm(ctx context.Context) error {
	return c.refresh(ctx, forceFetch)
}

const forceFetch = ^uint64(0)

// refresh fetches the key set once for every caller that asks while the fetch
// runs. seenGen is the generation the caller observed: if a fetch finished
// since, its outcome is returned instead of starting another, so callers that
// raced past the same stale snapshot do not each fetch.
func (c *keyCache) refresh(ctx context.Context, seenGen uint64) error {
	c.mu.Lock()
	if f := c.inflight; f != nil {
		c.mu.Unlock()
		return waitFlight(ctx, f)
	}
	if seenGen != forceFetch && c.gen != seenGen {
		err := c.lastErr
		c.mu.Unlock()
		return err
	}
	f := &flight{done: make(chan struct{})}
	c.inflight = f
	c.mu.Unlock()

	// The fetch must not die with the first caller's context, which other
	// callers are waiting on. It is bounded by its own timeout instead.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	go func() {
		defer cancel()
		keys, ttl, err := c.fetch(fetchCtx)
		now := c.now()

		c.mu.Lock()
		c.gen++
		c.lastErr = err
		if err == nil {
			c.keys = keys
			c.fetchedAt = now
			c.expiresAt = now.Add(ttl)
			c.retryAfter = time.Time{}
		} else {
			backoff := c.refreshMin
			if backoff > maxFailureBackoff {
				backoff = maxFailureBackoff
			}
			c.retryAfter = now.Add(backoff)
		}
		c.inflight = nil
		f.err = err
		c.mu.Unlock()
		close(f.done)
	}()
	return waitFlight(ctx, f)
}

func waitFlight(ctx context.Context, f *flight) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetch downloads and parses the key set. Only https is spoken, redirects to
// anything else are refused, and the body is capped.
func (c *keyCache) fetch(ctx context.Context) (map[string]*verificationKey, time.Duration, error) {
	target, err := url.Parse(c.url)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		return nil, 0, errors.New("key set URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")

	client := *c.client
	inner := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if next.URL.Scheme != "https" {
			return errors.New("redirect to a non-https URL refused")
		}
		if inner != nil {
			return inner(next, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch key set: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch key set: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read key set: %w", err)
	}
	if len(body) > maxKeySetBytes {
		return nil, 0, errors.New("key set response too large")
	}
	keys, err := parseKeySet(body)
	if err != nil {
		return nil, 0, err
	}
	return keys, cacheTTL(resp.Header, c.refreshMin), nil
}
