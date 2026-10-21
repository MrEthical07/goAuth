// Package oidc verifies OpenID Connect ID tokens that an application already
// obtained from Google, Sign in with Apple or another OIDC provider.
//
// It checks the signature against the provider's published key set, the
// standard claims, the nonce, and single use. It does not run any OAuth2
// flow: no authorization-code exchange, no redirects, no discovery.
package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalid means the token is not acceptable: malformed, wrongly signed,
	// for another audience, expired, or carrying the wrong nonce.
	ErrInvalid = errors.New("oidc: invalid id token")
	// ErrReplayed means the exact token was already used.
	ErrReplayed = errors.New("oidc: id token already used")
	// ErrUnavailable means the token could not be verified because the
	// provider's keys are unavailable. No token is accepted in that case.
	ErrUnavailable = errors.New("oidc: provider keys unavailable")
	// ErrStore means the single-use record could not be written.
	ErrStore = errors.New("oidc: replay store unavailable")
	// ErrUnknownProvider means no provider is configured under the name.
	ErrUnknownProvider = errors.New("oidc: unknown provider")
)

const (
	// MaxTokenBytes is the largest ID token accepted.
	MaxTokenBytes = 16 * 1024
	// maxSubjectLen is the longest subject accepted.
	maxSubjectLen = 255
	maxEmailLen   = 320
	maxKeyIDLen   = 256
	// maxTokenLifetime bounds how far in the future a token may expire. It
	// keeps the single-use record's lifetime bounded without leaving a gap
	// after which an old token could be replayed.
	maxTokenLifetime = 24 * time.Hour

	// ReplayKeyPrefix names the single-use records.
	ReplayKeyPrefix = "axt"

	DefaultLeeway        = 60 * time.Second
	DefaultKeyRefreshMin = 5 * time.Minute
	DefaultKeyMaxStale   = 24 * time.Hour
)

// Provider kinds.
const (
	KindGoogle = "google"
	KindApple  = "apple"
	KindOIDC   = "oidc"
)

// ProviderConfig describes one identity provider.
type ProviderConfig struct {
	Name          string
	Kind          string
	Issuers       []string // accepted values of iss
	ClientIDs     []string // accepted audiences
	JWKSURL       string
	Algorithms    []string
	HostedDomains []string // google only; when set, hd must match
}

// ReplayGuard records that a token was used.
type ReplayGuard interface {
	// SetNX stores key for ttl and reports whether it was absent.
	SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Options configures a Verifier.
type Options struct {
	Client        *http.Client
	Replay        ReplayGuard
	Leeway        time.Duration
	KeyRefreshMin time.Duration
	KeyMaxStale   time.Duration
	// Now is the time source; the server clock when nil.
	Now func() time.Time
}

// Claims are the verified facts about the signed-in user.
type Claims struct {
	Provider       string
	Subject        string
	Email          string
	EmailVerified  bool
	IsPrivateEmail bool
	ExpiresAt      time.Time
}

type provider struct {
	cfg  ProviderConfig
	keys *keyCache
}

// Verifier verifies ID tokens for a fixed set of providers. It is safe for
// concurrent use.
type Verifier struct {
	providers map[string]*provider
	replay    ReplayGuard
	leeway    time.Duration
	now       func() time.Time
}

// NewVerifier builds a Verifier. It performs no network call: keys are
// fetched on first use.
func NewVerifier(configs []ProviderConfig, opts Options) (*Verifier, error) {
	if opts.Replay == nil {
		return nil, errors.New("oidc: a replay guard is required")
	}
	if opts.Client == nil {
		return nil, errors.New("oidc: an http client is required")
	}
	if opts.Now == nil {
		opts.Now = clock.Now
	}
	if opts.Leeway <= 0 {
		opts.Leeway = DefaultLeeway
	}
	if opts.KeyRefreshMin <= 0 {
		opts.KeyRefreshMin = DefaultKeyRefreshMin
	}
	if opts.KeyMaxStale <= 0 {
		opts.KeyMaxStale = DefaultKeyMaxStale
	}
	if opts.KeyMaxStale < opts.KeyRefreshMin {
		return nil, errors.New("oidc: KeyMaxStale must be at least KeyRefreshMin")
	}
	v := &Verifier{
		providers: make(map[string]*provider, len(configs)),
		replay:    opts.Replay,
		leeway:    opts.Leeway,
		now:       opts.Now,
	}
	for _, cfg := range configs {
		if cfg.Name == "" || len(cfg.ClientIDs) == 0 || len(cfg.Issuers) == 0 || len(cfg.Algorithms) == 0 {
			return nil, fmt.Errorf("oidc: incomplete provider %q", cfg.Name)
		}
		for _, alg := range cfg.Algorithms {
			if !AllowedAlgorithm(alg) {
				return nil, fmt.Errorf("oidc: algorithm %q is not allowed", alg)
			}
		}
		v.providers[cfg.Name] = &provider{
			cfg:  cfg,
			keys: newKeyCache(cfg.JWKSURL, opts.Client, opts.KeyRefreshMin, opts.KeyMaxStale, opts.Now),
		}
	}
	return v, nil
}

// AllowedAlgorithm reports whether alg may be used to verify an ID token.
// Symmetric algorithms and "none" never are.
func AllowedAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384":
		return true
	}
	return false
}

// Has reports whether a provider is configured under name.
func (v *Verifier) Has(name string) bool {
	_, ok := v.providers[name]
	return ok
}

// Warm fetches every provider's key set now. It returns the joined errors of
// the providers that failed.
func (v *Verifier) Warm(ctx context.Context) error {
	var errs []error
	for name, p := range v.providers {
		if err := p.keys.warm(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

// Verify checks rawToken for the named provider and returns its claims.
// nonce is the raw nonce the server issued for this sign-in; it is required.
//
// The checks run in a fixed order and each fails closed: structure,
// signature, issuer, audience, time claims, nonce, subject, hosted domain,
// claim types, and finally the single-use record. The record is written only
// for a token that passed everything else, so a bad token never uses up the
// record of a good one, and it is keyed on the signed part of the token so
// that re-encoding or malleating the signature cannot yield a second use.
func (v *Verifier) Verify(ctx context.Context, providerName, rawToken, nonce string) (*Claims, error) {
	p, ok := v.providers[providerName]
	if !ok {
		return nil, ErrUnknownProvider
	}
	if nonce == "" {
		return nil, invalid("nonce is required")
	}
	if len(rawToken) == 0 || len(rawToken) > MaxTokenBytes {
		return nil, invalid("token size")
	}

	// 1. Structure: three parts, an allowed algorithm and a key id.
	alg, kid, err := parseHeader(rawToken, p.cfg.Algorithms)
	if err != nil {
		return nil, err
	}

	// 2. Signature, with the key the token names.
	key, err := p.keys.key(ctx, kid, alg)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{alg}),
		jwt.WithoutClaimsValidation(),
		// Reject non-canonical base64url, so one token has one spelling.
		jwt.WithStrictDecoding(),
	)
	if _, err := parser.ParseWithClaims(rawToken, claims, func(*jwt.Token) (interface{}, error) {
		return key.pub, nil
	}); err != nil {
		return nil, invalid("signature")
	}

	// 3. Issuer.
	iss, _ := claims["iss"].(string)
	if !containsExact(p.cfg.Issuers, iss) {
		return nil, invalid("issuer")
	}

	// 4. Audience, and the authorized party when the audience is shared.
	if err := checkAudience(claims, p.cfg.ClientIDs); err != nil {
		return nil, err
	}

	// 5. Times, against the server clock.
	now := v.now()
	exp, hasExp := numericDate(claims["exp"])
	iat, hasIat := numericDate(claims["iat"])
	if !hasExp || !hasIat {
		return nil, invalid("exp and iat are required")
	}
	if !exp.After(now.Add(-v.leeway)) {
		return nil, invalid("expired")
	}
	if exp.Sub(now) > maxTokenLifetime+v.leeway {
		return nil, invalid("expiry too far in the future")
	}
	if iat.After(now.Add(v.leeway)) {
		return nil, invalid("issued in the future")
	}
	if raw, present := claims["nbf"]; present {
		nbf, ok := numericDate(raw)
		if !ok || nbf.After(now.Add(v.leeway)) {
			return nil, invalid("not yet valid")
		}
	}

	// 6. Nonce: the raw value, or its lowercase hex SHA-256.
	tokenNonce, _ := claims["nonce"].(string)
	if !nonceMatches(tokenNonce, nonce) {
		return nil, invalid("nonce")
	}

	// 7. Subject.
	sub, _ := claims["sub"].(string)
	if sub == "" || len(sub) > maxSubjectLen {
		return nil, invalid("subject")
	}

	// 8. Hosted domain.
	if len(p.cfg.HostedDomains) > 0 {
		hd, _ := claims["hd"].(string)
		matched := false
		for _, allowed := range p.cfg.HostedDomains {
			if hd != "" && strings.EqualFold(hd, allowed) {
				matched = true
			}
		}
		if !matched {
			return nil, invalid("hosted domain")
		}
	}

	// 9. Claims the caller uses.
	email, _ := claims["email"].(string)
	email = strings.TrimSpace(email)
	if len(email) > maxEmailLen {
		return nil, invalid("email too long")
	}
	out := &Claims{
		Provider:       providerName,
		Subject:        sub,
		Email:          email,
		EmailVerified:  boolClaim(claims["email_verified"]),
		IsPrivateEmail: boolClaim(claims["is_private_email"]),
		ExpiresAt:      exp,
	}

	// 10. Single use.
	ttl := exp.Sub(now) + v.leeway
	if ttl < time.Second {
		ttl = time.Second
	}
	// The record is keyed on the signed part only. A signature has several
	// valid spellings (an ECDSA signature with s replaced by n-s verifies
	// too), so hashing the whole token would let a variant of a used token
	// through; header.payload cannot change without invalidating the
	// signature.
	signed := rawToken[:strings.LastIndexByte(rawToken, '.')]
	sum := sha256.Sum256([]byte(signed))
	fresh, err := v.replay.SetNX(ctx, ReplayKeyPrefix+":"+providerName+":"+hex.EncodeToString(sum[:]), ttl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	if !fresh {
		return nil, ErrReplayed
	}
	return out, nil
}

// parseHeader splits the token and checks its header.
func parseHeader(rawToken string, algorithms []string) (alg, kid string, err error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", invalid("structure")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", invalid("header encoding")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", "", invalid("header")
	}
	if _, critical := header["crit"]; critical {
		return "", "", invalid("critical header")
	}
	if err := json.Unmarshal(header["alg"], &alg); err != nil || !containsExact(algorithms, alg) {
		return "", "", invalid("algorithm")
	}
	if err := json.Unmarshal(header["kid"], &kid); err != nil || kid == "" || len(kid) > maxKeyIDLen {
		return "", "", invalid("key id")
	}
	return alg, kid, nil
}

func containsExact(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// checkAudience requires a configured client ID in aud. When aud lists more
// than one audience the authorized party must be present and configured too.
func checkAudience(claims jwt.MapClaims, clientIDs []string) error {
	var audiences []string
	switch aud := claims["aud"].(type) {
	case string:
		audiences = []string{aud}
	case []interface{}:
		for _, item := range aud {
			s, ok := item.(string)
			if !ok {
				return invalid("audience")
			}
			audiences = append(audiences, s)
		}
	default:
		return invalid("audience")
	}
	matched := false
	for _, a := range audiences {
		if containsExact(clientIDs, a) {
			matched = true
		}
	}
	if !matched {
		return invalid("audience")
	}
	if len(audiences) > 1 {
		azp, _ := claims["azp"].(string)
		if !containsExact(clientIDs, azp) {
			return invalid("authorized party")
		}
	}
	return nil
}

func numericDate(v interface{}) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 || n > 1<<40 {
			return time.Time{}, false
		}
		sec := int64(n)
		return time.Unix(sec, int64((n-float64(sec))*1e9)), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return numericDate(f)
	}
	return time.Time{}, false
}

// nonceMatches compares the token's nonce with the raw nonce the server
// issued, or with its lowercase hex SHA-256 (the form Sign in with Apple's
// native flow carries). Both comparisons always run, in constant time.
func nonceMatches(tokenNonce, raw string) bool {
	if tokenNonce == "" || raw == "" {
		return false
	}
	sum := sha256.Sum256([]byte(raw))
	hashed := hex.EncodeToString(sum[:])
	rawOK := subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(raw))
	hashOK := subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(hashed))
	return rawOK|hashOK == 1
}

// boolClaim reads a boolean that some providers send as a string.
func boolClaim(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}
