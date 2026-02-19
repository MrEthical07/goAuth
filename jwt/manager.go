package jwt

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningMethod identifies the JWT signing algorithm (e.g., ES256, RS256, HS256).
//
//	Docs: docs/jwt.md
type SigningMethod string

const (
	// MethodEd25519 is an exported constant or variable used by the authentication engine.
	MethodEd25519 SigningMethod = "ed25519"
	// MethodHS256 is an exported constant or variable used by the authentication engine.
	MethodHS256 SigningMethod = "hs256"
)

// Config holds JWT manager initialization parameters: TTLs, signing keys,
// issuer, audience, leeway, and IAT validation options.
//
//	Docs: docs/jwt.md
type Config struct {
	AccessTTL     time.Duration
	SigningMethod SigningMethod
	PrivateKey    []byte
	PublicKey     []byte
	Issuer        string
	Audience      string
	Leeway        time.Duration
	RequireIAT    bool
	MaxFutureIAT  time.Duration
	KeyID         string
	VerifyKeys    map[string][]byte
}

// Manager handles JWT access token creation and parsing. It holds the signing
// key, parser, and claim validation options. Safe for concurrent use.
//
//	Docs: docs/jwt.md
type Manager struct {
	config        Config
	parsedSignKey interface{} // cached at init: ed25519.PrivateKey or []byte (HS256)
	fast          *fastJWTState
}

// fastJWTState holds pre-computed state for zero-overhead JWT creation.
type fastJWTState struct {
	headerB64 string     // pre-computed base64url(json_header)
	hmacPool  *sync.Pool // reusable HMAC hashers (HS256 only)
}

// fastClaimsPayload avoids *NumericDate and ClaimStrings allocations.
type fastClaimsPayload struct {
	UID  string `json:"uid"`
	TID  uint32 `json:"tid,omitempty"`
	SID  string `json:"sid"`
	Mask []byte `json:"mask,omitempty"`
	PV   uint32 `json:"pv,omitempty"`
	RV   uint32 `json:"rv,omitempty"`
	AV   uint32 `json:"av,omitempty"`
	Iss  string `json:"iss,omitempty"`
	Aud  string `json:"aud,omitempty"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

// AccessClaims represents the decoded claims from a JWT access token,
// including user ID, tenant, session ID, permission mask, and version
// counters.
//
//	Docs: docs/jwt.md
type AccessClaims struct {
	UID            string `json:"uid"`
	TID            uint32 `json:"tid,omitempty"`
	SID            string `json:"sid"`
	Mask           []byte `json:"mask,omitempty"`
	PermVersion    uint32 `json:"pv,omitempty"`
	RoleVersion    uint32 `json:"rv,omitempty"`
	AccountVersion uint32 `json:"av,omitempty"`
	jwt.RegisteredClaims
}

// NewManager creates a JWT [Manager] from the given [Config]. It
// initializes the signing key, parser, and claim validation options.
//
//	Docs: docs/jwt.md
func NewManager(cfg Config) (*Manager, error) {
	if cfg.AccessTTL <= 0 {
		return nil, errors.New("invalid TTL configuration")
	}
	if cfg.Leeway < 0 || cfg.Leeway > 2*time.Minute {
		return nil, errors.New("invalid leeway configuration")
	}
	if cfg.MaxFutureIAT == 0 {
		cfg.MaxFutureIAT = 10 * time.Minute
	}
	if cfg.MaxFutureIAT < 0 || cfg.MaxFutureIAT > 24*time.Hour {
		return nil, errors.New("invalid MaxFutureIAT configuration")
	}
	cfg.KeyID = strings.TrimSpace(cfg.KeyID)
	switch cfg.SigningMethod {
	case MethodHS256:
		if len(cfg.PrivateKey) == 0 {
			return nil, errors.New("hs256 requires private key")
		}
	case MethodEd25519:
		if len(cfg.PrivateKey) > 0 {
			if _, err := parseEdPrivateKey(cfg.PrivateKey); err != nil {
				return nil, err
			}
		}
		if len(cfg.PublicKey) > 0 {
			if _, err := parseEdPublicKey(cfg.PublicKey); err != nil {
				return nil, err
			}
		}
		if len(cfg.VerifyKeys) == 0 && len(cfg.PublicKey) == 0 {
			return nil, errors.New("ed25519 requires public key or verify key set")
		}
		for kid, key := range cfg.VerifyKeys {
			if strings.TrimSpace(kid) == "" {
				return nil, errors.New("verify key map contains empty kid")
			}
			if _, err := parseEdPublicKey(key); err != nil {
				return nil, fmt.Errorf("invalid ed25519 verify key for kid %q: %w", kid, err)
			}
		}
	default:
		return nil, errors.New("unsupported signing method")
	}
	if cfg.KeyID != "" && len(cfg.VerifyKeys) > 0 {
		if _, ok := cfg.VerifyKeys[cfg.KeyID]; !ok {
			return nil, errors.New("KeyID is not present in VerifyKeys")
		}
	}

	m := &Manager{config: cfg}

	// Pre-parse and cache the signing key to avoid per-call parsing.
	switch cfg.SigningMethod {
	case MethodHS256:
		m.parsedSignKey = cfg.PrivateKey
	case MethodEd25519:
		if len(cfg.PrivateKey) > 0 {
			sk, err := parseEdPrivateKey(cfg.PrivateKey)
			if err != nil {
				return nil, err
			}
			m.parsedSignKey = sk
		}
	}

	m.initFastJWT()

	return m, nil
}

func (j *Manager) initFastJWT() {
	// Pre-compute base64url-encoded header (deterministic JSON via sorted map keys).
	header := map[string]string{
		"alg": j.getMethod().Alg(),
		"typ": "JWT",
	}
	if j.config.KeyID != "" {
		header["kid"] = j.config.KeyID
	}
	headerJSON, _ := json.Marshal(header)

	state := &fastJWTState{
		headerB64: base64.RawURLEncoding.EncodeToString(headerJSON),
	}

	if j.config.SigningMethod == MethodHS256 {
		key := j.config.PrivateKey
		state.hmacPool = &sync.Pool{
			New: func() interface{} {
				return hmac.New(sha256.New, key)
			},
		}
	}

	j.fast = state
}

// CreateAccess mints a signed JWT access token with the given claims
// (userID, tenantID, sessionID, permission mask, version counters).
//
//	Performance: single ECDSA/RSA/HMAC sign operation.
//	Docs: docs/jwt.md
func (j *Manager) CreateAccess(
	uid string,
	tid uint32,
	sid string,
	mask []byte,
	permVersion uint32,
	roleVersion uint32,
	accountVersion uint32,
	includeMask bool,
	includePermVersion bool,
	includeRoleVersion bool,
	includeAccountVersion bool,
	isRoot bool,
) (string, error) {

	// Fast path: build JWT directly without library overhead.
	if j.fast != nil && j.parsedSignKey != nil {
		return j.createAccessFast(
			uid, tid, sid, mask,
			permVersion, roleVersion, accountVersion,
			includeMask, includePermVersion, includeRoleVersion, includeAccountVersion,
			isRoot,
		)
	}

	// Legacy path (fallback).
	return j.createAccessLegacy(
		uid, tid, sid, mask,
		permVersion, roleVersion, accountVersion,
		includeMask, includePermVersion, includeRoleVersion, includeAccountVersion,
		isRoot,
	)
}

func (j *Manager) createAccessFast(
	uid string, tid uint32, sid string, mask []byte,
	permVersion, roleVersion, accountVersion uint32,
	includeMask, includePermVersion, includeRoleVersion, includeAccountVersion bool,
	isRoot bool,
) (string, error) {
	ttl := j.config.AccessTTL
	if isRoot && ttl > 2*time.Minute {
		ttl = 2 * time.Minute
	}

	now := time.Now()
	payload := fastClaimsPayload{
		UID: uid,
		TID: tid,
		SID: sid,
		Exp: now.Add(ttl).Unix(),
		Iat: now.Unix(),
		Iss: j.config.Issuer,
		Aud: j.config.Audience,
	}
	if includeMask {
		payload.Mask = mask
	}
	if includePermVersion {
		payload.PV = permVersion
	}
	if includeRoleVersion {
		payload.RV = roleVersion
	}
	if includeAccountVersion {
		payload.AV = accountVersion
	}

	claimsJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Compute sizes for single-allocation token buffer.
	headerLen := len(j.fast.headerB64)
	claimsB64Len := base64.RawURLEncoding.EncodedLen(len(claimsJSON))
	var sigRawSize int
	switch j.config.SigningMethod {
	case MethodHS256:
		sigRawSize = sha256.Size
	default:
		sigRawSize = ed25519.SignatureSize
	}
	sigB64Len := base64.RawURLEncoding.EncodedLen(sigRawSize)
	totalLen := headerLen + 1 + claimsB64Len + 1 + sigB64Len

	buf := make([]byte, totalLen)
	copy(buf, j.fast.headerB64)
	buf[headerLen] = '.'
	base64.RawURLEncoding.Encode(buf[headerLen+1:], claimsJSON)
	buf[headerLen+1+claimsB64Len] = '.'

	signingInput := buf[:headerLen+1+claimsB64Len]
	sigDst := buf[headerLen+1+claimsB64Len+1:]

	switch j.config.SigningMethod {
	case MethodHS256:
		mac := j.fast.hmacPool.Get().(hash.Hash)
		mac.Reset()
		mac.Write(signingInput)
		var rawSig [sha256.Size]byte
		mac.Sum(rawSig[:0])
		j.fast.hmacPool.Put(mac)
		base64.RawURLEncoding.Encode(sigDst, rawSig[:])
	default:
		privKey, ok := j.parsedSignKey.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("cached sign key is not ed25519")
		}
		sig := ed25519.Sign(privKey, signingInput)
		base64.RawURLEncoding.Encode(sigDst, sig)
	}

	return string(buf), nil
}

func (j *Manager) createAccessLegacy(
	uid string, tid uint32, sid string, mask []byte,
	permVersion, roleVersion, accountVersion uint32,
	includeMask, includePermVersion, includeRoleVersion, includeAccountVersion bool,
	isRoot bool,
) (string, error) {

	ttl := j.config.AccessTTL

	if isRoot {
		// root TTL override: 2 minutes
		if ttl > 2*time.Minute {
			ttl = 2 * time.Minute
		}
	}

	claims := AccessClaims{
		UID: uid,
		TID: tid,
		SID: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    j.config.Issuer,
		},
	}
	if j.config.Audience != "" {
		claims.Audience = jwt.ClaimStrings{j.config.Audience}
	}

	if includeMask {
		claims.Mask = mask
	}

	if includePermVersion {
		claims.PermVersion = permVersion
	}
	if includeRoleVersion {
		claims.RoleVersion = roleVersion
	}
	if includeAccountVersion {
		claims.AccountVersion = accountVersion
	}

	token := jwt.NewWithClaims(j.getMethod(), claims)
	if j.config.KeyID != "" {
		token.Header["kid"] = j.config.KeyID
	}

	signKey, err := j.getSignKey()
	if err != nil {
		return "", err
	}

	return token.SignedString(signKey)
}

// ParseAccess verifies and parses a JWT access token, returning the
// embedded claims. Returns an error if the signature, expiry, issuer,
// or audience checks fail.
//
//	Performance: single signature verify + claim decode.
//	Docs: docs/jwt.md
func (j *Manager) ParseAccess(tokenStr string) (*AccessClaims, error) {
	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{j.getMethod().Alg()}),
	}
	if j.config.Leeway > 0 {
		options = append(options, jwt.WithLeeway(j.config.Leeway))
	}
	if j.config.RequireIAT {
		options = append(options, jwt.WithIssuedAt())
	}
	if j.config.Issuer != "" {
		options = append(options, jwt.WithIssuer(j.config.Issuer))
	}
	if j.config.Audience != "" {
		options = append(options, jwt.WithAudience(j.config.Audience))
	}

	parser := jwt.NewParser(options...)
	token, err := parser.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != j.getMethod().Alg() {
			return nil, fmt.Errorf("unexpected signing algorithm: %s", t.Method.Alg())
		}

		if len(j.config.VerifyKeys) > 0 {
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("missing kid")
			}
			key, ok := j.config.VerifyKeys[kid]
			if !ok {
				return nil, errors.New("unknown kid")
			}
			return j.keyBytesToVerifyKey(key)
		}

		if j.config.KeyID != "" {
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("missing kid")
			}
			if kid != j.config.KeyID {
				return nil, errors.New("unknown kid")
			}
		}

		return j.getVerifyKey()
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if j.config.RequireIAT && claims.IssuedAt == nil {
		return nil, errors.New("token missing required iat claim")
	}
	if claims.IssuedAt != nil && j.config.MaxFutureIAT > 0 {
		maxAllowed := time.Now().Add(j.config.MaxFutureIAT)
		if claims.IssuedAt.Time.After(maxAllowed) {
			return nil, errors.New("token iat too far in the future")
		}
	}

	return claims, nil
}

func (j *Manager) getMethod() jwt.SigningMethod {
	switch j.config.SigningMethod {
	case MethodHS256:
		return jwt.SigningMethodHS256
	default:
		return jwt.SigningMethodEdDSA
	}
}

func (j *Manager) getSignKey() (interface{}, error) {
	if j.parsedSignKey != nil {
		return j.parsedSignKey, nil
	}
	switch j.config.SigningMethod {
	case MethodHS256:
		return j.config.PrivateKey, nil
	default:
		return parseEdPrivateKey(j.config.PrivateKey)
	}
}

func (j *Manager) getVerifyKey() (interface{}, error) {
	switch j.config.SigningMethod {
	case MethodHS256:
		return j.config.PrivateKey, nil
	default:
		return parseEdPublicKey(j.config.PublicKey)
	}
}

func (j *Manager) keyBytesToVerifyKey(key []byte) (interface{}, error) {
	switch j.config.SigningMethod {
	case MethodHS256:
		return key, nil
	default:
		return parseEdPublicKey(key)
	}
}

func parseEdPrivateKey(key []byte) (ed25519.PrivateKey, error) {
	if len(key) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(key), nil
	}
	parsed, err := jwt.ParseEdPrivateKeyFromPEM(key)
	if err != nil {
		return nil, errors.New("invalid ed25519 private key")
	}
	edKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid ed25519 private key type")
	}
	return edKey, nil
}

func parseEdPublicKey(key []byte) (ed25519.PublicKey, error) {
	if len(key) == ed25519.PublicKeySize {
		return ed25519.PublicKey(key), nil
	}
	parsed, err := jwt.ParseEdPublicKeyFromPEM(key)
	if err != nil {
		return nil, errors.New("invalid ed25519 public key")
	}
	edKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("invalid ed25519 public key type")
	}
	return edKey, nil
}
