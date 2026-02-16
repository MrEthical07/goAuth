package jwt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningMethod defines a public type used by goAuth APIs.
//
// SigningMethod instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SigningMethod string

const (
	// MethodEd25519 is an exported constant or variable used by the authentication engine.
	MethodEd25519 SigningMethod = "ed25519"
	// MethodHS256 is an exported constant or variable used by the authentication engine.
	MethodHS256 SigningMethod = "hs256"
)

// Config defines a public type used by goAuth APIs.
//
// Config instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
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

// Manager defines a public type used by goAuth APIs.
//
// Manager instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Manager struct {
	config Config
}

// AccessClaims defines a public type used by goAuth APIs.
//
// AccessClaims instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
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

// NewManager describes the newmanager operation and its observable behavior.
//
// NewManager may return an error when input validation, dependency calls, or security checks fail.
// NewManager does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

	return &Manager{config: cfg}, nil
}

// CreateAccess describes the createaccess operation and its observable behavior.
//
// CreateAccess may return an error when input validation, dependency calls, or security checks fail.
// CreateAccess does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

// ParseAccess describes the parseaccess operation and its observable behavior.
//
// ParseAccess may return an error when input validation, dependency calls, or security checks fail.
// ParseAccess does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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
