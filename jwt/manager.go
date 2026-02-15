package jwt

import (
	"errors"
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
		},
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

	return token.SignedString(j.getSignKey())
}

// ParseAccess describes the parseaccess operation and its observable behavior.
//
// ParseAccess may return an error when input validation, dependency calls, or security checks fail.
// ParseAccess does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (j *Manager) ParseAccess(tokenStr string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		return j.getVerifyKey(), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
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

func (j *Manager) getSignKey() interface{} {
	switch j.config.SigningMethod {
	case MethodHS256:
		return j.config.PrivateKey
	default:
		return j.config.PrivateKey
	}
}

func (j *Manager) getVerifyKey() interface{} {
	switch j.config.SigningMethod {
	case MethodHS256:
		return j.config.PrivateKey
	default:
		return j.config.PublicKey
	}
}
