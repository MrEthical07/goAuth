package flows

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/jwt"
	"github.com/MrEthical07/goAuth/session"
)

// ModeResolverConfig allows host packages to resolve route/engine validation modes
// without importing host package-specific enums (avoids import cycles).
type ModeResolverConfig struct {
	ModeInherit int
	ModeJWTOnly int
	ModeHybrid  int
	ModeStrict  int
}

// ResolveRouteMode resolves a route mode override against engine default mode.
func ResolveRouteMode(routeMode, engineMode int, cfg ModeResolverConfig) (int, bool) {
	switch routeMode {
	case cfg.ModeInherit:
		switch engineMode {
		case cfg.ModeJWTOnly, cfg.ModeHybrid, cfg.ModeStrict:
			return engineMode, true
		default:
			return 0, false
		}
	case cfg.ModeJWTOnly:
		return cfg.ModeJWTOnly, true
	case cfg.ModeStrict:
		return cfg.ModeStrict, true
	default:
		return 0, false
	}
}

// ValidateFailureKind classifies validation failures for root-level mapping.
type ValidateFailureKind int

const (
	ValidateFailureNone ValidateFailureKind = iota
	ValidateFailureUnauthorized
	ValidateFailureTokenClockSkew
	ValidateFailureInvalidRouteMode
	ValidateFailureSessionNotFound
	ValidateFailureStatus
	ValidateFailureUnverified
	ValidateFailureDeviceBinding
)

// ValidateResult returns either claims/session success payload or classified failure.
type ValidateResult struct {
	Failure ValidateFailureKind
	Err     error
	Claims  *jwt.AccessClaims
	Session *session.Session
}

type ValidateSessionStore interface {
	Get(ctx context.Context, tenantID, sessionID string, ttl time.Duration) (*session.Session, error)
	Delete(ctx context.Context, tenantID, sessionID string) error
}

// ValidateDeps captures strict/hybrid/jwt-only validation dependencies.
type ValidateDeps struct {
	ParseAccess               func(string) (*jwt.AccessClaims, error)
	ResolveRouteMode          func(int) (int, error)
	Now                       func() time.Time
	MaxClockSkew              time.Duration
	ModeJWTOnly               int
	ModeHybrid                int
	EnablePermissionCheck     bool
	EnableRoleCheck           bool
	EnableAccountCheck        bool
	ShouldRequireVerified     func() bool
	PendingVerificationStatus uint8
	AccountStatusError        func(uint8) error
	ValidateDeviceBinding     func(context.Context, *session.Session) error
	TenantIDFromToken         func(uint32) string
	SessionLifetime           func() time.Duration
	SessionStore              ValidateSessionStore
	RedisUnavailable          error
	RedisNil                  error
}

// RunValidate executes access-token validation and strict-session checks.
func RunValidate(ctx context.Context, tokenStr string, routeMode int, deps ValidateDeps) ValidateResult {
	claims, err := deps.ParseAccess(tokenStr)
	if err != nil {
		return ValidateResult{Failure: ValidateFailureUnauthorized, Err: err}
	}
	if deps.MaxClockSkew >= 0 && claims.IssuedAt != nil {
		if claims.IssuedAt.Time.After(deps.Now().Add(deps.MaxClockSkew)) {
			return ValidateResult{Failure: ValidateFailureTokenClockSkew}
		}
	}

	effectiveMode, err := deps.ResolveRouteMode(routeMode)
	if err != nil {
		return ValidateResult{Failure: ValidateFailureInvalidRouteMode, Err: err}
	}

	// JWT-only and hybrid-default paths are stateless.
	if effectiveMode == deps.ModeJWTOnly || effectiveMode == deps.ModeHybrid {
		return ValidateResult{Claims: claims}
	}

	tenantID := deps.TenantIDFromToken(claims.TID)
	sess, err := deps.SessionStore.Get(ctx, tenantID, claims.SID, deps.SessionLifetime())
	if err != nil {
		if deps.RedisUnavailable != nil && errors.Is(err, deps.RedisUnavailable) {
			return ValidateResult{Failure: ValidateFailureUnauthorized, Err: err}
		}
		if deps.RedisNil != nil && errors.Is(err, deps.RedisNil) {
			return ValidateResult{Failure: ValidateFailureSessionNotFound, Err: err}
		}
		return ValidateResult{Failure: ValidateFailureSessionNotFound, Err: err}
	}

	if deps.EnablePermissionCheck && claims.PermVersion != sess.PermissionVersion {
		_ = deps.SessionStore.Delete(ctx, tenantID, claims.SID)
		return ValidateResult{Failure: ValidateFailureSessionNotFound}
	}
	if deps.EnableRoleCheck && claims.RoleVersion != sess.RoleVersion {
		_ = deps.SessionStore.Delete(ctx, tenantID, claims.SID)
		return ValidateResult{Failure: ValidateFailureSessionNotFound}
	}
	if deps.EnableAccountCheck &&
		claims.AccountVersion != 0 &&
		sess.AccountVersion != 0 &&
		claims.AccountVersion != sess.AccountVersion {
		_ = deps.SessionStore.Delete(ctx, tenantID, claims.SID)
		return ValidateResult{Failure: ValidateFailureSessionNotFound}
	}
	if statusErr := deps.AccountStatusError(sess.Status); statusErr != nil {
		_ = deps.SessionStore.Delete(ctx, tenantID, claims.SID)
		return ValidateResult{Failure: ValidateFailureStatus, Err: statusErr}
	}
	if deps.ShouldRequireVerified != nil &&
		deps.ShouldRequireVerified() &&
		sess.Status == deps.PendingVerificationStatus {
		_ = deps.SessionStore.Delete(ctx, tenantID, claims.SID)
		return ValidateResult{Failure: ValidateFailureUnverified}
	}
	if err := deps.ValidateDeviceBinding(ctx, sess); err != nil {
		return ValidateResult{Failure: ValidateFailureDeviceBinding, Err: err}
	}

	return ValidateResult{
		Claims:  claims,
		Session: sess,
	}
}
