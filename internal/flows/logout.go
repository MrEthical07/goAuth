package flows

import (
	"context"
	"time"

	"github.com/MrEthical07/goAuth/jwt"
)

type LogoutSessionStore interface {
	Delete(ctx context.Context, tenantID, sessionID string) error
	DeleteAllForUser(ctx context.Context, tenantID, userID string) error
}

// LogoutDeps captures logout flow dependencies.
type LogoutDeps struct {
	// ParseAccessAllowExpired accepts authentic tokens whose only defect is
	// expiry, so an expired session can still be logged out gracefully.
	ParseAccessAllowExpired func(string) (*jwt.AccessClaims, error)
	TenantIDFromContext     func(context.Context) string
	TenantIDFromToken       func(string) string
	Now                     func() time.Time
	SessionStore            LogoutSessionStore

	// PeekProfile, when set, reports the session profile of a session just
	// before it is destroyed, for the audit trail. The engine sets it only
	// while session profiles are configured.
	PeekProfile func(ctx context.Context, tenantID, sessionID string) string
}

type LogoutByAccessResult struct {
	TenantID  string
	SessionID string
	// TokenExpired reports that the access token was expired but otherwise
	// authentic; surfaced as audit metadata, not as an error.
	TokenExpired bool
	// Profile is the destroyed session's profile, when PeekProfile is wired.
	Profile string
	Err     error
}

func RunLogoutInTenant(ctx context.Context, tenantID, sessionID string, deps LogoutDeps) error {
	return deps.SessionStore.Delete(ctx, tenantID, sessionID)
}

func RunLogoutAllInTenant(ctx context.Context, tenantID, userID string, deps LogoutDeps) error {
	return deps.SessionStore.DeleteAllForUser(ctx, tenantID, userID)
}

func RunLogoutByAccessToken(ctx context.Context, tokenStr string, deps LogoutDeps) LogoutByAccessResult {
	claims, err := deps.ParseAccessAllowExpired(tokenStr)
	if err != nil {
		return LogoutByAccessResult{
			TenantID: deps.TenantIDFromContext(ctx),
			Err:      err,
		}
	}

	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}
	expired := claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now())

	tenantID := deps.TenantIDFromToken(claims.TID)
	profile := ""
	if deps.PeekProfile != nil {
		profile = deps.PeekProfile(ctx, tenantID, claims.SID)
	}
	return LogoutByAccessResult{
		TenantID:     tenantID,
		SessionID:    claims.SID,
		TokenExpired: expired,
		Profile:      profile,
		Err:          deps.SessionStore.Delete(ctx, tenantID, claims.SID),
	}
}
