package flows

import (
	"context"

	"github.com/MrEthical07/goAuth/jwt"
)

type LogoutSessionStore interface {
	Delete(ctx context.Context, tenantID, sessionID string) error
	DeleteAllForUser(ctx context.Context, tenantID, userID string) error
}

// LogoutDeps captures logout flow dependencies.
type LogoutDeps struct {
	ParseAccess         func(string) (*jwt.AccessClaims, error)
	TenantIDFromContext func(context.Context) string
	TenantIDFromToken   func(uint32) string
	SessionStore        LogoutSessionStore
}

type LogoutByAccessResult struct {
	TenantID  string
	SessionID string
	Err       error
}

func RunLogoutInTenant(ctx context.Context, tenantID, sessionID string, deps LogoutDeps) error {
	return deps.SessionStore.Delete(ctx, tenantID, sessionID)
}

func RunLogoutAllInTenant(ctx context.Context, tenantID, userID string, deps LogoutDeps) error {
	return deps.SessionStore.DeleteAllForUser(ctx, tenantID, userID)
}

func RunLogoutByAccessToken(ctx context.Context, tokenStr string, deps LogoutDeps) LogoutByAccessResult {
	claims, err := deps.ParseAccess(tokenStr)
	if err != nil {
		return LogoutByAccessResult{
			TenantID: deps.TenantIDFromContext(ctx),
			Err:      err,
		}
	}

	tenantID := deps.TenantIDFromToken(claims.TID)
	return LogoutByAccessResult{
		TenantID:  tenantID,
		SessionID: claims.SID,
		Err:       deps.SessionStore.Delete(ctx, tenantID, claims.SID),
	}
}
