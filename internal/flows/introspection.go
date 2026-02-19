package flows

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

type IntrospectionSessionStore interface {
	ActiveSessionCount(ctx context.Context, tenantID, userID string) (int, error)
	ActiveSessionIDs(ctx context.Context, tenantID, userID string) ([]string, error)
	GetManyReadOnly(ctx context.Context, tenantID string, sessionIDs []string) ([]*session.Session, error)
	GetReadOnly(ctx context.Context, tenantID, sessionID string) (*session.Session, error)
	EstimateActiveSessions(ctx context.Context, tenantID string) (int, error)
	Ping(ctx context.Context) (time.Duration, error)
}

type IntrospectionRateLimiter interface {
	GetLoginAttempts(ctx context.Context, identifier string) (int, error)
}

type IntrospectionDeps struct {
	SessionStore                IntrospectionSessionStore
	RateLimiter                 IntrospectionRateLimiter
	MultiTenantEnabled          bool
	TenantIDFromContext         func(context.Context) string
	TenantIDFromContextExplicit func(context.Context) (string, bool)
	UnauthorizedErr             error
	EngineNotReadyErr           error
	UserNotFoundErr             error
	SessionNotFoundErr          error
	RedisNil                    error
}

func resolveTenantFromContext(ctx context.Context, deps IntrospectionDeps) (string, error) {
	if deps.MultiTenantEnabled {
		tenantID, ok := deps.TenantIDFromContextExplicit(ctx)
		if !ok {
			return "", deps.UnauthorizedErr
		}
		return tenantID, nil
	}
	return deps.TenantIDFromContext(ctx), nil
}

func resolveTenantFromParam(ctx context.Context, tenantID string, deps IntrospectionDeps) (string, error) {
	if tenantID == "" {
		if deps.MultiTenantEnabled {
			return "", deps.UnauthorizedErr
		}
		tenantID = deps.TenantIDFromContext(ctx)
	}

	if contextTenant, ok := deps.TenantIDFromContextExplicit(ctx); ok && contextTenant != tenantID {
		return "", deps.UnauthorizedErr
	}

	return tenantID, nil
}

func RunGetActiveSessionCount(ctx context.Context, userID string, deps IntrospectionDeps) (int, error) {
	if deps.SessionStore == nil {
		return 0, deps.EngineNotReadyErr
	}
	if userID == "" {
		return 0, deps.UserNotFoundErr
	}

	tenantID, err := resolveTenantFromContext(ctx, deps)
	if err != nil {
		return 0, err
	}

	return deps.SessionStore.ActiveSessionCount(ctx, tenantID, userID)
}

func RunListActiveSessions(ctx context.Context, userID string, deps IntrospectionDeps) ([]*session.Session, error) {
	if deps.SessionStore == nil {
		return nil, deps.EngineNotReadyErr
	}
	if userID == "" {
		return nil, deps.UserNotFoundErr
	}

	tenantID, err := resolveTenantFromContext(ctx, deps)
	if err != nil {
		return nil, err
	}

	sessionIDs, err := deps.SessionStore.ActiveSessionIDs(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	return deps.SessionStore.GetManyReadOnly(ctx, tenantID, sessionIDs)
}

func RunGetSessionInfo(ctx context.Context, tenantID, sessionID string, deps IntrospectionDeps) (*session.Session, error) {
	if deps.SessionStore == nil {
		return nil, deps.EngineNotReadyErr
	}
	if sessionID == "" {
		return nil, deps.SessionNotFoundErr
	}

	resolvedTenant, err := resolveTenantFromParam(ctx, tenantID, deps)
	if err != nil {
		return nil, err
	}

	sess, err := deps.SessionStore.GetReadOnly(ctx, resolvedTenant, sessionID)
	if err != nil {
		if deps.RedisNil != nil && errors.Is(err, deps.RedisNil) {
			return nil, deps.SessionNotFoundErr
		}
		return nil, err
	}
	return sess, nil
}

func RunActiveSessionEstimate(ctx context.Context, deps IntrospectionDeps) (int, error) {
	if deps.SessionStore == nil {
		return 0, deps.EngineNotReadyErr
	}

	tenantID, err := resolveTenantFromContext(ctx, deps)
	if err != nil {
		return 0, err
	}

	return deps.SessionStore.EstimateActiveSessions(ctx, tenantID)
}

func RunHealth(ctx context.Context, deps IntrospectionDeps) (bool, time.Duration) {
	if deps.SessionStore == nil {
		return false, 0
	}
	latency, err := deps.SessionStore.Ping(ctx)
	return err == nil, latency
}

func RunGetLoginAttempts(ctx context.Context, identifier string, deps IntrospectionDeps) (int, error) {
	if deps.RateLimiter == nil {
		return 0, deps.EngineNotReadyErr
	}
	if identifier == "" {
		return 0, nil
	}
	return deps.RateLimiter.GetLoginAttempts(ctx, identifier)
}
