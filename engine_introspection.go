package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// SessionInfo is the safe introspection view for a session.
// It intentionally excludes refresh hashes, token material, and raw mask bits.
type SessionInfo struct {
	SessionID         string
	CreatedAt         int64
	ExpiresAt         int64
	Role              string
	Status            AccountStatus
	AccountVersion    uint32
	PermissionVersion uint32
}

// HealthStatus is an on-demand backend health result.
type HealthStatus struct {
	RedisAvailable bool
	RedisLatency   time.Duration
}

func (e *Engine) GetActiveSessionCount(ctx context.Context, userID string) (int, error) {
	if e == nil || e.sessionStore == nil {
		return 0, ErrEngineNotReady
	}
	if userID == "" {
		return 0, ErrUserNotFound
	}

	tenantID, err := e.introspectionTenantFromContext(ctx)
	if err != nil {
		return 0, err
	}

	return e.sessionStore.ActiveSessionCount(ctx, tenantID, userID)
}

func (e *Engine) ListActiveSessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	if e == nil || e.sessionStore == nil {
		return nil, ErrEngineNotReady
	}
	if userID == "" {
		return nil, ErrUserNotFound
	}

	tenantID, err := e.introspectionTenantFromContext(ctx)
	if err != nil {
		return nil, err
	}

	sessionIDs, err := e.sessionStore.ActiveSessionIDs(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	sessions, err := e.sessionStore.GetManyReadOnly(ctx, tenantID, sessionIDs)
	if err != nil {
		return nil, err
	}

	out := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, toSessionInfo(sess))
	}

	return out, nil
}

func (e *Engine) GetSessionInfo(ctx context.Context, tenantID, sessionID string) (*SessionInfo, error) {
	if e == nil || e.sessionStore == nil {
		return nil, ErrEngineNotReady
	}
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	resolvedTenant, err := e.introspectionTenantFromParam(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	sess, err := e.sessionStore.GetReadOnly(ctx, resolvedTenant, sessionID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	info := toSessionInfo(sess)
	return &info, nil
}

func (e *Engine) ActiveSessionEstimate(ctx context.Context) (int, error) {
	if e == nil || e.sessionStore == nil {
		return 0, ErrEngineNotReady
	}

	tenantID, err := e.introspectionTenantFromContext(ctx)
	if err != nil {
		return 0, err
	}

	return e.sessionStore.EstimateActiveSessions(ctx, tenantID)
}

func (e *Engine) Health(ctx context.Context) HealthStatus {
	if e == nil || e.sessionStore == nil {
		return HealthStatus{}
	}

	latency, err := e.sessionStore.Ping(ctx)
	return HealthStatus{
		RedisAvailable: err == nil,
		RedisLatency:   latency,
	}
}

func (e *Engine) GetLoginAttempts(ctx context.Context, identifier string) (int, error) {
	if e == nil || e.rateLimiter == nil {
		return 0, ErrEngineNotReady
	}
	if identifier == "" {
		return 0, nil
	}

	return e.rateLimiter.GetLoginAttempts(ctx, identifier)
}

func toSessionInfo(sess *session.Session) SessionInfo {
	return SessionInfo{
		SessionID:         sess.SessionID,
		CreatedAt:         sess.CreatedAt,
		ExpiresAt:         sess.ExpiresAt,
		Role:              sess.Role,
		Status:            AccountStatus(sess.Status),
		AccountVersion:    sess.AccountVersion,
		PermissionVersion: sess.PermissionVersion,
	}
}

func (e *Engine) introspectionTenantFromContext(ctx context.Context) (string, error) {
	if e != nil && e.config.MultiTenant.Enabled {
		tenantID, ok := tenantIDFromContextExplicit(ctx)
		if !ok {
			return "", ErrUnauthorized
		}
		return tenantID, nil
	}
	return tenantIDFromContext(ctx), nil
}

func (e *Engine) introspectionTenantFromParam(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		if e != nil && e.config.MultiTenant.Enabled {
			return "", ErrUnauthorized
		}
		tenantID = tenantIDFromContext(ctx)
	}

	if contextTenant, ok := tenantIDFromContextExplicit(ctx); ok && contextTenant != tenantID {
		return "", ErrUnauthorized
	}

	return tenantID, nil
}
