package goAuth

import (
	"context"
	"time"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/session"
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

// GetActiveSessionCount describes the getactivesessioncount operation and its observable behavior.
//
// GetActiveSessionCount may return an error when input validation, dependency calls, or security checks fail.
// GetActiveSessionCount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetActiveSessionCount(ctx context.Context, userID string) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunGetActiveSessionCount(ctx, userID, e.flowDeps.Introspection)
}

// ListActiveSessions describes the listactivesessions operation and its observable behavior.
//
// ListActiveSessions may return an error when input validation, dependency calls, or security checks fail.
// ListActiveSessions does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ListActiveSessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	e.ensureFlowDeps()
	sessions, err := internalflows.RunListActiveSessions(ctx, userID, e.flowDeps.Introspection)
	if err != nil {
		return nil, err
	}

	out := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, toSessionInfo(sess))
	}

	return out, nil
}

// GetSessionInfo describes the getsessioninfo operation and its observable behavior.
//
// GetSessionInfo may return an error when input validation, dependency calls, or security checks fail.
// GetSessionInfo does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetSessionInfo(ctx context.Context, tenantID, sessionID string) (*SessionInfo, error) {
	e.ensureFlowDeps()
	sess, err := internalflows.RunGetSessionInfo(ctx, tenantID, sessionID, e.flowDeps.Introspection)
	if err != nil {
		return nil, err
	}

	info := toSessionInfo(sess)
	return &info, nil
}

// ActiveSessionEstimate describes the activesessionestimate operation and its observable behavior.
//
// ActiveSessionEstimate may return an error when input validation, dependency calls, or security checks fail.
// ActiveSessionEstimate does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ActiveSessionEstimate(ctx context.Context) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunActiveSessionEstimate(ctx, e.flowDeps.Introspection)
}

// Health describes the health operation and its observable behavior.
//
// Health may return an error when input validation, dependency calls, or security checks fail.
// Health does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Health(ctx context.Context) HealthStatus {
	e.ensureFlowDeps()
	available, latency := internalflows.RunHealth(ctx, e.flowDeps.Introspection)
	return HealthStatus{
		RedisAvailable: available,
		RedisLatency:   latency,
	}
}

// GetLoginAttempts describes the getloginattempts operation and its observable behavior.
//
// GetLoginAttempts may return an error when input validation, dependency calls, or security checks fail.
// GetLoginAttempts does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetLoginAttempts(ctx context.Context, identifier string) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunGetLoginAttempts(ctx, identifier, e.flowDeps.Introspection)
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
