package goAuth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/session"
)

// SwitchRole always uses a fresh random session ID, so an occupied ID cannot
// happen through the public path; the mapping is pinned directly: it is an
// infrastructure failure, "unavailable", never a session-not-found.
func TestSwitchRoleSessionIDInUseIsUnavailable(t *testing.T) {
	env := newRSEnv(t)
	res, err := env.engine.roleSwitchFailure(env.ctx(), internalflows.RoleSwitchResult{
		Failure:  internalflows.RoleSwitchFailureUnavailable,
		Err:      fmt.Errorf("swap: %w", session.ErrSessionIDInUse),
		TenantID: "0",
	})
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
	assertBoundaryAuthError(t, err, ErrSystemUnavailable)
	if errors.Is(err, ErrSessionNotFound) {
		t.Fatal("an occupied replacement ID must not look like a logout")
	}
	env.waitForAudit(auditEventRoleSwitchFailed, "unavailable")
}

// Through the flow: a store that reports the ID as in use fails the switch
// as unavailable without touching the old session's refresh token.
func TestRunSwitchRoleStoreIDInUseIsUnavailable(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	deps := env.engine.roleSwitchFlowDeps()
	deps.SessionStore = idInUseStore{RoleSwitchSessionStore: env.engine.sessionStore}
	result := internalflows.RunSwitchRole(env.ctx(), refresh, "admin", internalflows.RoleSwitchOptions{}, deps)
	if result.Failure != internalflows.RoleSwitchFailureUnavailable || !errors.Is(result.Err, session.ErrSessionIDInUse) {
		t.Fatalf("result = %+v, want an unavailable failure carrying ErrSessionIDInUse", result)
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatal("the old session must be untouched")
	}
	if _, _, err := env.engine.Refresh(env.ctx(), refresh); err != nil {
		t.Fatalf("the same refresh token must still work: %v", err)
	}
}

type idInUseStore struct {
	internalflows.RoleSwitchSessionStore
}

func (idInUseStore) SwapSession(_ context.Context, _, _ string, _ [32]byte, _ *session.Session, _ *session.Assurance) error {
	return session.ErrSessionIDInUse
}
