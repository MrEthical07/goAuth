package goAuth

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// UpdateIdentifier makes every mock user provider an EmailChangeProvider, with
// the contract the interface documents: tenant-scoped, compare-and-set on the
// old identifier, case-insensitive uniqueness within the tenant, and an
// AccountVersion bump.
func (m *mockUserProvider) UpdateIdentifier(ctx context.Context, tenantID, userID, oldIdentifier, newIdentifier string) error {
	if m.beforeUpdateIdentifier != nil {
		m.beforeUpdateIdentifier()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateIdentifierCalls++
	if m.updateIdentifierErr != nil {
		return m.updateIdentifierErr
	}
	user, ok := m.users[userID]
	if !ok || user.TenantID != tenantID {
		return ErrUserNotFound
	}
	if user.Identifier != oldIdentifier {
		return ErrEmailChangeStale
	}
	for id, other := range m.users {
		if id != userID && other.TenantID == tenantID && strings.EqualFold(other.Identifier, newIdentifier) {
			return ErrProviderDuplicateIdentifier
		}
	}
	delete(m.byIdentifier, tenantIdentifierKey(tenantID, oldIdentifier))
	if m.byIdentifier[oldIdentifier] == userID {
		delete(m.byIdentifier, oldIdentifier)
	}
	m.byIdentifier[tenantIdentifierKey(tenantID, newIdentifier)] = userID
	if _, taken := m.byIdentifier[newIdentifier]; !taken {
		m.byIdentifier[newIdentifier] = userID
	}
	user.Identifier = newIdentifier
	user.AccountVersion++
	m.users[userID] = user
	return nil
}

var _ EmailChangeProvider = (*mockUserProvider)(nil)

const ecNewEmail = "new.address@example.com"

// ecEnv is the role-switch test engine with email change enabled: one Active
// user (rsUserID, rsIdentifier) with a password.
type ecEnv struct {
	*rsEnv
	logs *syncBuffer
}

// ecConfig enables email change with the OTP strategy and small limits.
func ecConfig(mutate func(*EmailChangeConfig)) rsOption {
	return rsConfig(func(c *Config) {
		c.EmailChange = EmailChangeConfig{
			Enabled:            true,
			Strategy:           VerificationOTP,
			OTPDigits:          6,
			VerificationTTL:    10 * time.Minute,
			MaxAttempts:        3,
			RequestMaxAttempts: 3,
			RequestCooldown:    time.Hour,
		}
		if mutate != nil {
			mutate(&c.EmailChange)
		}
	})
}

func newECEnv(t *testing.T, mutate func(*EmailChangeConfig), opts ...rsOption) *ecEnv {
	t.Helper()
	logs := &syncBuffer{}
	all := append([]rsOption{
		ecConfig(mutate),
		rsConfig(func(c *Config) {
			c.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			c.EmailVerification = testEmailVerificationConfig(VerificationOTP)
			c.PasswordReset = testResetConfig(ResetOTP)
		}),
	}, opts...)
	env := newRSEnv(t, all...)
	env.up.typedNotFound = true
	return &ecEnv{rsEnv: env, logs: logs}
}

func (env *ecEnv) request(newEmail string) (*EmailChangeRequest, error) {
	return env.engine.RequestEmailChange(env.ctx(), rsUserID, newEmail)
}

func (env *ecEnv) mustRequest(newEmail string) *EmailChangeRequest {
	env.t.Helper()
	req, err := env.request(newEmail)
	if err != nil {
		env.t.Fatalf("RequestEmailChange(%q): %v", newEmail, err)
	}
	return req
}

func (env *ecEnv) confirm(req *EmailChangeRequest, opts ConfirmEmailChangeOptions) (*EmailChangeResult, error) {
	return env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, req.Code, opts)
}

func (env *ecEnv) mustConfirm(req *EmailChangeRequest, opts ConfirmEmailChangeOptions) *EmailChangeResult {
	env.t.Helper()
	res, err := env.confirm(req, opts)
	if err != nil {
		env.t.Fatalf("ConfirmEmailChange: %v", err)
	}
	return res
}

func (env *ecEnv) user(id string) UserRecord {
	env.up.mu.Lock()
	defer env.up.mu.Unlock()
	return env.up.users[id]
}

func (env *ecEnv) setUser(u UserRecord) {
	env.up.mu.Lock()
	defer env.up.mu.Unlock()
	env.up.users[u.UserID] = u
}

// addOther registers another user in the test tenant.
func (env *ecEnv) addOther(id, identifier string) {
	env.up.addUser(UserRecord{
		UserID: id, Identifier: identifier, TenantID: env.tenant,
		Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	env.up.grant(id, "member")
}

// changeKeys are the challenge records and per-user pointers; the identifier
// change marker (aeci:*) is listed by markerKeys.
func (env *ecEnv) changeKeys() []string {
	env.t.Helper()
	return append(env.keys("aec:*"), env.keys("aecp:*")...)
}

func (env *ecEnv) markerKeys() []string {
	env.t.Helper()
	return env.keys("aeci:*")
}

// auditJSON is every audit event the engine emitted, serialized, for
// searching for things that must never appear in it.
func (env *ecEnv) auditJSON() string {
	env.t.Helper()
	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	b, err := json.Marshal(env.sink.events)
	if err != nil {
		env.t.Fatalf("marshal audit events: %v", err)
	}
	return string(b)
}

func (env *ecEnv) eventsOf(eventType string) []AuditEvent {
	env.t.Helper()
	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	var out []AuditEvent
	for _, ev := range env.sink.events {
		if ev.EventType == eventType {
			out = append(out, ev)
		}
	}
	return out
}
