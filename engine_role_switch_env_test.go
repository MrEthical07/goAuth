package goAuth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	rsUserID     = "u1"
	rsIdentifier = "teacher@example.com"
	rsPassword   = "correct-password-123"
)

// rsEnv is a fully built engine with role switching enabled, a user who
// holds both the "teacher" (primary) and "admin" roles, and handles on every
// collaborator a test needs to assert on.
type rsEnv struct {
	t      *testing.T
	engine *Engine
	up     *roleSwitchMockProvider
	mr     *miniredis.Miniredis
	rdb    *redis.Client
	sink   *collectingSink
	cfg    Config
	tenant string
	cmds   *redisCommandLog
}

type rsOption func(*rsEnv, *Config)

func rsMultiTenant() rsOption {
	return func(env *rsEnv, cfg *Config) {
		cfg.MultiTenant.Enabled = true
		env.tenant = "tenant-a"
	}
}

func rsConfig(mutate func(*Config)) rsOption {
	return func(_ *rsEnv, cfg *Config) { mutate(cfg) }
}

// redisCommandLog records every command the engine sends, so a test can
// assert that a code path issued no extra Redis traffic.
type redisCommandLog struct {
	mu   sync.Mutex
	cmds [][]interface{}
}

func (l *redisCommandLog) DialHook(next redis.DialHook) redis.DialHook { return next }

func (l *redisCommandLog) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		l.mu.Lock()
		l.cmds = append(l.cmds, append([]interface{}(nil), cmd.Args()...))
		l.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (l *redisCommandLog) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		l.mu.Lock()
		for _, cmd := range cmds {
			l.cmds = append(l.cmds, append([]interface{}(nil), cmd.Args()...))
		}
		l.mu.Unlock()
		return next(ctx, cmds)
	}
}

func (l *redisCommandLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cmds = nil
}

// names returns the lower-cased command names in order.
func (l *redisCommandLog) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.cmds))
	for _, args := range l.cmds {
		if len(args) == 0 {
			continue
		}
		name, _ := args[0].(string)
		out = append(out, strings.ToLower(name))
	}
	return out
}

// touches reports whether any recorded command mentions a key containing substr.
func (l *redisCommandLog) touches(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, args := range l.cmds {
		for _, a := range args[1:] {
			if s, ok := a.(string); ok && strings.Contains(s, substr) {
				return true
			}
		}
	}
	return false
}

func newRSEnv(t *testing.T, opts ...rsOption) *rsEnv {
	t.Helper()

	mr, rdb := newTestRedis(t)
	t.Cleanup(mr.Close)
	t.Cleanup(func() { _ = rdb.Close() })

	env := &rsEnv{t: t, mr: mr, rdb: rdb, tenant: "0", sink: &collectingSink{}, cmds: &redisCommandLog{}}
	rdb.AddHook(env.cmds)

	cfg := totpTestConfig()
	// Cheap Argon2 keeps the suite fast; the production floor is a lint
	// concern, not what these tests exercise.
	cfg.Password.Memory = 8192
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.RoleSwitch.Enabled = true
	cfg.Audit.Enabled = true
	cfg.Metrics.Enabled = true
	cfg.Result.IncludeRole = true
	cfg.Result.IncludePermissions = true
	cfg.TOTP.EnforceReplayProtection = false
	for _, opt := range opts {
		opt(env, &cfg)
	}
	env.cfg = cfg

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		t.Fatalf("NewArgon2 failed: %v", err)
	}
	hash, err := hasher.Hash(rsPassword)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	env.up = newRoleSwitchMockProvider()
	env.up.addUser(UserRecord{
		UserID: rsUserID, Identifier: rsIdentifier, TenantID: env.tenant,
		PasswordHash: hash, Status: AccountActive, Role: "teacher",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	env.up.grant(rsUserID, "teacher", "admin")

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read", "perm.write"}).
		WithRoles(map[string][]string{
			"member":  {},
			"teacher": {"perm.read"},
			"admin":   {"perm.read", "perm.write"},
		}).
		WithUserProvider(env.up).
		WithAuditSink(env.sink).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	env.engine = engine
	t.Cleanup(engine.Close)
	return env
}

func (env *rsEnv) ctx() context.Context {
	if env.cfg.MultiTenant.Enabled {
		return WithTenantID(context.Background(), env.tenant)
	}
	return context.Background()
}

func (env *rsEnv) login() (access, refresh string) {
	env.t.Helper()
	access, refresh, err := env.engine.Login(env.ctx(), rsIdentifier, rsPassword)
	if err != nil {
		env.t.Fatalf("Login failed: %v", err)
	}
	return access, refresh
}

func (env *rsEnv) sidOf(refresh string) string {
	env.t.Helper()
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		env.t.Fatalf("decode refresh token: %v", err)
	}
	return sid
}

func (env *rsEnv) peek(sid string) *session.Session {
	env.t.Helper()
	sess, err := env.engine.sessionStore.Peek(context.Background(), env.tenant, sid)
	if err != nil {
		env.t.Fatalf("peek %s: %v", sid, err)
	}
	return sess
}

// sameSession reports whether two sessions encode to identical bytes (the
// Mask is a pointer, so the structs cannot be compared directly).
func sameSession(t *testing.T, a, b *session.Session) bool {
	t.Helper()
	ab, err := session.Encode(a)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	bb, err := session.Encode(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(ab) == string(bb)
}

// sessionKey is the Redis key of a session of the test tenant.
func (env *rsEnv) sessionKey(sid string) string {
	return env.cfg.Session.RedisPrefix + ":" + env.tenant + ":" + sid
}

func (env *rsEnv) hasSession(sid string) bool {
	env.t.Helper()
	_, err := env.engine.sessionStore.Peek(context.Background(), env.tenant, sid)
	return err == nil
}

func (env *rsEnv) sessionIDs() []string {
	env.t.Helper()
	ids, err := env.engine.sessionStore.ActiveSessionIDs(context.Background(), env.tenant, rsUserID)
	if err != nil {
		env.t.Fatalf("ActiveSessionIDs: %v", err)
	}
	sort.Strings(ids)
	return ids
}

func (env *rsEnv) keys(pattern string) []string {
	env.t.Helper()
	keys, err := env.rdb.Keys(context.Background(), pattern).Result()
	if err != nil {
		env.t.Fatalf("keys %s: %v", pattern, err)
	}
	sort.Strings(keys)
	return keys
}

func (env *rsEnv) validate(token string, mode RouteMode) (*AuthResult, error) {
	return env.engine.Validate(env.ctx(), token, mode)
}

func (env *rsEnv) switchRole(refresh, role string, opts RoleSwitchOptions) (*RoleSwitchResult, error) {
	return env.engine.SwitchRole(env.ctx(), refresh, role, opts)
}

// mustSwitch performs a switch that is expected to succeed.
func (env *rsEnv) mustSwitch(refresh, role string) *RoleSwitchResult {
	env.t.Helper()
	res, err := env.switchRole(refresh, role, RoleSwitchOptions{})
	if err != nil {
		env.t.Fatalf("SwitchRole(%s) failed: %v", role, err)
	}
	if res == nil || res.AccessToken == "" || res.RefreshToken == "" {
		env.t.Fatalf("SwitchRole(%s) returned an incomplete result: %+v", role, res)
	}
	return res
}

func (env *rsEnv) metric(id MetricID) uint64 {
	return env.engine.MetricsSnapshot().Counters[id]
}

// waitForAudit polls for an audit event: the dispatcher forwards events from
// its own goroutine.
func (env *rsEnv) waitForAudit(eventType, reason string) *AuditEvent {
	env.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if ev := env.sink.find(eventType, reason); ev != nil {
			return ev
		}
		if time.Now().After(deadline) {
			env.t.Fatalf("audit event %q (reason %q) was never emitted", eventType, reason)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// auditCount reports how many events of a type reached the sink so far. The
// dispatcher is asynchronous, so use waitForAudit to await an expected event.
func (env *rsEnv) auditCount(eventType string) int {
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	n := 0
	for _, ev := range env.sink.events {
		if ev.EventType == eventType {
			n++
		}
	}
	return n
}
