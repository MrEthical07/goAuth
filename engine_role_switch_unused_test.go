package goAuth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// normalizedCommands returns the commands recorded since the last reset,
// without connection handshake traffic, with go-redis's EVALSHA-then-EVAL
// script fallback collapsed into one "script" call.
func (l *redisCommandLog) normalized() []string {
	names := l.names()
	out := make([]string, 0, len(names))
	for i := 0; i < len(names); i++ {
		name := names[i]
		switch name {
		case "hello", "client":
			continue
		case "evalsha":
			if i+1 < len(names) && names[i+1] == "eval" {
				i++
			}
			name = "script"
		case "eval":
			name = "script"
		}
		out = append(out, name)
	}
	return out
}

func jwtClaimKeys(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	claims := map[string]interface{}{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// With the feature unused (the default), behavior is byte-for-byte what
// v0.6.2 did: the same Redis traffic, the same access-token claims, the same
// errors, the same audit events and the same metrics. The expected values
// below were captured by running the same scenario against the v0.6.2 tag.
func TestRoleSwitchDisabledMatchesV062(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.RoleSwitch.Enabled = false }))
	log := env.cmds
	ctx := env.ctx()

	step := func(name string, want []string, run func()) {
		t.Helper()
		log.reset()
		run()
		if got := log.normalized(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: Redis commands = %v, want %v", name, got, want)
		}
	}

	var access, refresh, access2 string
	step("login", []string{"get", "scard", "multi", "set", "sadd", "incr", "exec", "del"}, func() {
		access, refresh = env.login()
	})
	step("refresh", []string{"script"}, func() {
		var err error
		access2, _, err = env.engine.Refresh(ctx, refresh)
		if err != nil {
			t.Fatalf("refresh failed: %v", err)
		}
	})
	step("hybrid validate", []string{}, func() { _, _ = env.validate(access2, ModeHybrid) })
	step("jwt-only validate", []string{}, func() { _, _ = env.validate(access2, ModeJWTOnly) })
	step("strict validate", []string{"get", "expire"}, func() {
		res, err := env.validate(access2, ModeStrict)
		if err != nil || res.Role != "teacher" {
			t.Fatalf("strict validate = (%+v, %v)", res, err)
		}
	})
	step("stale refresh token", []string{"script", "incr", "expire"}, func() {
		if _, _, err := env.engine.Refresh(ctx, refresh); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("stale refresh = %v, want ErrRefreshReuse", err)
		}
	})
	step("undecodable refresh token", []string{}, func() {
		if _, _, err := env.engine.Refresh(ctx, "garbage"); !errors.Is(err, ErrRefreshInvalid) {
			t.Fatalf("garbage refresh = %v, want ErrRefreshInvalid", err)
		}
	})

	wantClaims := []string{"av", "exp", "iat", "mask", "pv", "rv", "sid", "tid", "uid"}
	for name, token := range map[string]string{"login": access, "refresh": access2} {
		if got := jwtClaimKeys(t, token); !reflect.DeepEqual(got, wantClaims) {
			t.Fatalf("%s token claims = %v, want %v", name, got, wantClaims)
		}
	}

	if n := env.up.callCount(); n != 0 {
		t.Fatalf("the role-switch provider was called %d times while the feature is off", n)
	}
	for _, forbidden := range []string{"asa:", "rl:roleswitch"} {
		if keys := env.keys("*" + forbidden + "*"); len(keys) != 0 {
			t.Fatalf("keys %v written while the feature is off", keys)
		}
	}

	// Audit trail and metrics.
	env.engine.Close()
	var events []string
	env.sink.mu.Lock()
	for _, ev := range env.sink.events {
		events = append(events, ev.EventType+":"+ev.Metadata["reason"])
	}
	env.sink.mu.Unlock()
	wantEvents := []string{"login_success:", "refresh_success:", "refresh_reuse_detected:", "refresh_invalid:decode_failed"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("audit events = %v, want %v", events, wantEvents)
	}

	wantMetrics := map[MetricID]uint64{
		MetricLoginSuccess:         1,
		MetricRefreshSuccess:       1,
		MetricRefreshFailure:       1,
		MetricRefreshReuseDetected: 1,
		MetricReplayDetected:       1,
		MetricLimiterCheck:         1,
		MetricSessionCreated:       1,
		MetricSessionInvalidated:   1,
	}
	got := map[MetricID]uint64{}
	for id, v := range env.engine.MetricsSnapshot().Counters {
		if v != 0 {
			got[id] = v
		}
	}
	if !reflect.DeepEqual(got, wantMetrics) {
		t.Fatalf("metrics = %v, want %v", got, wantMetrics)
	}
}

// Enabling role switching without step-up policies changes nothing about
// login or validation, and refresh gains exactly one read plus one provider
// call.
func TestRoleSwitchEnabledAddsOnlyTheDocumentedCalls(t *testing.T) {
	env := newRSEnv(t)
	log := env.cmds
	ctx := env.ctx()

	log.reset()
	access, refresh := env.login()
	if got, want := log.normalized(), []string{"get", "scard", "multi", "set", "sadd", "incr", "exec", "del"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("login with role switching enabled used %v, want the unchanged %v", got, want)
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("login called the provider %d times", n)
	}

	log.reset()
	_, _ = env.validate(access, ModeHybrid)
	_, _ = env.validate(access, ModeJWTOnly)
	if got := log.normalized(); len(got) != 0 {
		t.Fatalf("stateless validation used Redis: %v", got)
	}
	log.reset()
	if _, err := env.validate(access, ModeStrict); err != nil {
		t.Fatalf("strict validate: %v", err)
	}
	if got, want := log.normalized(), []string{"get", "expire"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("strict validation used %v, want %v", got, want)
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("validation called the provider %d times", n)
	}

	log.reset()
	_, next, err := env.engine.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got, want := log.normalized(), []string{"get", "script"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("refresh with role switching enabled used %v, want %v (one extra read)", got, want)
	}
	if n := env.up.callCount(); n != 1 {
		t.Fatalf("refresh called the provider %d times, want exactly 1", n)
	}

	// The switched token has no role claim: the role lives in the session.
	sw := env.mustSwitch(next, "admin")
	wantClaims := []string{"av", "exp", "iat", "mask", "pv", "rv", "sid", "tid", "uid"}
	if got := jwtClaimKeys(t, sw.AccessToken); !reflect.DeepEqual(got, wantClaims) {
		t.Fatalf("switched token claims = %v, want %v", got, wantClaims)
	}
	if keys := env.keys("asa:*"); len(keys) != 0 {
		t.Fatalf("no step-up is configured but %v exists", keys)
	}
}
