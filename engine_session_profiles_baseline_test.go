package goAuth

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// spbCaptureEnv, when set, makes TestSessionProfilesUnusedMatchesV070 print
// the transcript instead of asserting it. The expected transcript below was
// produced by running this very file, with the variable set, against the
// v0.7.0 tag:
//
//	git worktree add ../goauth-v070 v0.7.0
//	cp engine_session_profiles_baseline_test.go ../goauth-v070/
//	cd ../goauth-v070 && GOAUTH_CAPTURE_V070=1 go test -run TestSessionProfilesUnusedMatchesV070 -v .
//
// The scenario only uses API that exists in v0.7.0, so the file compiles on
// both sides.
const spbCaptureEnv = "GOAUTH_CAPTURE_V070"

// spbID matches the 22-character base64url identifiers sessions and MFA
// challenges are named with.
var spbID = regexp.MustCompile(`[A-Za-z0-9_-]{22}`)

// spbTranscript collects the observable behavior of one scenario run as a
// list of lines. Identifiers that differ per run (UUIDs, timestamps, hashes)
// are normalized; everything else is compared verbatim.
type spbTranscript struct {
	lines []string
	ids   []string
}

func (tr *spbTranscript) add(format string, args ...interface{}) {
	tr.lines = append(tr.lines, fmt.Sprintf(format, args...))
}

// normalized replaces every session and challenge identifier registered with
// know by a label numbered by first appearance.
func (tr *spbTranscript) normalized() []string {
	labels := map[string]string{}
	for i, id := range tr.ids {
		labels[id] = "<id" + strconv.Itoa(i+1) + ">"
	}
	out := make([]string, len(tr.lines))
	for i, line := range tr.lines {
		line = spbID.ReplaceAllStringFunc(line, func(id string) string {
			if l, ok := labels[id]; ok {
				return l
			}
			return id
		})
		if strings.HasPrefix(line, "keys ") {
			// Sorted after masking so the order does not depend on the ids.
			fields := strings.Fields(line)[1:]
			sort.Strings(fields)
			line = "keys " + strings.Join(fields, " ")
		}
		out[i] = line
	}
	return out
}

// know registers an identifier to be masked, numbered in registration order.
func (tr *spbTranscript) know(id string) {
	for _, have := range tr.ids {
		if have == id {
			return
		}
	}
	tr.ids = append(tr.ids, id)
}

// spbArg renders one Redis command argument. Session blobs are rendered by
// spbBlob, hashes and timestamps are masked, and Lua source is elided (the
// script text legitimately changes when the parsers learn a new schema
// version; its arguments must not).
func spbArg(arg interface{}) string {
	var raw []byte
	switch v := arg.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	case int64:
		if v > 1_000_000_000 {
			return "<ts>"
		}
		return fmt.Sprint(v)
	case int, uint64, float64, bool:
		return fmt.Sprint(v)
	default:
		return fmt.Sprintf("%v", v)
	}
	switch {
	case len(raw) > 100 && raw[0] == 5:
		return "blob:" + spbBlob(raw)
	// A random 32-byte hash must be recognized before the challenge case:
	// about one in 256 of them starts with the byte 2 and would otherwise be
	// rendered as an MFA challenge record, whose unmasked bytes differ per
	// run. No challenge in this scenario is exactly 32 bytes long.
	case len(raw) == 32 && !spbPrintable(raw):
		return "<bin32>"
	case len(raw) >= 13 && len(raw) < 100 && raw[0] == 2 && !spbPrintable(raw):
		return "challenge:" + spbChallenge(raw)
	case len(raw) > 200 && strings.Contains(string(raw), "redis.call"):
		return "<lua>"
	}
	s := string(raw)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 1_000_000_000 {
		return "<ts>"
	}
	return s
}

func spbPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// spbBlob renders a v5 session blob with the refresh hash (random) and the
// two timestamps masked; the timestamps are reported as the lifetime they
// encode.
func spbBlob(raw []byte) string {
	if len(raw) < 112 {
		return "short:" + hex.EncodeToString(raw)
	}
	masked := append([]byte(nil), raw...)
	end := len(masked)
	created := int64(binary.BigEndian.Uint64(masked[end-16:]))
	expires := int64(binary.BigEndian.Uint64(masked[end-8:]))
	for i := end - 112; i < end-80; i++ {
		masked[i] = 0xEE
	}
	for i := end - 16; i < end; i++ {
		masked[i] = 0
	}
	return fmt.Sprintf("%s lifetime=%ds", hex.EncodeToString(masked), expires-created)
}

// spbCommands renders the commands recorded since the last reset. The
// handshake is dropped and go-redis's EVALSHA-then-EVAL fallback is collapsed
// into one "script" entry whose keys and arguments are listed.
func spbCommands(l *redisCommandLog) []string {
	l.mu.Lock()
	cmds := make([][]interface{}, 0, len(l.cmds))
	for _, args := range l.cmds {
		// The handshake of a fresh connection can land between EVALSHA and
		// its EVAL fallback when a script is the first command sent.
		if len(args) > 0 {
			if name := strings.ToLower(fmt.Sprint(args[0])); name == "hello" || name == "client" {
				continue
			}
		}
		cmds = append(cmds, args)
	}
	l.mu.Unlock()

	var out []string
	for i := 0; i < len(cmds); i++ {
		args := cmds[i]
		if len(args) == 0 {
			continue
		}
		name := strings.ToLower(fmt.Sprint(args[0]))
		switch name {
		case "hello", "client":
			continue
		case "evalsha", "eval":
			if name == "evalsha" && i+1 < len(cmds) && strings.ToLower(fmt.Sprint(cmds[i+1][0])) == "eval" {
				i++
			}
			numKeys, _ := strconv.Atoi(fmt.Sprint(args[2]))
			var keys, argv []string
			for j, a := range args[3:] {
				if j < numKeys {
					keys = append(keys, spbArg(a))
				} else {
					argv = append(argv, spbArg(a))
				}
			}
			out = append(out, fmt.Sprintf("script keys=[%s] argv=[%s]", strings.Join(keys, " "), strings.Join(argv, " ")))
			continue
		}
		if name == "expire" && len(args) == 3 {
			secs, _ := strconv.ParseInt(fmt.Sprint(args[2]), 10, 64)
			out = append(out, fmt.Sprintf("expire %s ~%ds", spbArg(args[1]), (secs+5)/10*10))
			continue
		}
		parts := []string{name}
		for j, a := range args[1:] {
			// A remaining lifetime computed from the wall clock is rounded
			// to 10s for the same reason as in state().
			if prev := strings.ToLower(fmt.Sprint(args[j])); name == "set" && prev == "px" {
				ms, _ := strconv.ParseInt(fmt.Sprint(a), 10, 64)
				parts = append(parts, fmt.Sprintf("~%dms", (ms+5000)/10000*10000))
				continue
			}
			parts = append(parts, spbArg(a))
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func spbErr(err error) string {
	if err == nil {
		return "nil"
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		return string(ae.Code) + "/" + string(ae.Category)
	}
	return "raw:" + err.Error()
}

func spbClaims(t *testing.T, token string) string {
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
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	return fmt.Sprintf("claims=%s ttl=%ds", strings.Join(keys, ","), int64(exp-iat))
}

// spbRun runs the legacy scenario: every session-creating path, refresh,
// validation in all three modes, reuse, role switch, both logouts and an MFA
// login, with no session profile anywhere.
func spbRun(t *testing.T) []string {
	t.Helper()
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.TOTP.RequireForLogin = true
		c.Account.AutoLogin = true
		// Jitter is random by design; everything else is deterministic.
		c.Session.JitterEnabled = false
	}))
	ctx := env.ctx()
	tr := &spbTranscript{}

	step := func(name string, run func()) {
		t.Helper()
		env.cmds.reset()
		tr.add("== %s", name)
		run()
		for _, c := range spbCommands(env.cmds) {
			tr.add("  cmd %s", c)
		}
	}
	state := func(label, sid string) {
		t.Helper()
		tr.know(sid)
		key := env.sessionKey(sid)
		// Rounded to 10s: a sliding renewal is computed from the wall clock,
		// which may cross a second boundary between two steps.
		ttl := (env.mr.TTL(key).Milliseconds() + 5000) / 10000 * 10000
		tr.add("  %s ttl=%dms blob=%s", label, ttl, spbBlob([]byte(mustGet(t, env, key))))
		members, _ := env.mr.Members("au:" + env.tenant + ":" + rsUserID)
		tr.add("  %s index=%d count=%s", label, len(members), mustGetOrEmpty(env, "ast:"+env.tenant+":count"))
	}

	var access, refresh, access2 string

	step("login", func() { access, refresh = env.login() })
	sid := env.sidOf(refresh)
	state("session", sid)
	tr.add("  token %s", spbClaims(t, access))

	var rememberRefresh string
	tr.know(sid)
	step("login remember-me", func() {
		res, err := env.engine.LoginWithOptions(ctx, rsIdentifier, rsPassword, LoginOptions{RememberMe: true})
		if err != nil || res.RefreshToken == "" {
			t.Fatalf("remember-me login: %v", err)
		}
		rememberRefresh = res.RefreshToken
	})
	state("session", env.sidOf(rememberRefresh))

	step("refresh", func() {
		var err error
		access2, _, err = env.engine.Refresh(ctx, refresh)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
	})
	state("session", sid)
	tr.add("  token %s", spbClaims(t, access2))

	step("validate hybrid", func() { _, err := env.validate(access2, ModeHybrid); tr.add("  err %s", spbErr(err)) })
	step("validate jwt-only", func() { _, err := env.validate(access2, ModeJWTOnly); tr.add("  err %s", spbErr(err)) })
	step("validate strict", func() { _, err := env.validate(access2, ModeStrict); tr.add("  err %s", spbErr(err)) })
	state("session", sid)

	step("refresh reuse", func() { _, _, err := env.engine.Refresh(ctx, refresh); tr.add("  err %s", spbErr(err)) })
	step("refresh undecodable", func() { _, _, err := env.engine.Refresh(ctx, "garbage"); tr.add("  err %s", spbErr(err)) })
	step("validate strict after reuse", func() { _, err := env.validate(access2, ModeStrict); tr.add("  err %s", spbErr(err)) })

	var swapRefresh string
	step("login for role switch", func() { _, swapRefresh = env.login() })
	tr.know(env.sidOf(swapRefresh))
	var switched *RoleSwitchResult
	step("role switch", func() { switched = env.mustSwitch(swapRefresh, "admin") })
	state("switched", env.sidOf(switched.RefreshToken))
	tr.add("  token %s", spbClaims(t, switched.AccessToken))

	step("logout", func() { tr.add("  err %s", spbErr(env.engine.Logout(ctx, env.sidOf(switched.RefreshToken)))) })
	step("logout all", func() { tr.add("  err %s", spbErr(env.engine.LogoutAll(ctx, rsUserID))) })

	step("login wrong password", func() {
		_, _, err := env.engine.Login(ctx, rsIdentifier, "wrong-password-123")
		tr.add("  err %s", spbErr(err))
	})
	step("login unknown user", func() {
		_, _, err := env.engine.Login(ctx, "nobody@example.com", rsPassword)
		tr.add("  err %s", spbErr(err))
	})

	var created *CreateAccountResult
	step("create account auto-login", func() {
		var err error
		created, err = env.engine.CreateAccount(ctx, CreateAccountRequest{
			Identifier: "new@example.com", Password: "brand-new-password-1", Role: "member",
		})
		if err != nil || created.RefreshToken == "" {
			t.Fatalf("create account: %v", err)
		}
	})
	state("auto-login session", env.sidOf(created.RefreshToken))
	tr.add("  token %s", spbClaims(t, created.AccessToken))

	secret := enableUserTOTP(t, env.engine, rsUserID, env.cfg)
	var challenge *LoginResult
	step("mfa login step 1", func() {
		var err error
		challenge, err = env.engine.LoginWithResult(ctx, rsIdentifier, rsPassword)
		if err != nil || !challenge.MFARequired {
			t.Fatalf("mfa step 1: %v %+v", err, challenge)
		}
	})
	tr.know(challenge.MFASession)
	record := []byte(mustGet(t, env, "amc:"+challenge.MFASession))
	tr.add("  challenge ttl=%dms bytes=%s", env.mr.TTL("amc:"+challenge.MFASession).Milliseconds(), spbChallenge(record))

	var confirmed *LoginResult
	step("mfa wrong code", func() {
		_, err := env.engine.ConfirmLoginMFA(ctx, challenge.MFASession, "000000")
		tr.add("  err %s", spbErr(err))
	})
	record = []byte(mustGet(t, env, "amc:"+challenge.MFASession))
	tr.add("  challenge after failure bytes=%s", spbChallenge(record))
	step("mfa login step 2", func() {
		var err error
		confirmed, err = env.engine.ConfirmLoginMFA(ctx, challenge.MFASession, codeForOffset(t, secret, env.cfg.TOTP, 1))
		if err != nil {
			t.Fatalf("mfa step 2: %v", err)
		}
	})
	state("mfa session", env.sidOf(confirmed.RefreshToken))
	tr.add("  token %s", spbClaims(t, confirmed.AccessToken))

	// Audit trail and metrics.
	env.engine.Close()
	env.sink.mu.Lock()
	for _, ev := range env.sink.events {
		keys := make([]string, 0, len(ev.Metadata))
		for k := range ev.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var meta []string
		for _, k := range keys {
			v := ev.Metadata[k]
			if k == "identifier" || k == "reason" || k == "from_role" || k == "to_role" || strings.HasSuffix(k, "_session_id") || k == "role" {
				meta = append(meta, k+"="+v)
			} else {
				meta = append(meta, k+"=<"+strconv.Itoa(len(v))+">")
			}
		}
		tr.add("audit %s success=%v user=%s session=%s err=%s meta=[%s]", ev.EventType, ev.Success, ev.UserID, ev.SessionID, ev.Error, strings.Join(meta, " "))
	}
	env.sink.mu.Unlock()

	counters := env.engine.MetricsSnapshot().Counters
	ids := make([]int, 0, len(counters))
	for id, v := range counters {
		if v != 0 {
			ids = append(ids, int(id))
		}
	}
	sort.Ints(ids)
	for _, id := range ids {
		tr.add("metric %d=%d", id, counters[MetricID(id)])
	}

	// Nothing but the legacy keyspace may exist.
	prefixes := append([]string(nil), env.mr.Keys()...)
	sort.Strings(prefixes)
	tr.add("keys %s", strings.Join(prefixes, " "))

	return tr.normalized()
}

func spbChallenge(raw []byte) string {
	masked := append([]byte(nil), raw...)
	if len(masked) >= 11 {
		for i := 3; i < 11; i++ {
			masked[i] = 0
		}
	}
	return hex.EncodeToString(masked)
}

func mustGet(t *testing.T, env *rsEnv, key string) string {
	t.Helper()
	v, err := env.mr.Get(key)
	if err != nil {
		t.Fatalf("miniredis get %s: %v", key, err)
	}
	return v
}

func mustGetOrEmpty(env *rsEnv, key string) string {
	v, err := env.mr.Get(key)
	if err != nil {
		return ""
	}
	return v
}

// With no session profile configured (the default), everything observable
// matches v0.7.0: the Redis commands and their arguments, the stored session
// and MFA challenge bytes, key lifetimes, token claims and lifetimes,
// errors, audit events and metrics.
func TestSessionProfilesUnusedMatchesV070(t *testing.T) {
	got := spbRun(t)
	if os.Getenv(spbCaptureEnv) != "" {
		t.Logf("\n%s", strings.Join(got, "\n"))
		return
	}
	want := strings.Split(strings.TrimSpace(spbV070Transcript), "\n")
	if len(got) != len(want) {
		t.Errorf("transcript has %d lines, v0.7.0 had %d", len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			t.Errorf("line %d differs from v0.7.0:\n got: %s\nwant: %s", i+1, got[i], want[i])
		}
	}
	if t.Failed() {
		t.Logf("full transcript:\n%s", strings.Join(got, "\n"))
	}
}

const spbV070Transcript = `
== login
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd scard au:0:u1
  cmd multi
  cmd set as:0:<id1> blob:050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id1>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  session index=1 count=1
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== login remember-me
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd scard au:0:u1
  cmd multi
  cmd set as:0:<id2> blob:050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id2>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  session index=2 count=2
== refresh
  cmd get as:0:<id1>
  cmd script keys=[as:0:<id1> ast:0:count] argv=[<id1> au:0: <bin32> <bin32> <ts>]
  session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  session index=2 count=2
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== validate hybrid
  err nil
== validate jwt-only
  err nil
== validate strict
  err nil
  cmd get as:0:<id1>
  cmd expire as:0:<id1> ~604800s
  session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  session index=2 count=2
== refresh reuse
  err AUTH_REFRESH_REUSE_DETECTED/AUTH_ABUSE
  cmd get as:0:<id1>
  cmd script keys=[as:0:<id1> ast:0:count] argv=[<id1> au:0: <bin32> <bin32> <ts>]
  cmd incr arp:<id1>
  cmd expire arp:<id1> ~604800s
== refresh undecodable
  err AUTH_REFRESH_INVALID/AUTH_VALIDATION
== validate strict after reuse
  err AUTH_SESSION_EXPIRED/AUTH_STATE
  cmd get as:0:<id1>
== login for role switch
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd scard au:0:u1
  cmd multi
  cmd set as:0:<id3> blob:050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id3>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
== role switch
  cmd script keys=[rl:roleswitch:0:<id3>] argv=[900000]
  cmd get as:0:<id3>
  cmd script keys=[as:0:<id3> as:0:<id4> ast:0:count asa:0:<id3> asa:0:<id4>] argv=[<id3> au:0: <bin32> <ts> blob:0502753101300561646d696e00000001000000010000000100080000000000000003eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s <id4>  u1]
  cmd del rl:roleswitch:0:<id3>
  switched ttl=604800000ms blob=0502753101300561646d696e00000001000000010000000100080000000000000003eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  switched index=2 count=2
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== logout
  err nil
  cmd get as:0:<id4>
  cmd script keys=[as:0:<id4> au:0:u1 ast:0:count] argv=[<id4>]
== logout all
  err nil
  cmd script keys=[au:0:u1 ast:0:count] argv=[as:0: asa:0: ]
== login wrong password
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
== login unknown user
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:e788ea2014693dcdb86767aceb3860a432fc626c6477a6c53016aff40726842b] argv=[5 60000]
== create account auto-login
  cmd script keys=[rl:account:req:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:f0030501023327437b06e5c6f87df7871b8e704ae608d1d0b7b24fdd2a06c716] argv=[60000]
  cmd multi
  cmd set as:0:<id5> blob:050275320130066d656d62657200000001000000010000000100080000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u2 <id5>
  cmd incr ast:0:count
  cmd exec
  auto-login session ttl=604800000ms blob=050275320130066d656d62657200000001000000010000000100080000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  auto-login session index=0 count=1
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== mfa login step 1
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd scard au:0:u1
  cmd set amc:<id6> challenge:02000000000000000000000002753100013000 ex 180
  challenge ttl=180000ms bytes=02000000000000000000000002753100013000
== mfa wrong code
  err AUTH_MFA_INVALID_CODE/AUTH_VALIDATION
  cmd get amc:<id6>
  cmd script keys=[amc:<id6>] argv=[5 <ts>]
  cmd script keys=[rl:totp:fail:0:u1] argv=[5 60000]
  challenge after failure bytes=02000100000000000000000002753100013000
== mfa login step 2
  cmd get amc:<id6>
  cmd script keys=[amc:<id6>] argv=[5 <ts>]
  cmd script keys=[rl:totp:fail:0:u1] argv=[5 60000]
  cmd del rl:totp:fail:0:u1
  cmd del amc:<id6>
  cmd multi
  cmd set as:0:<id7> blob:050275310130077465616368657200000001000000010000000200080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id7>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  mfa session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000200080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  mfa session index=1 count=2
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
audit login_success success=true user=u1 session=<id1> err= meta=[identifier=teacher@example.com]
audit login_success success=true user=u1 session=<id2> err= meta=[identifier=teacher@example.com]
audit refresh_success success=true user=u1 session=<id1> err= meta=[]
audit refresh_reuse_detected success=false user= session=<id1> err=refresh_reuse meta=[]
audit refresh_invalid success=false user= session= err=invalid_token meta=[reason=decode_failed]
audit login_success success=true user=u1 session=<id3> err= meta=[identifier=teacher@example.com]
audit role_switched success=true user=u1 session=<id4> err= meta=[from_role=teacher new_session_id=<id4> old_session_id=<id3> to_role=admin]
audit logout_session success=true user= session=<id4> err= meta=[]
audit logout_all success=true user=u1 session= err= meta=[]
audit login_failure success=false user=u1 session= err=invalid_credentials meta=[identifier=teacher@example.com reason=password_mismatch]
audit login_failure success=false user= session= err=invalid_credentials meta=[identifier=nobody@example.com reason=user_not_found]
audit account_creation_success success=true user=u2 session= err= meta=[identifier=new@example.com role=member]
audit totp_setup_requested success=true user=u1 session= err= meta=[]
audit logout_all success=true user=u1 session= err= meta=[]
audit totp_enabled success=true user=u1 session= err= meta=[]
audit mfa_required success=true user=u1 session= err= meta=[identifier=teacher@example.com]
audit mfa_failure success=false user=u1 session= err=mfa_invalid meta=[]
audit login_success success=true user=u1 session=<id7> err= meta=[identifier=teacher@example.com]
audit mfa_success success=true user=u1 session= err= meta=[]
metric 0=4
metric 1=2
metric 3=1
metric 4=1
metric 5=1
metric 6=1
metric 12=1
metric 13=1
metric 14=1
metric 15=1
metric 21=11
metric 25=5
metric 26=4
metric 27=1
metric 28=2
metric 29=1
keys arp:<id1> as:0:<id5> as:0:<id7> ast:0:count au:0:u1 au:0:u2 rl:account:req:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:f0030501023327437b06e5c6f87df7871b8e704ae608d1d0b7b24fdd2a06c716 rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:e788ea2014693dcdb86767aceb3860a432fc626c6477a6c53016aff40726842b
`
