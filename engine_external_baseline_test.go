package goAuth

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// extbCaptureEnv, when set, makes TestExternalAuthUnusedMatchesMain print the
// transcript instead of asserting it. The expected transcript below was
// produced by running this very file, with the variable set, against the
// commit this feature branched from (ba68cd7):
//
//	git worktree add ../goauth-base ba68cd7
//	cp engine_external_baseline_test.go ../goauth-base/
//	cd ../goauth-base && GOAUTH_CAPTURE_BASE=1 go test -run TestExternalAuthUnusedMatchesMain -v .
//
// The scenario only uses API that exists on that commit, so the file compiles
// on both sides. It reuses the transcript helpers of the session-profile
// baseline test.
const extbCaptureEnv = "GOAUTH_CAPTURE_BASE"

// extbSpuriousChallenge matches what spbArg prints when a random 32-byte hash
// happens to start with the byte 2, which its heuristic takes for an MFA
// challenge record (about one run in 256). This scenario has no MFA
// challenge, so any such rendering is really a 32-byte hash.
var extbSpuriousChallenge = regexp.MustCompile(`challenge:[0-9a-f]{64}`)

const (
	extbNewPassword = "second-password-456"
	extbWrong       = "wrong-password-123"
)

// extbRun logs in, refreshes, validates in all three modes, verifies and
// changes the password, fails logins, and logs out, with ExternalAuth left at
// its zero value. Every step records the Redis commands it sent.
func extbRun(t *testing.T) []string {
	t.Helper()
	env := newRSEnv(t, rsConfig(func(c *Config) {
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
			tr.add("  cmd %s", extbSpuriousChallenge.ReplaceAllString(c, "<bin32>"))
		}
	}

	var access, refresh, access2 string
	step("login", func() { access, refresh = env.login() })
	sid := env.sidOf(refresh)
	tr.know(sid)
	tr.add("  session ttl=%dms blob=%s", (env.mr.TTL(env.sessionKey(sid)).Milliseconds()+5000)/10000*10000, spbBlob([]byte(mustGet(t, env, env.sessionKey(sid)))))
	tr.add("  token %s", spbClaims(t, access))

	step("refresh", func() {
		var err error
		access2, _, err = env.engine.Refresh(ctx, refresh)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
	})
	tr.add("  token %s", spbClaims(t, access2))

	step("validate hybrid", func() { _, err := env.validate(access2, ModeHybrid); tr.add("  err %s", spbErr(err)) })
	step("validate jwt-only", func() { _, err := env.validate(access2, ModeJWTOnly); tr.add("  err %s", spbErr(err)) })
	step("validate strict", func() { _, err := env.validate(access2, ModeStrict); tr.add("  err %s", spbErr(err)) })

	step("verify password wrong", func() { tr.add("  err %s", spbErr(env.engine.VerifyPassword(ctx, rsUserID, extbWrong))) })
	step("verify password ok", func() { tr.add("  err %s", spbErr(env.engine.VerifyPassword(ctx, rsUserID, rsPassword))) })
	step("change password wrong old", func() {
		tr.add("  err %s", spbErr(env.engine.ChangePassword(ctx, rsUserID, extbWrong, extbNewPassword)))
	})
	step("change password reuse", func() {
		tr.add("  err %s", spbErr(env.engine.ChangePassword(ctx, rsUserID, rsPassword, rsPassword)))
	})
	step("change password", func() {
		tr.add("  err %s", spbErr(env.engine.ChangePassword(ctx, rsUserID, rsPassword, extbNewPassword)))
	})
	step("validate strict after change", func() { _, err := env.validate(access2, ModeStrict); tr.add("  err %s", spbErr(err)) })

	var refresh2 string
	step("login new password", func() {
		var err error
		_, refresh2, err = env.engine.Login(ctx, rsIdentifier, extbNewPassword)
		if err != nil {
			t.Fatalf("login with new password: %v", err)
		}
	})
	tr.know(env.sidOf(refresh2))
	step("login old password", func() {
		_, _, err := env.engine.Login(ctx, rsIdentifier, rsPassword)
		tr.add("  err %s", spbErr(err))
	})
	step("login empty password", func() {
		_, _, err := env.engine.Login(ctx, rsIdentifier, "")
		tr.add("  err %s", spbErr(err))
	})
	step("login unknown user", func() {
		_, _, err := env.engine.Login(ctx, "nobody@example.com", rsPassword)
		tr.add("  err %s", spbErr(err))
	})
	step("logout", func() { tr.add("  err %s", spbErr(env.engine.Logout(ctx, env.sidOf(refresh2)))) })
	step("logout all", func() { tr.add("  err %s", spbErr(env.engine.LogoutAll(ctx, rsUserID))) })

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
			if k == "identifier" || k == "reason" {
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

	keys := append([]string(nil), env.mr.Keys()...)
	sort.Strings(keys)
	tr.add("keys %s", strings.Join(keys, " "))

	return tr.normalized()
}

// With ExternalAuth left at its zero value (the default), login, refresh,
// validation, password verification and change, and both logouts behave
// exactly as on the commit before external identity existed: the Redis
// commands and their arguments, stored session bytes, key lifetimes, token
// claims, errors, audit events and metrics, and no new key appears.
func TestExternalAuthUnusedMatchesMain(t *testing.T) {
	got := extbRun(t)
	if os.Getenv(extbCaptureEnv) != "" {
		t.Logf("\n%s", strings.Join(got, "\n"))
		return
	}
	want := strings.Split(strings.TrimSpace(extbBaseTranscript), "\n")
	if len(got) != len(want) {
		t.Errorf("transcript has %d lines, the base had %d", len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			t.Errorf("line %d differs from the base:\n got: %s\nwant: %s", i+1, got[i], want[i])
		}
	}
	if t.Failed() {
		t.Logf("full transcript:\n%s", strings.Join(got, "\n"))
	}
}

const extbBaseTranscript = `
== login
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd script keys=[rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd del rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19
  cmd scard au:0:u1
  cmd multi
  cmd set as:0:<id1> blob:050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id1>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  session ttl=604800000ms blob=050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== refresh
  cmd get as:0:<id1>
  cmd script keys=[as:0:<id1> ast:0:count] argv=[<id1> au:0: <bin32> <bin32> <ts>]
  token claims=av,exp,iat,mask,pv,rv,sid,tid,uid ttl=300s
== validate hybrid
  err nil
== validate jwt-only
  err nil
== validate strict
  err nil
  cmd get as:0:<id1>
  cmd expire as:0:<id1> ~604800s
== verify password wrong
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:pwdverify:fail:0:u1] argv=[60000]
== verify password ok
  err nil
  cmd script keys=[rl:pwdverify:fail:0:u1] argv=[60000]
  cmd del rl:pwdverify:fail:0:u1
== change password wrong old
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:pwdverify:fail:0:u1] argv=[60000]
== change password reuse
  err AUTH_PASSWORD_REUSE/AUTH_VALIDATION
  cmd script keys=[rl:pwdverify:fail:0:u1] argv=[60000]
  cmd del rl:pwdverify:fail:0:u1
== change password
  err nil
  cmd script keys=[rl:pwdverify:fail:0:u1] argv=[60000]
  cmd del rl:pwdverify:fail:0:u1
  cmd script keys=[au:0:u1 ast:0:count] argv=[as:0: asa:0: ]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd del rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19
== validate strict after change
  err AUTH_SESSION_EXPIRED/AUTH_STATE
  cmd get as:0:<id1>
== login new password
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd script keys=[rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19] argv=[5 60000]
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
  cmd del rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19
  cmd scard au:0:u1
  cmd multi
  cmd set as:0:<id2> blob:050275310130077465616368657200000001000000010000000100080000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 lifetime=604800s ex 604800
  cmd sadd au:0:u1 <id2>
  cmd incr ast:0:count
  cmd exec
  cmd del rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053
== login old password
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
  cmd script keys=[rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19] argv=[5 60000]
== login empty password
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053] argv=[5 60000]
== login unknown user
  err AUTH_INVALID_CREDENTIALS/AUTH_VALIDATION
  cmd script keys=[rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:e788ea2014693dcdb86767aceb3860a432fc626c6477a6c53016aff40726842b] argv=[5 60000]
== logout
  err nil
  cmd get as:0:<id2>
  cmd script keys=[as:0:<id2> au:0:u1 ast:0:count] argv=[<id2>]
== logout all
  err nil
  cmd script keys=[au:0:u1 ast:0:count] argv=[as:0: asa:0: ]
audit login_success success=true user=u1 session=<id1> err= meta=[identifier=teacher@example.com]
audit refresh_success success=true user=u1 session=<id1> err= meta=[]
audit password_verify_failure success=false user=u1 session= err=invalid_credentials meta=[]
audit password_verify_success success=true user=u1 session= err= meta=[]
audit password_change_invalid_old success=false user=u1 session= err=invalid_credentials meta=[]
audit password_change_reuse_attempt success=false user=u1 session= err=password_reuse meta=[]
audit logout_all success=true user=u1 session= err= meta=[]
audit password_change_success success=true user=u1 session= err= meta=[]
audit login_success success=true user=u1 session=<id2> err= meta=[identifier=teacher@example.com]
audit login_failure success=false user=u1 session= err=invalid_credentials meta=[identifier=teacher@example.com reason=password_mismatch]
audit login_failure success=false user= session= err=invalid_credentials meta=[identifier=teacher@example.com reason=empty_password]
audit login_failure success=false user= session= err=invalid_credentials meta=[identifier=nobody@example.com reason=user_not_found]
audit logout_session success=true user= session=<id2> err= meta=[]
audit logout_all success=true user=u1 session= err= meta=[]
metric 0=2
metric 1=3
metric 3=1
metric 21=13
metric 25=2
metric 26=3
metric 27=1
metric 28=2
metric 32=1
metric 33=1
metric 34=1
keys rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:9beb1edd8c46a76b1eb950557175f686f7daf96bab8f8a05beb186f887287053 rl:login:fail:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:e788ea2014693dcdb86767aceb3860a432fc626c6477a6c53016aff40726842b rl:login:user:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19
`
