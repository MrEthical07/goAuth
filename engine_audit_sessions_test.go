package goAuth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"
)

// Regression tests for the session-lifecycle findings of the v0.8.0 security
// audit (run 2). Each one is labelled FAILED-BEFORE with the finding ID: it
// fails on the commit the audit was run against and passes with the fix.

// loginParker parks the first password verification of the real account until
// release is called, which is the moment between "the login has read the
// account" and "the login stores its session".
type loginParker struct {
	armed  atomic.Bool
	parked chan struct{}
	gate   chan struct{}
}

func installLoginParker(engine *Engine, realHash string) *loginParker {
	p := &loginParker{parked: make(chan struct{}), gate: make(chan struct{})}
	p.armed.Store(true)
	engine.verifyHashFn = func(password, encodedHash string) (bool, error) {
		if encodedHash == realHash && p.armed.CompareAndSwap(true, false) {
			close(p.parked)
			<-p.gate
		}
		return engine.passwordHash.Verify(password, encodedHash)
	}
	return p
}

func (p *loginParker) release() { close(p.gate) }

// parkedLogin starts a login that parks in password verification and returns
// once it has parked, plus the channel its outcome arrives on.
func parkedLogin(t *testing.T, engine *Engine, p *loginParker, password string) <-chan error {
	t.Helper()
	out := make(chan error, 1)
	go func() {
		_, _, err := engine.Login(context.Background(), "alice", password)
		out <- err
	}()
	<-p.parked
	return out
}

func activeSessions(t *testing.T, engine *Engine) int {
	t.Helper()
	n, err := engine.sessionStore.ActiveSessionCount(context.Background(), "0", "u1")
	if err != nil {
		t.Fatalf("ActiveSessionCount: %v", err)
	}
	return n
}

// FAILED-BEFORE (R2-08): a login that had read the account before a password
// change still stored a live, refreshable session after the change had revoked
// everything.
func TestLoginRacingAPasswordChangeLeavesNoSession(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.ChangePassword(context.Background(), "u1", "correct-password-123", "another-password-456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	p.release()

	if err := <-outcome; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the racing login returned %v, want ErrInvalidCredentials", err)
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("%d session(s) survived the password change", n)
	}
}

// FAILED-BEFORE (R2-08): the same for DisableAccount.
func TestLoginRacingADisableLeavesNoSession(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.DisableAccount(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}
	p.release()

	if err := <-outcome; !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("the racing login returned %v, want ErrAccountDisabled", err)
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("%d session(s) survived DisableAccount", n)
	}
}

// A logout-all that is unrelated to the login (the account is still usable and
// the password is the one that was verified) does not fail the login: it
// retries once on the account as it is now.
func TestLoginRacingAnUnrelatedLogoutAllStillSucceeds(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, "correct-password-123")
	if err := engine.LogoutAll(context.Background(), "u1"); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	p.release()

	if err := <-outcome; err != nil {
		t.Fatalf("the racing login returned %v, want success", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("%d sessions, want the login's own", n)
	}
}

// FAILED-BEFORE (R2-08): the unparked schedule of the audit. Several loops of
// logins with the old password run while the owner changes it; when they stop
// no session may remain.
func TestOverlappingLoginsDoNotSurviveAPasswordChange(t *testing.T) {
	for round := 0; round < 4; round++ {
		cfg := accountTestConfig()
		cfg.Security.EnableLoginFailureLimiter = false
		up := newHardeningUserProvider(t)
		engine, _ := newAuditEngine(t, cfg, up)

		var wg sync.WaitGroup
		stop := make(chan struct{})
		started := make(chan struct{}, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started <- struct{}{}
				for {
					select {
					case <-stop:
						return
					default:
						_, _, _ = engine.Login(context.Background(), "alice", "correct-password-123")
					}
				}
			}()
		}
		for i := 0; i < 8; i++ {
			<-started
		}
		if err := engine.ChangePassword(context.Background(), "u1", "correct-password-123", "another-password-456"); err != nil {
			t.Fatalf("round %d: ChangePassword: %v", round, err)
		}
		close(stop)
		wg.Wait()

		if n := activeSessions(t, engine); n != 0 {
			t.Fatalf("round %d: %d session(s) created with the old password survived the change", round, n)
		}
		if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("round %d: the old password still logs in: %v", round, err)
		}
	}
}

// FAILED-BEFORE (R2-27): the session caps were checked at the password step
// only, so confirming several MFA challenges stored more sessions than the cap.
func TestMFAConfirmCannotExceedThePerUserSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 4)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	succeeded := 0
	for _, challenge := range challenges {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP))
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrSessionLimitExceeded):
		default:
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != cfg.SessionHardening.MaxSessionsPerUser {
		t.Fatalf("%d MFA logins stored a session, the cap is %d", succeeded, cfg.SessionHardening.MaxSessionsPerUser)
	}
	if n := activeSessions(t, engine); n != cfg.SessionHardening.MaxSessionsPerUser {
		t.Fatalf("user holds %d sessions, want %d", n, cfg.SessionHardening.MaxSessionsPerUser)
	}
}

// FAILED-BEFORE (R2-27): the shared tenant cap.
func TestMFAConfirmCannotExceedTheTenantSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerTenant = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 4)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	succeeded := 0
	for _, challenge := range challenges {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP))
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTenantSessionLimitExceeded):
		default:
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != 2 {
		t.Fatalf("%d MFA logins stored a session, the tenant cap is 2", succeeded)
	}
	if n, _ := engine.sessionStore.TenantSessionCount(context.Background(), "0"); n != 2 {
		t.Fatalf("tenant holds %d sessions, want 2", n)
	}
}

// FAILED-BEFORE (R2-27): and in parallel, where check-then-write cannot hold.
func TestParallelMFAConfirmsCannotExceedTheSessionCap(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 2
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenges := make([]string, 8)
	for i := range challenges {
		challenges[i] = mfaChallenge(t, engine)
	}
	code := codeForNow(t, secret, cfg.TOTP)
	errs := burst(t, len(challenges), 0, nil, func(i int) error {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenges[i], code)
		return err
	})
	succeeded := 0
	for _, err := range errs {
		// Confirmations beyond the account's TOTP budget in flight at once are
		// refused by that budget before their code is checked.
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrSessionLimitExceeded) && !errors.Is(err, ErrTOTPRateLimited) {
			t.Fatalf("confirm: %v", err)
		}
	}
	if succeeded != 2 || activeSessions(t, engine) != 2 {
		t.Fatalf("%d confirmations stored a session (%d held), the cap is 2", succeeded, activeSessions(t, engine))
	}
}

// FAILED-BEFORE (R2-28): with EnforceSingleSession the password step ended all
// of the account's sessions before the second factor, so a first-factor-only
// caller could sign the owner out repeatedly.
func TestPasswordStepOfAnMFALoginDoesNotEndExistingSessions(t *testing.T) {
	cfg := mfaLoginConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	first, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), codeForNow(t, secret, cfg.TOTP))
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Someone who only knows the password.
	pending := mfaChallenge(t, engine)
	if _, err := engine.Validate(ctx, first.AccessToken, ModeStrict); err != nil {
		t.Fatalf("the password step ended the owner's session: %v", err)
	}

	// The login that completes replaces it, as single-session mode promises.
	second, err := engine.ConfirmLoginMFA(ctx, pending, codeForNow(t, secret, cfg.TOTP))
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if _, err := engine.Validate(ctx, first.AccessToken, ModeStrict); err == nil {
		t.Fatal("single-session mode left the previous session alive after the new login completed")
	}
	if _, err := engine.Validate(ctx, second.AccessToken, ModeStrict); err != nil {
		t.Fatalf("the new session does not validate: %v", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}

// Single-session mode without MFA keeps its behavior: the new login replaces
// the old session.
func TestSingleSessionPasswordLoginStillReplacesThePreviousSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.EnforceSingleSession = true
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	ctx := context.Background()

	first, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Validate(ctx, first, ModeStrict); err == nil {
		t.Fatal("the previous session survived")
	}
	if _, err := engine.Validate(ctx, second, ModeStrict); err != nil {
		t.Fatalf("the new session does not validate: %v", err)
	}
}

// failOnceOnKey makes the first Redis command that names key fail, like a
// transient outage in the middle of a revocation.
type failOnceOnKey struct {
	key   string
	armed atomic.Bool
}

func (h *failOnceOnKey) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *failOnceOnKey) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		for _, a := range cmd.Args() {
			if s, ok := a.(string); ok && s == h.key && h.armed.CompareAndSwap(true, false) {
				return errors.New("transient redis failure")
			}
		}
		return next(ctx, cmd)
	}
}

func (h *failOnceOnKey) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func requireSessionRevoked(t *testing.T, engine *Engine, access, refresh string) {
	t.Helper()
	ctx := context.Background()
	if _, err := engine.Validate(ctx, access, ModeStrict); err == nil {
		t.Fatal("the old access token still validates strictly")
	}
	if _, _, err := engine.Refresh(ctx, refresh); err == nil {
		t.Fatal("the old refresh token still rotates")
	}
}

// FAILED-BEFORE (R2-12): DisableAccount committed the status and then failed to
// revoke the sessions; the retry saw the status already in place, returned nil
// and never revoked them.
func TestRetriedDisableAfterAFailedRevocationRevokesTheSessions(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	hook := &failOnceOnKey{key: "au:0:u1"}
	hook.armed.Store(true)
	rdb.AddHook(hook)

	if err := engine.DisableAccount(ctx, "u1"); !errors.Is(err, ErrSessionInvalidationFailed) {
		t.Fatalf("first DisableAccount: %v, want ErrSessionInvalidationFailed", err)
	}
	if up.users["u1"].Status != AccountDisabled {
		t.Fatalf("the status was not committed: %d", up.users["u1"].Status)
	}
	if err := engine.DisableAccount(ctx, "u1"); err != nil {
		t.Fatalf("retried DisableAccount: %v", err)
	}
	requireSessionRevoked(t, engine, access, refresh)
}

// FAILED-BEFORE (R2-12): a provider that commits the status without advancing
// the account version made DisableAccount fail before it revoked anything.
func TestDisableRevokesEvenWhenTheProviderDoesNotAdvanceTheVersion(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	up.skipStatusVersionBump = true
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.DisableAccount(ctx, "u1"); !errors.Is(err, ErrAccountVersionNotAdvanced) {
		t.Fatalf("DisableAccount: %v, want ErrAccountVersionNotAdvanced", err)
	}
	requireSessionRevoked(t, engine, access, refresh)
}

// FAILED-BEFORE (R2-12): a status the host wrote itself before the call.
func TestDisableOfAnAlreadyDisabledAccountStillRevokes(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	user := up.users["u1"]
	user.Status = AccountDisabled
	up.users["u1"] = user

	if err := engine.DisableAccount(ctx, "u1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}
	requireSessionRevoked(t, engine, access, refresh)
}

// Enabling an account that is already active remains a no-op.
func TestEnableOfAnActiveAccountIsStillANoOp(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	access, _, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.EnableAccount(ctx, "u1"); err != nil {
		t.Fatalf("EnableAccount: %v", err)
	}
	if _, err := engine.Validate(ctx, access, ModeStrict); err != nil {
		t.Fatalf("a no-op enable ended the session: %v", err)
	}
}

// FAILED-BEFORE (R2-09): a provider record whose tenant differs from the
// request's made password change and account disabling revoke under the
// record's tenant only, while the login had stored the session under the
// request's.
func TestRevocationReachesSessionsUnderTheContextTenantWhenTheRecordTenantDiffers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(ctx context.Context, e *Engine) error
	}{
		{"password change", func(ctx context.Context, e *Engine) error {
			return e.ChangePassword(ctx, "u1", "correct-password-123", "another-password-456")
		}},
		{"disable", func(ctx context.Context, e *Engine) error { return e.DisableAccount(ctx, "u1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := accountTestConfig()
			cfg.ValidationMode = ModeStrict
			up := newHardeningUserProvider(t)
			user := up.users["u1"]
			user.TenantID = "7"
			up.users["u1"] = user
			engine, _, done := newCreateAccountEngine(t, cfg, up)
			defer done()
			ctx := context.Background()

			access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.revoke(ctx, engine); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			requireSessionRevoked(t, engine, access, refresh)
		})
	}
}

func TestSessionRevocationTenants(t *testing.T) {
	for _, tc := range []struct {
		name, ctxTenant, record string
		want                    []string
	}{
		{"same tenant", "t1", "t1", []string{"t1"}},
		{"record has none", "t1", "", []string{"t1"}},
		{"default tenant spelled two ways", "", "0", []string{""}},
		{"different tenants", "t1", "t2", []string{"t1", "t2"}},
		{"default context, tenant record", "", "7", []string{"", "7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.ctxTenant != "" {
				ctx = WithTenantID(ctx, tc.ctxTenant)
			}
			got := sessionRevocationTenants(ctx, tc.record)
			want := make([]string, len(tc.want))
			for i, w := range tc.want {
				want[i] = w
				if w == "" {
					want[i] = tenantIDFromContext(ctx)
				}
			}
			if len(got) != len(want) {
				t.Fatalf("tenants = %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("tenants = %v, want %v", got, want)
				}
			}
		})
	}
}

// Every flow that ends a user's sessions goes through revokeUserSessions, so
// no call site can pick a single tenant on its own again.
func TestEveryEngineRevocationGoesThroughTheSharedHelper(t *testing.T) {
	files, err := filepath.Glob("engine*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "LogoutAllInTenant = e.LogoutAllInTenant") {
			t.Errorf("%s wires a flow's revocation to LogoutAllInTenant directly; use revokeUserSessions", f)
		}
	}
}

// FAILED-BEFORE (R2-08, MFA step): the confirmation read the revocation epoch
// when it ran, so a password change between the password step and the
// confirmation was invisible to the fence and the session it stored survived.
func TestMFAConfirmAfterARevocationSincePasswordStepStoresNoSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(e *Engine) error
	}{
		{"password change", func(e *Engine) error {
			return e.ChangePassword(context.Background(), "u1", "correct-password-123", "another-password-456")
		}},
		{"logout all", func(e *Engine) error { return e.LogoutAll(context.Background(), "u1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mfaLoginConfig()
			up := newHardeningUserProvider(t)
			engine, _ := newAuditEngine(t, cfg, up)
			secret := enableUserTOTP(t, engine, "u1", cfg)

			challenge := mfaChallenge(t, engine)
			if err := tc.revoke(engine); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if _, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP)); err == nil {
				t.Fatal("the confirmation stored a session after the revocation")
			}
			if n := activeSessions(t, engine); n != 0 {
				t.Fatalf("user holds %d sessions, want 0", n)
			}
		})
	}
}

// A challenge stored without an epoch (created by an earlier version) reads the
// epoch when it is confirmed, as before.
func TestMFAConfirmOfAChallengeWithoutAStoredEpochStillWorks(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenge := mfaChallenge(t, engine)
	removed := 0
	for _, key := range mr.Keys() {
		if strings.HasSuffix(key, ":ep") && strings.Contains(key, challenge) {
			mr.Del(key)
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("expected one stored epoch for the challenge, found %d", removed)
	}
	if _, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if n := activeSessions(t, engine); n != 1 {
		t.Fatalf("user holds %d sessions, want 1", n)
	}
}

func TestMFAChallengeEpochIsRemovedWithTheChallenge(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)

	challenge := mfaChallenge(t, engine)
	if _, err := engine.ConfirmLoginMFA(context.Background(), challenge, codeForNow(t, secret, cfg.TOTP)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, challenge) {
			t.Fatalf("challenge key %q survived its confirmation", key)
		}
	}
}

// A counter that drifted above the tenant cap is corrected by the login that
// finds it, whichever step does the correcting.
func TestLoginReconcilesADriftedTenantCounter(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.MaxSessionsPerTenant = 3
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	ctx := context.Background()

	if err := engine.sessionStore.SetTenantSessionCount(ctx, "0", 50); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
		t.Fatalf("a drifted counter refused a login: %v", err)
	}
	if n, _ := engine.sessionStore.TenantSessionCount(ctx, "0"); n != 1 {
		t.Fatalf("tenant counter = %d, want 1", n)
	}
}

// beforeSaveHook runs fn once, just before the session-save script reaches
// Redis: after the login has made every decision about the account.
type beforeSaveHook struct {
	fn    func()
	fired atomic.Bool
}

func (h *beforeSaveHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *beforeSaveHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if name := strings.ToLower(cmd.Name()); name != "evalsha" && name != "eval" {
			return next(ctx, cmd)
		}
		for _, a := range cmd.Args() {
			if s, ok := a.(string); ok && strings.HasPrefix(s, "aue:") && h.fired.CompareAndSwap(false, true) {
				h.fn()
				break
			}
		}
		return next(ctx, cmd)
	}
}

func (h *beforeSaveHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// FAILED-BEFORE (R2-08 follow-up): a login that was fenced by a revocation and
// retried on the re-read account issued a session although the revocation was
// the user enrolling a second factor, which the decisions made on the first
// read did not know about.
func TestFencedLoginIsNotRetriedAcrossAChangeToTheAccount(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	// The user enrols a factor after the password-only login has decided that
	// no second factor is needed, and before it stores its session.
	rdb.AddHook(&beforeSaveHook{fn: func() { enableUserTOTP(t, engine, "u1", cfg) }})
	_, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err == nil {
		t.Fatal("the login that decided before the second factor was enrolled got a session")
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("user holds %d sessions, want 0", n)
	}
}
