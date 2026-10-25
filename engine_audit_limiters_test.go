package goAuth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// Regression tests for the limiter findings of the v0.8.0 security audit
// (run 2). Each one is labelled FAILED-BEFORE with the finding ID: it fails on
// the commit the audit was run against and passes with the fix.

// gatedProvider wraps the shared test provider for the burst tests. Lookups can
// be parked on a gate so a test controls when verification may start, folding
// makes the lookup case-insensitive (the provider shape the audit assumed for
// the spelling findings), and the counters are safe under -race.
type gatedProvider struct {
	*mockUserProvider
	fold    bool
	gate    chan struct{}
	lookups atomic.Int64
}

func newGatedProvider(t *testing.T, fold bool) *gatedProvider {
	t.Helper()
	return &gatedProvider{mockUserProvider: newHardeningUserProvider(t), fold: fold}
}

func (p *gatedProvider) GetUserByIdentifier(identifier string) (UserRecord, error) {
	p.lookups.Add(1)
	if p.gate != nil {
		<-p.gate
	}
	key := identifier
	if p.fold {
		key = strings.ToLower(identifier)
	}
	id, ok := p.byIdentifier[key]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}
	return p.users[id], nil
}

// burst runs n calls released together and returns their errors in call order.
// While gate is non-nil the calls that reach the provider stay parked until
// every call that is going to be refused up front has returned (or the
// deadline passes, which is what happens when nothing refuses them).
func burst(t *testing.T, n, wantRefused int, gate chan struct{}, call func(i int) error) []error {
	t.Helper()
	type result struct {
		i   int
		err error
	}
	out := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			out <- result{i, call(i)}
		}(i)
	}
	close(start)

	errs := make([]error, n)
	got := 0
	deadline := time.After(3 * time.Second)
collect:
	for got < wantRefused {
		select {
		case r := <-out:
			errs[r.i] = r.err
			got++
		case <-deadline:
			break collect
		}
	}
	if gate != nil {
		close(gate)
	}
	for ; got < n; got++ {
		r := <-out
		errs[r.i] = r.err
	}
	return errs
}

func countErrs(errs []error, targets ...error) (matched int) {
	for _, err := range errs {
		for _, target := range targets {
			if errors.Is(err, target) {
				matched++
				break
			}
		}
	}
	return matched
}

// FAILED-BEFORE (R2-05): the login gate read the failure counter, verified the
// password and only then recorded the failure, so every request in a burst saw
// a count below the limit and ran Argon2.
func TestLoginConcurrentBurstBoundedByMaxLoginAttempts(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	up.gate = make(chan struct{})
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	const n = 40
	max := cfg.Security.MaxLoginAttempts
	errs := burst(t, n, n-max, up.gate, func(i int) error {
		_, _, err := engine.Login(context.Background(), "alice", fmt.Sprintf("wrong-password-%d", i))
		return err
	})

	if got := up.lookups.Load(); got != int64(max) {
		t.Fatalf("%d of %d concurrent logins reached verification, want exactly MaxLoginAttempts (%d)", got, n, max)
	}
	if got := countErrs(errs, ErrInvalidCredentials); got != max {
		t.Fatalf("%d logins were verified and rejected, want %d (errors: %v)", got, max, errs)
	}
	if got := countErrs(errs, ErrLoginRateLimited); got != n-max {
		t.Fatalf("%d logins were rate limited, want %d", got, n-max)
	}
}

// The sequential behavior is unchanged: the sixth attempt is the first one
// refused, and the password is not verified for it.
func TestLoginSequentialAttemptsRefusedAtTheSameNumber(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for i := 1; i <= cfg.Security.MaxLoginAttempts; i++ {
		if _, _, err := engine.Login(ctx, "alice", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v, want ErrInvalidCredentials", i, err)
		}
	}
	if _, _, err := engine.Login(ctx, "alice", "wrong-password-123"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("attempt %d: %v, want ErrLoginRateLimited", cfg.Security.MaxLoginAttempts+1, err)
	}
	if got := up.lookups.Load(); got != int64(cfg.Security.MaxLoginAttempts) {
		t.Fatalf("the refused attempt reached verification: %d lookups", got)
	}
}

// A correct password is bounded by the same budget: a guess hidden in the
// sixth position is not evaluated.
func TestLoginCorrectPasswordAfterTheBudgetIsRefused(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for i := 0; i < cfg.Security.MaxLoginAttempts; i++ {
		_, _, _ = engine.Login(ctx, "alice", "wrong-password-123")
	}
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("a correct password past the budget got %v, want ErrLoginRateLimited", err)
	}
}

// A good login clears the budget it claimed.
func TestLoginSuccessResetsTheClaim(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for round := 0; round < 3; round++ {
		for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
			_, _, _ = engine.Login(ctx, "alice", "wrong-password-123")
		}
		if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
			t.Fatalf("round %d: login failed: %v", round, err)
		}
	}
	if attempts, err := engine.GetLoginAttempts(ctx, "alice"); err != nil || attempts != 0 {
		t.Fatalf("GetLoginAttempts = %d, %v; a good login must leave nothing behind", attempts, err)
	}
}

// gatedBackupProvider parks every backup-code evaluation on a gate and counts
// them. The code is always wrong.
type gatedBackupProvider struct {
	*mockUserProvider
	gate     chan struct{}
	consumes atomic.Int64
}

func (p *gatedBackupProvider) ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error) {
	p.consumes.Add(1)
	if p.gate != nil {
		<-p.gate
	}
	return false, nil
}

// gateTOTPEvaluations makes every TOTP code evaluation park on gate, count
// itself and report a wrong code.
func gateTOTPEvaluations(engine *Engine, gate chan struct{}) *atomic.Int64 {
	var evals atomic.Int64
	engine.verifyTOTPFn = func([]byte, string, time.Time) (bool, int64, error) {
		evals.Add(1)
		<-gate
		return false, 0, nil
	}
	return &evals
}

// requireBoundedEvaluations checks a burst of wrong codes: exactly max codes
// were evaluated, max-1 of them answered "invalid", and everything else,
// including the evaluation that filled the budget, was "rate limited".
func requireBoundedEvaluations(t *testing.T, errs []error, evaluated int64, max int, invalid, limited error) {
	t.Helper()
	if evaluated != int64(max) {
		t.Fatalf("%d of %d concurrent attempts were evaluated, want exactly the budget (%d)", evaluated, len(errs), max)
	}
	if got := countErrs(errs, invalid); got != max-1 {
		t.Fatalf("%d attempts answered %v, want %d (errors: %v)", got, invalid, max-1, errs)
	}
	if got := countErrs(errs, limited); got != len(errs)-max+1 {
		t.Fatalf("%d attempts answered %v, want %d", got, limited, len(errs)-max+1)
	}
}

// FAILED-BEFORE (R2-10): VerifyTOTP read the failure counter, evaluated the
// code and recorded the failure afterwards, so a burst evaluated far more
// codes than the budget.
func TestVerifyTOTPConcurrentBurstBoundedByMaxAttempts(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	enableUserTOTP(t, engine, "u1", cfg)

	gate := make(chan struct{})
	evals := gateTOTPEvaluations(engine, gate)
	const n = 40
	max := cfg.TOTP.MFALoginMaxAttempts
	errs := burst(t, n, n-max, gate, func(i int) error {
		return engine.VerifyTOTP(context.Background(), "u1", fmt.Sprintf("%06d", i))
	})
	requireBoundedEvaluations(t, errs, evals.Load(), max, ErrTOTPInvalid, ErrTOTPRateLimited)
}

// FAILED-BEFORE (R2-10): the same race on the enrolment confirmation.
func TestConfirmTOTPSetupConcurrentBurstBoundedByMaxAttempts(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	if _, err := engine.GenerateTOTPSetup(context.Background(), "u1"); err != nil {
		t.Fatalf("GenerateTOTPSetup: %v", err)
	}

	gate := make(chan struct{})
	evals := gateTOTPEvaluations(engine, gate)
	const n = 40
	max := cfg.TOTP.MFALoginMaxAttempts
	errs := burst(t, n, n-max, gate, func(i int) error {
		return engine.ConfirmTOTPSetup(context.Background(), "u1", fmt.Sprintf("%06d", i))
	})
	requireBoundedEvaluations(t, errs, evals.Load(), max, ErrTOTPInvalid, ErrTOTPRateLimited)
}

// FAILED-BEFORE (R2-10): the same race on the inline step-up check that backs
// backup-code regeneration, password-reset MFA and role switching.
func TestVerifyTOTPForUserConcurrentBurstBoundedByMaxAttempts(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	enableUserTOTP(t, engine, "u1", cfg)

	gate := make(chan struct{})
	evals := gateTOTPEvaluations(engine, gate)
	const n = 40
	max := cfg.TOTP.MFALoginMaxAttempts
	errs := burst(t, n, n-max, gate, func(i int) error {
		_, err := engine.RegenerateBackupCodes(context.Background(), "u1", fmt.Sprintf("%06d", i))
		return err
	})
	requireBoundedEvaluations(t, errs, evals.Load(), max, ErrTOTPInvalid, ErrTOTPRateLimited)
}

// FAILED-BEFORE (R2-10): the same race on backup codes.
func TestVerifyBackupCodeConcurrentBurstBoundedByMaxAttempts(t *testing.T) {
	cfg := totpTestConfig()
	up := &gatedBackupProvider{mockUserProvider: newHardeningUserProvider(t), gate: make(chan struct{})}
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	const n = 40
	max := cfg.TOTP.BackupCodeMaxAttempts
	errs := burst(t, n, n-max, up.gate, func(i int) error {
		return engine.VerifyBackupCode(context.Background(), "u1", fmt.Sprintf("AAAAA-%05d", i))
	})
	requireBoundedEvaluations(t, errs, up.consumes.Load(), max, ErrBackupCodeInvalid, ErrBackupCodeRateLimited)
}

// Sequentially nothing changes: the failure that fills the budget is already
// reported as rate limited, later attempts are refused without being
// evaluated, and a refused request never reaches the code check.
func TestVerifyTOTPSequentialBudgetIsUnchanged(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	secret := enableUserTOTP(t, engine, "u1", cfg)

	var evals atomic.Int64
	real := engine.totp.VerifyCode
	engine.verifyTOTPFn = func(s []byte, code string, now time.Time) (bool, int64, error) {
		evals.Add(1)
		return real(s, code, now)
	}

	ctx := context.Background()
	max := cfg.TOTP.MFALoginMaxAttempts
	for i := 1; i < max; i++ {
		if err := engine.VerifyTOTP(ctx, "u1", "000000"); !errors.Is(err, ErrTOTPInvalid) {
			t.Fatalf("wrong code %d: %v, want ErrTOTPInvalid", i, err)
		}
	}
	if err := engine.VerifyTOTP(ctx, "u1", "000000"); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("wrong code %d: %v, want ErrTOTPRateLimited", max, err)
	}
	before := evals.Load()
	if err := engine.VerifyTOTP(ctx, "u1", codeForNow(t, secret, cfg.TOTP)); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("the correct code past the budget: %v, want ErrTOTPRateLimited", err)
	}
	if evals.Load() != before {
		t.Fatal("a refused attempt evaluated the code")
	}
	if err := engine.VerifyTOTP(ctx, "u1", ""); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("an empty code past the budget: %v, want ErrTOTPRateLimited", err)
	}
}

// A good code clears the budget it claimed.
func TestVerifyTOTPSuccessResetsTheClaim(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.EnforceReplayProtection = false
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	secret := enableUserTOTP(t, engine, "u1", cfg)

	ctx := context.Background()
	for round := 0; round < 3; round++ {
		for i := 0; i < cfg.TOTP.MFALoginMaxAttempts-1; i++ {
			_ = engine.VerifyTOTP(ctx, "u1", "000000")
		}
		if err := engine.VerifyTOTP(ctx, "u1", codeForNow(t, secret, cfg.TOTP)); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
}

// mfaChallenge logs in with the password and returns the MFA challenge.
func mfaChallenge(t *testing.T, engine *Engine) string {
	t.Helper()
	res, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil || !res.MFARequired || res.MFASession == "" {
		t.Fatalf("expected an MFA challenge, got %+v, %v", res, err)
	}
	return res.MFASession
}

func mfaLoginConfig() Config {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	cfg.TOTP.EnforceReplayProtection = false
	return cfg
}

// FAILED-BEFORE (R2-24): the per-challenge attempt cap was charged after the
// factor had been evaluated, so parallel confirmations all got their code
// checked before the cap-th failure committed.
func TestConfirmLoginMFAConcurrentBurstBoundedByMFALoginMaxAttempts(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	enableUserTOTP(t, engine, "u1", cfg)
	challenge := mfaChallenge(t, engine)

	gate := make(chan struct{})
	evals := gateTOTPEvaluations(engine, gate)
	const n = 40
	max := cfg.TOTP.MFALoginMaxAttempts
	errs := burst(t, n, n-max, gate, func(i int) error {
		_, err := engine.ConfirmLoginMFA(context.Background(), challenge, fmt.Sprintf("%06d", i))
		return err
	})

	if got := evals.Load(); got != int64(max) {
		t.Fatalf("%d of %d concurrent confirmations had their code evaluated, want exactly MFALoginMaxAttempts (%d)", got, n, max)
	}
	for i, err := range errs {
		// The guess that fills the account's own budget answers rate limited.
		if !errors.Is(err, ErrMFALoginInvalid) && !errors.Is(err, ErrMFALoginAttemptsExceeded) && !errors.Is(err, ErrTOTPRateLimited) {
			t.Fatalf("confirmation %d: %v", i, err)
		}
	}
}

// Sequentially the cap behaves as it always did: failures one to four are
// "invalid", the fifth exhausts the challenge, and the challenge is gone.
func TestConfirmLoginMFASequentialAttemptCapIsUnchanged(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	// A correct code after four wrong ones still completes the login.
	challenge := mfaChallenge(t, engine)
	for i := 1; i < cfg.TOTP.MFALoginMaxAttempts; i++ {
		if _, err := engine.ConfirmLoginMFA(ctx, challenge, "000000"); !errors.Is(err, ErrMFALoginInvalid) {
			t.Fatalf("wrong code %d: %v, want ErrMFALoginInvalid", i, err)
		}
	}
	if _, err := engine.ConfirmLoginMFA(ctx, challenge, codeForNow(t, secret, cfg.TOTP)); err != nil {
		t.Fatalf("the correct code after %d wrong ones: %v", cfg.TOTP.MFALoginMaxAttempts-1, err)
	}

	// The fifth wrong code exhausts the challenge.
	up2 := newHardeningUserProvider(t)
	engine2, rdb2, done2 := newCreateAccountEngine(t, cfg, up2)
	defer done2()
	enableUserTOTP(t, engine2, "u1", cfg)
	challenge = mfaChallenge(t, engine2)
	for i := 1; i < cfg.TOTP.MFALoginMaxAttempts; i++ {
		_, _ = engine2.ConfirmLoginMFA(ctx, challenge, "000000")
	}
	if _, err := engine2.ConfirmLoginMFA(ctx, challenge, "000000"); !errors.Is(err, ErrMFALoginAttemptsExceeded) {
		t.Fatalf("wrong code %d: %v, want ErrMFALoginAttemptsExceeded", cfg.TOTP.MFALoginMaxAttempts, err)
	}
	if rdb2.Exists(ctx, "amc:"+challenge).Val() != 0 {
		t.Fatal("the exhausted challenge must be deleted")
	}
	if _, err := engine2.ConfirmLoginMFA(ctx, challenge, "000000"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("a deleted challenge: %v, want ErrMFALoginInvalid", err)
	}
}

// newAuditEngine builds an engine like newCreateAccountEngine but hands back
// the fake Redis so a test can move its clock.
func newAuditEngine(t *testing.T, cfg Config, up UserProvider) (*Engine, *miniredis.Miniredis) {
	t.Helper()
	mr, rdb := newTestRedis(t)
	t.Cleanup(mr.Close)
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return engine, mr
}

// FAILED-BEFORE (R2-01): the TOTP guesses made at MFA login were counted only
// inside the disposable challenge, so a holder of the password could mint a
// new challenge for every five guesses and never meet a per-account limit.
func TestConfirmLoginMFAGuessesAcrossChallengesShareThePerUserBudget(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, mr := newAuditEngine(t, cfg, up)
	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()

	limitedAt := -1
	for i := 0; i < 25; i++ {
		_, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), "000000")
		if errors.Is(err, ErrTOTPRateLimited) {
			limitedAt = i
			break
		}
		if !errors.Is(err, ErrMFALoginInvalid) {
			t.Fatalf("guess %d: %v, want ErrMFALoginInvalid", i+1, err)
		}
	}
	if want := cfg.TOTP.MFALoginMaxAttempts - 1; limitedAt != want {
		t.Fatalf("the guess that used up the account's budget was number %d, want %d (-1: 25 guesses over 25 challenges were never limited)", limitedAt+1, want+1)
	}

	// With the budget spent, the right code is refused too, and the challenge
	// it was presented on is destroyed.
	challenge := mfaChallenge(t, engine)
	if _, err := engine.ConfirmLoginMFA(ctx, challenge, codeForNow(t, secret, cfg.TOTP)); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("the right code with the budget spent: %v, want ErrTOTPRateLimited", err)
	}
	if _, err := engine.ConfirmLoginMFA(ctx, challenge, codeForNow(t, secret, cfg.TOTP)); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("the destroyed challenge: %v, want ErrMFALoginInvalid", err)
	}

	// The window passes and the account can log in again.
	mr.FastForward(cfg.TOTP.VerifyAttemptCooldown + time.Second)
	if _, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), codeForNow(t, secret, cfg.TOTP)); err != nil {
		t.Fatalf("login after the window: %v", err)
	}
}

// The budget is the one VerifyTOTP uses, and a right code clears it.
func TestConfirmLoginMFAUsesAndResetsTheVerifyTOTPBudget(t *testing.T) {
	cfg := mfaLoginConfig()
	up := newHardeningUserProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	enableUserTOTP(t, engine, "u1", cfg)
	ctx := context.Background()
	max := cfg.TOTP.MFALoginMaxAttempts

	// Wrong codes through the step-up check leave fewer guesses for the login.
	for i := 0; i < max-1; i++ {
		if err := engine.VerifyTOTP(ctx, "u1", "000000"); !errors.Is(err, ErrTOTPInvalid) {
			t.Fatalf("VerifyTOTP %d: %v", i+1, err)
		}
	}
	if _, err := engine.ConfirmLoginMFA(ctx, mfaChallenge(t, engine), "000000"); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("the guess that fills the shared budget: %v, want ErrTOTPRateLimited", err)
	}

	// A right code clears the budget again.
	engine2, _ := newAuditEngine(t, cfg, newHardeningUserProvider(t))
	secret2 := enableUserTOTP(t, engine2, "u1", cfg)
	for round := 0; round < 3; round++ {
		for i := 0; i < max-2; i++ {
			if _, err := engine2.ConfirmLoginMFA(ctx, mfaChallenge(t, engine2), "000000"); !errors.Is(err, ErrMFALoginInvalid) {
				t.Fatalf("round %d guess %d: %v", round, i+1, err)
			}
		}
		if _, err := engine2.ConfirmLoginMFA(ctx, mfaChallenge(t, engine2), codeForNow(t, secret2, cfg.TOTP)); err != nil {
			t.Fatalf("round %d: the right code: %v", round, err)
		}
	}
}

// A limiter outage at the MFA login confirmation follows LimiterFailClosed
// like every other limiter: closed refuses with a system error and leaves the
// challenge usable, open lets the code be checked unthrottled.
func TestLimiterFailClosedAppliesToTheMFALoginTOTPBudget(t *testing.T) {
	for _, closed := range []bool{true, false} {
		env := newRSEnv(t, limiterFailClosedConfig(closed), rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
		br := &limiterBreaker{}
		env.rdb.AddHook(br)
		secret := env.enableTOTP()
		res, err := env.engine.LoginWithResult(env.ctx(), rsIdentifier, rsPassword)
		if err != nil || !res.MFARequired {
			t.Fatalf("closed=%v: expected an MFA challenge, got %+v, %v", closed, res, err)
		}

		br.set(breakWrites)
		_, err = env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, "000000")
		if closed {
			if !isSystemError(err) {
				t.Fatalf("closed: got %v, want a system error", err)
			}
		} else if !errors.Is(err, ErrMFALoginInvalid) {
			t.Fatalf("open: got %v, want the code checked and rejected", err)
		}
		waitForLimiterEvent(t, env, "totp")

		if closed {
			br.set(breakOff)
			if _, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, env.totpCode(secret)); err != nil {
				t.Fatalf("closed: the challenge must survive an outage that refused the code: %v", err)
			}
		}
	}
}

// capturedHashes records every encoded hash a password verification is run
// against, so a test can see what the dummy verifications cost.
func captureVerifiedHashes(engine *Engine) *[]string {
	var mu sync.Mutex
	var hashes []string
	engine.verifyHashFn = func(password, encodedHash string) (bool, error) {
		mu.Lock()
		hashes = append(hashes, encodedHash)
		mu.Unlock()
		return engine.passwordHash.Verify(password, encodedHash)
	}
	return &hashes
}

func phcParams(t *testing.T, encoded string) string {
	t.Helper()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("not a PHC string: %q", encoded)
	}
	return parts[3]
}

// FAILED-BEFORE (R2-18): the hash verified in place of a real one was a
// constant of fixed cost (m=65536,t=3,p=2), so with any other Password
// configuration an unknown identifier took visibly more or less time than a
// wrong password on a real account.
func TestDummyVerificationCostsWhatTheConfiguredHasherCosts(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Password = PasswordConfig{Memory: 16 * 1024, Time: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	up := newHardeningUserProvider(t)
	up.users["u3"] = UserRecord{UserID: "u3", Identifier: "carol", TenantID: "0", PasswordHash: "", Status: AccountActive, Role: "member", PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1}
	up.byIdentifier["carol"] = "u3"
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	hashes := captureVerifiedHashes(engine)
	ctx := context.Background()
	const want = "m=16384,t=2,p=1"

	for name, call := range map[string]func(){
		"unknown identifier":        func() { _, _, _ = engine.Login(ctx, "nobody", "some-password-123") },
		"empty password":            func() { _, _, _ = engine.Login(ctx, "alice", "") },
		"account without password":  func() { _, _, _ = engine.Login(ctx, "carol", "some-password-123") },
		"VerifyPassword, no secret": func() { _ = engine.VerifyPassword(ctx, "u3", "some-password-123") },
	} {
		*hashes = (*hashes)[:0]
		call()
		if len(*hashes) != 1 {
			t.Fatalf("%s: %d verifications, want exactly one", name, len(*hashes))
		}
		if got := phcParams(t, (*hashes)[0]); got != want {
			t.Fatalf("%s: dummy verification ran at %s, want the configured %s", name, got, want)
		}
	}
}

// FAILED-BEFORE (R2-23): an over-length password was rejected by the hasher
// before any hashing for an account that has a password, while an unknown
// identifier paid a full dummy verification, so the response time told the two
// apart. Inputs that cannot be real now take one cheap path whatever the
// account is.
func TestOverLengthInputsAreRefusedOnOneCheapPath(t *testing.T) {
	env := newRSEnv(t, limiterFailClosedConfig(false))
	var verifications atomic.Int64
	env.engine.verifyHashFn = func(password, encodedHash string) (bool, error) {
		verifications.Add(1)
		return env.engine.passwordHash.Verify(password, encodedHash)
	}

	long := strings.Repeat("p", 1025)
	for _, tc := range []struct{ name, identifier, password string }{
		{"existing account, long password", rsIdentifier, long},
		{"unknown identifier, long password", "nobody@example.com", long},
		{"long identifier, right password", strings.Repeat("a", 321), rsPassword},
		{"long identifier, long password", strings.Repeat("a", 321), long},
	} {
		before := verifications.Load()
		if _, _, err := env.engine.Login(env.ctx(), tc.identifier, tc.password); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: %v, want ErrInvalidCredentials", tc.name, err)
		}
		if got := verifications.Load() - before; got != 0 {
			t.Fatalf("%s: %d password verifications, want 0 (the same cheap path for every account)", tc.name, got)
		}
	}
	if keys := env.mr.Keys(); len(keys) != 0 {
		t.Fatalf("a refused input must leave no limiter state, found %v", keys)
	}
}

// The cap is inclusive: an identifier of exactly 320 bytes is an ordinary
// failed login.
func TestIdentifierAtTheCapIsProcessedNormally(t *testing.T) {
	env := newRSEnv(t, limiterFailClosedConfig(false))
	var verifications atomic.Int64
	env.engine.verifyHashFn = func(password, encodedHash string) (bool, error) {
		verifications.Add(1)
		return env.engine.passwordHash.Verify(password, encodedHash)
	}
	if _, _, err := env.engine.Login(env.ctx(), strings.Repeat("a", 320), rsPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
	if verifications.Load() != 1 {
		t.Fatalf("an identifier at the cap must reach the dummy verification, got %d", verifications.Load())
	}
}

// FAILED-BEFORE (R2-23 and the needs-validation record): identifiers of any
// size went to the user lookup, into limiter keys and into audit events, so a
// queued event held as many bytes as the caller sent.
func TestUnauthenticatedEntryPointsRefuseAndTruncateHugeIdentifiers(t *testing.T) {
	env := newRSEnv(t, limiterFailClosedConfig(false))
	ctx := env.ctx()
	huge := strings.Repeat("x", 1<<16)

	if _, _, err := env.engine.Login(ctx, huge, rsPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login: %v, want ErrInvalidCredentials", err)
	}
	if _, err := env.engine.RequestPasswordReset(ctx, huge); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("RequestPasswordReset: %v, want ErrPasswordResetInvalid", err)
	}
	if _, err := env.engine.RequestEmailVerification(ctx, huge); !errors.Is(err, ErrEmailVerificationInvalid) {
		t.Fatalf("RequestEmailVerification: %v, want ErrEmailVerificationInvalid", err)
	}
	if _, err := env.engine.CreateAccount(ctx, CreateAccountRequest{Identifier: huge, Password: "brand-new-password-1"}); !errors.Is(err, ErrAccountCreationInvalid) {
		t.Fatalf("CreateAccount: %v, want ErrAccountCreationInvalid", err)
	}

	env.engine.Close() // flush the asynchronous dispatcher
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	if len(env.sink.events) < 4 {
		t.Fatalf("expected an audit event per refused request, got %d", len(env.sink.events))
	}
	for _, ev := range env.sink.events {
		for k, v := range ev.Metadata {
			if len(v) > 320 {
				t.Fatalf("%s: audit metadata %q holds %d bytes of caller input", ev.EventType, k, len(v))
			}
		}
	}
	if keys := env.mr.Keys(); len(keys) != 0 {
		t.Fatalf("a refused identifier must leave no limiter state, found %v", keys)
	}
}
