package goAuth

import (
	"errors"
	"strings"
	"testing"
)

// Regression tests for C4 of the v0.8.1 verification audit (run 3): the
// unauthenticated confirm paths copied a caller-supplied challenge ID into
// audit metadata, and into Redis and limiter lookups, with no size or shape
// check. Each test is labelled FAILED-BEFORE with the finding ID.

const oversizedID = 1 << 20

// strategyName names a strategy value for a subtest: Token, OTP and UUID are 0,
// 1 and 2 for both the verification and the reset strategy types.
func strategyName(strategy int) string {
	return [...]string{"token", "otp", "uuid"}[strategy]
}

func bigText(n int) string { return strings.Repeat("A", n) }

// assertAuditBounded closes the engine (draining the audit queue) and checks
// that no recorded event holds more than MaxIdentifierBytes in any metadata
// value, or more than the tenant bound in its tenant.
func assertAuditBounded(t *testing.T, sink *collectingSink, closeEngine func()) {
	t.Helper()
	closeEngine()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, ev := range sink.events {
		for k, v := range ev.Metadata {
			if len(v) > MaxIdentifierBytes {
				t.Errorf("%s metadata %q is %d bytes, over the %d cap", ev.EventType, k, len(v), MaxIdentifierBytes)
			}
		}
		if len(ev.TenantID) > 256 {
			t.Errorf("%s tenant is %d bytes", ev.EventType, len(ev.TenantID))
		}
	}
}

func assertNoRedis(t *testing.T, cmds *redisCommandLog, what string) {
	t.Helper()
	if names := cmds.names(); len(names) != 0 {
		t.Errorf("%s sent %d Redis commands (%v), want none", what, len(names), names)
	}
}

// FAILED-BEFORE (C4): the verification confirm paths looked up and audited an
// ID of any size.
func TestOversizedVerificationIDIsRefusedBeforeRedisAndAudit(t *testing.T) {
	for _, strategy := range []VerificationStrategyType{VerificationToken, VerificationUUID, VerificationOTP} {
		strategy := strategy
		t.Run(strategyName(int(strategy)), func(t *testing.T) {
			env := newECEnv(t, nil, rsConfig(func(c *Config) {
				c.EmailVerification = testEmailVerificationConfig(strategy)
			}))
			_, challenge, _, err := generateEmailVerificationChallenge(strategy, 6, "0")
			if err != nil {
				t.Fatal(err)
			}
			code := strings.SplitN(challenge, ":", 3)[2]
			ctx := env.ctx()
			env.cmds.reset()

			for name, big := range map[string]string{"1 MiB": bigText(oversizedID), "4 MiB": bigText(4 * oversizedID)} {
				if err := env.engine.ConfirmEmailVerification(ctx, "0:"+big+":"+code); !errors.Is(err, ErrEmailVerificationInvalid) {
					t.Errorf("ConfirmEmailVerification (%s ID) = %v, want ErrEmailVerificationInvalid", name, err)
				}
				if err := env.engine.ConfirmEmailVerificationCode(ctx, big, code); !errors.Is(err, ErrEmailVerificationInvalid) {
					t.Errorf("ConfirmEmailVerificationCode (%s ID) = %v, want ErrEmailVerificationInvalid", name, err)
				}
			}
			// A tenant far over the bound is refused the same way.
			if err := env.engine.ConfirmEmailVerification(ctx, bigText(oversizedID)+":"+strings.SplitN(challenge, ":", 3)[1]+":"+code); !errors.Is(err, ErrEmailVerificationInvalid) {
				t.Errorf("ConfirmEmailVerification (1 MiB tenant) = %v", err)
			}
			assertNoRedis(t, env.cmds, "the verification confirm paths")
			assertAuditBounded(t, env.sink, env.engine.Close)
		})
	}
}

// FAILED-BEFORE (C4): the reset confirm decoded a challenge of any size.
func TestOversizedResetChallengeIsRefusedBeforeRedisAndAudit(t *testing.T) {
	for _, strategy := range []ResetStrategyType{ResetToken, ResetUUID, ResetOTP} {
		strategy := strategy
		t.Run(strategyName(int(strategy)), func(t *testing.T) {
			env := newECEnv(t, nil, rsConfig(func(c *Config) {
				c.PasswordReset = testResetConfig(strategy)
			}))
			ctx := env.ctx()
			env.cmds.reset()

			big := bigText(oversizedID)
			challenges := []string{big, big + ".123456", "123456." + big, "0:" + big}
			for _, challenge := range challenges {
				if err := env.engine.ConfirmPasswordReset(ctx, challenge, "new-password-123"); !errors.Is(err, ErrPasswordResetInvalid) {
					t.Errorf("ConfirmPasswordReset (%d bytes) = %v, want ErrPasswordResetInvalid", len(challenge), err)
				}
			}
			assertNoRedis(t, env.cmds, "ConfirmPasswordReset")
			assertAuditBounded(t, env.sink, env.engine.Close)
		})
	}
}

// FAILED-BEFORE (C4): the email-change confirm looked up an ID of any size
// and audited the tenant it carried.
func TestOversizedEmailChangeIDIsRefusedBeforeRedisAndAudit(t *testing.T) {
	// Email change does not support the UUID strategy.
	for _, strategy := range []VerificationStrategyType{VerificationToken, VerificationOTP} {
		strategy := strategy
		t.Run(strategyName(int(strategy)), func(t *testing.T) {
			env := newECEnv(t, func(c *EmailChangeConfig) { c.Strategy = strategy })
			_, challenge, _, err := generateEmailVerificationChallenge(strategy, 6, "0")
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.SplitN(challenge, ":", 3)
			ctx := env.ctx()
			env.cmds.reset()

			big := bigText(oversizedID)
			for name, id := range map[string]string{
				"1 MiB ID":     "0:" + big,
				"1 MiB tenant": big + ":" + parts[1],
			} {
				if _, err := env.engine.ConfirmEmailChange(ctx, id, parts[2], ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
					t.Errorf("ConfirmEmailChange (%s) = %v, want ErrEmailChangeInvalid", name, err)
				}
			}
			assertNoRedis(t, env.cmds, "ConfirmEmailChange")
			assertAuditBounded(t, env.sink, env.engine.Close)
		})
	}
}

// FAILED-BEFORE (C4): the sign-up handle was hashed and looked up at any size.
func TestOversizedExternalSignupHandleIsRefusedBeforeRedis(t *testing.T) {
	env := newExtEnv(t, extSignup())
	ctx := env.ctx()
	env.cmds.reset()

	big := bigText(oversizedID)
	if _, err := env.engine.CompleteExternalSignup(ctx, big, ExternalSignupOptions{}); !errors.Is(err, ErrExternalSignupInvalid) {
		t.Errorf("CompleteExternalSignup (1 MiB) = %v, want ErrExternalSignupInvalid", err)
	}
	// Cancel is idempotent: a handle that names nothing is not an error.
	if err := env.engine.CancelExternalSignup(ctx, big); err != nil {
		t.Errorf("CancelExternalSignup (1 MiB) = %v, want nil", err)
	}
	assertNoRedis(t, env.cmds, "the sign-up handle paths")
	assertAuditBounded(t, env.sink, env.engine.Close)
}
