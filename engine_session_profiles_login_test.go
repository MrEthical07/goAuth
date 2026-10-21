package goAuth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/session"
)

// spWantSession asserts that the session behind refresh was created under
// profile: the stored record carries it (schema v6) and the key lifetime is
// what the profile prescribes.
func spWantSession(t *testing.T, env *spEnv, refresh, profile string, wantTTL time.Duration) *session.Session {
	t.Helper()
	sid := env.sidOf(refresh)
	sess := env.peek(sid)
	if sess.Profile != profile {
		t.Fatalf("session profile = %q, want %q", sess.Profile, profile)
	}
	if sess.SchemaVersion != session.ProfileSchemaVersion {
		t.Fatalf("session schema = %d, want %d", sess.SchemaVersion, session.ProfileSchemaVersion)
	}
	if got := env.mr.TTL(env.sessionKey(sid)); got != wantTTL {
		t.Fatalf("session TTL = %v, want %v", got, wantTTL)
	}
	return sess
}

// spProfileTTL is the initial key lifetime of each test profile.
var spProfileTTL = map[string]time.Duration{
	"web": 15 * spDay, "mobile": 90 * spDay, "mobile-use": 90 * spDay, "agent": spDay,
}

// The profile is chosen through every session-creating path that needs no
// second factor, and with none named the default applies.
func TestSessionProfilesChosenOnEveryLoginPath(t *testing.T) {
	paths := map[string]func(env *spEnv, ctx context.Context) (string, error){
		"Login": func(env *spEnv, ctx context.Context) (string, error) {
			_, refresh, err := env.engine.Login(ctx, rsIdentifier, rsPassword)
			return refresh, err
		},
		"LoginWithResult": func(env *spEnv, ctx context.Context) (string, error) {
			res, err := env.engine.LoginWithResult(ctx, rsIdentifier, rsPassword)
			if err != nil {
				return "", err
			}
			return res.RefreshToken, nil
		},
		"LoginWithOptions": func(env *spEnv, ctx context.Context) (string, error) {
			res, err := env.engine.LoginWithOptions(ctx, rsIdentifier, rsPassword, LoginOptions{})
			if err != nil {
				return "", err
			}
			return res.RefreshToken, nil
		},
		"CreateAccount auto-login": func(env *spEnv, ctx context.Context) (string, error) {
			res, err := env.engine.CreateAccount(ctx, CreateAccountRequest{
				Identifier: "fresh@example.com", Password: "brand-new-password-1", Role: "member",
			})
			if res == nil {
				return "", err
			}
			return res.RefreshToken, err
		},
	}

	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			for _, profile := range []string{"mobile", "agent", "mobile-use", "web"} {
				env := newSPEnv(t, nil)
				refresh, err := path(env, env.ctxFor(profile))
				if err != nil {
					t.Fatalf("%s as %s: %v", name, profile, err)
				}
				spWantSession(t, env, refresh, profile, spProfileTTL[profile])
			}

			// No profile named: the default.
			env := newSPEnv(t, nil)
			refresh, err := path(env, env.ctx())
			if err != nil {
				t.Fatalf("%s with no profile: %v", name, err)
			}
			spWantSession(t, env, refresh, "web", 15*spDay)
		})
	}
}

// spMFAEnv is a profile env whose user has TOTP and backup codes, so every
// login needs a second factor.
func spMFAEnv(t *testing.T, mutate func(*Config), opts ...rsOption) (*spEnv, string, []string) {
	t.Helper()
	env := newSPEnv(t, mutate, opts...)
	secret := enableUserTOTP(t, env.engine, rsUserID, env.cfg)
	codes, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	return env, secret, codes
}

func (e *spEnv) totp(secret string) string {
	return codeForOffset(e.t, secret, e.cfg.TOTP, 1)
}

// The profile chosen at login survives the MFA step, through every way of
// finishing it.
func TestSessionProfilesChosenOnEveryMFAPath(t *testing.T) {
	for _, profile := range []string{"mobile", "agent", "web"} {
		t.Run(profile, func(t *testing.T) {
			ttl := spProfileTTL[profile]

			t.Run("LoginWithTOTP", func(t *testing.T) {
				env, secret, _ := spMFAEnv(t, nil)
				_, refresh, err := env.engine.LoginWithTOTP(env.ctxFor(profile), rsIdentifier, rsPassword, env.totp(secret))
				if err != nil {
					t.Fatalf("LoginWithTOTP: %v", err)
				}
				spWantSession(t, env, refresh, profile, ttl)
			})

			t.Run("LoginWithBackupCode", func(t *testing.T) {
				env, _, codes := spMFAEnv(t, nil)
				_, refresh, err := env.engine.LoginWithBackupCode(env.ctxFor(profile), rsIdentifier, rsPassword, codes[0])
				if err != nil {
					t.Fatalf("LoginWithBackupCode: %v", err)
				}
				spWantSession(t, env, refresh, profile, ttl)
			})

			t.Run("ConfirmLoginMFA", func(t *testing.T) {
				env, secret, _ := spMFAEnv(t, nil)
				res, err := env.engine.LoginWithResult(env.ctxFor(profile), rsIdentifier, rsPassword)
				if err != nil || !res.MFARequired {
					t.Fatalf("step 1: %v %+v", err, res)
				}
				// The confirm names no profile: the stored one wins.
				done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, env.totp(secret))
				if err != nil {
					t.Fatalf("ConfirmLoginMFA: %v", err)
				}
				spWantSession(t, env, done.RefreshToken, profile, ttl)
			})

			t.Run("ConfirmLoginMFAWithType backup", func(t *testing.T) {
				env, _, codes := spMFAEnv(t, nil)
				res, err := env.engine.LoginWithResult(env.ctxFor(profile), rsIdentifier, rsPassword)
				if err != nil || !res.MFARequired {
					t.Fatalf("step 1: %v %+v", err, res)
				}
				// Naming the same profile again is not a conflict.
				done, err := env.engine.ConfirmLoginMFAWithType(env.ctxFor(profile), res.MFASession, codes[0], "backup")
				if err != nil {
					t.Fatalf("ConfirmLoginMFAWithType: %v", err)
				}
				spWantSession(t, env, done.RefreshToken, profile, ttl)
			})
		})
	}
}

func spChallengeBytes(t *testing.T, env *spEnv, id string) []byte {
	t.Helper()
	raw, err := env.mr.Get("amc:" + id)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	return []byte(raw)
}

// With profiles configured the challenge is written as record v3: the v2
// layout with a length-prefixed profile after the flags byte.
func TestSessionProfilesMFAChallengeRecordV3(t *testing.T) {
	env, secret, _ := spMFAEnv(t, nil)
	res, err := env.engine.LoginWithResult(env.ctxFor("mobile"), rsIdentifier, rsPassword)
	if err != nil || !res.MFARequired {
		t.Fatalf("step 1: %v %+v", err, res)
	}
	raw := spChallengeBytes(t, env, res.MFASession)

	// [3][attempts u16][expires i64][ulen u16]"u1"[tlen u16]"0"[flags][plen]"mobile"
	if raw[0] != 3 {
		t.Fatalf("challenge version = %d, want 3", raw[0])
	}
	if got, want := hex.EncodeToString(raw[1:3]), "0000"; got != want {
		t.Fatalf("attempts = %s, want %s", got, want)
	}
	const tail = "0002" + "7531" + "0001" + "30" + "00" + "06" + "6d6f62696c65"
	if got := hex.EncodeToString(raw[11:]); got != tail {
		t.Fatalf("challenge tail = %s, want %s", got, tail)
	}

	// A failed attempt re-writes the record and keeps the profile.
	if _, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, "000000"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("wrong code = %v, want ErrMFALoginInvalid", err)
	}
	raw = spChallengeBytes(t, env, res.MFASession)
	if raw[0] != 3 || !bytes.HasSuffix(raw, []byte{6, 'm', 'o', 'b', 'i', 'l', 'e'}) || hex.EncodeToString(raw[1:3]) != "0001" {
		t.Fatalf("record after a failed attempt = %x", raw)
	}
	done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, env.totp(secret))
	if err != nil {
		t.Fatalf("ConfirmLoginMFA: %v", err)
	}
	spWantSession(t, env, done.RefreshToken, "mobile", 90*spDay)
}

// A confirm that names a different profile than the challenge is refused
// without consuming the challenge or an attempt; the challenge still works
// with the right profile (or none).
func TestSessionProfilesMFAConfirmConflictKeepsChallenge(t *testing.T) {
	env, secret, _ := spMFAEnv(t, nil)
	res, err := env.engine.LoginWithResult(env.ctxFor("mobile"), rsIdentifier, rsPassword)
	if err != nil || !res.MFARequired {
		t.Fatalf("step 1: %v %+v", err, res)
	}
	before := spChallengeBytes(t, env, res.MFASession)
	lookups := env.up.getByIDCalls + env.up.getByIdentifierCalls

	for _, named := range []string{"web", "agent", "ghost"} {
		env.cmds.reset()
		_, err := env.engine.ConfirmLoginMFA(env.ctxFor(named), res.MFASession, env.totp(secret))
		if !errors.Is(err, ErrSessionProfileConflict) {
			t.Fatalf("confirm naming %q = %v, want ErrSessionProfileConflict", named, err)
		}
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Code != string(CodeAuthSessionProfileConflict) {
			t.Fatalf("error = %#v", err)
		}
		if after := spChallengeBytes(t, env, res.MFASession); !bytes.Equal(after, before) {
			t.Fatalf("a refused confirm changed the challenge:\n before %x\n after  %x", before, after)
		}
		if env.cmds.touches("rl:") || env.up.getByIDCalls+env.up.getByIdentifierCalls != lookups {
			t.Fatal("a refused confirm reached a limiter or the user provider")
		}
	}
	if ids := env.sessionIDs(); len(ids) != 0 {
		t.Fatalf("sessions were created by refused confirms: %v", ids)
	}

	done, err := env.engine.ConfirmLoginMFA(env.ctxFor("mobile"), res.MFASession, env.totp(secret))
	if err != nil {
		t.Fatalf("confirm with the right profile: %v", err)
	}
	spWantSession(t, env, done.RefreshToken, "mobile", 90*spDay)
}

// A challenge from before profiles were configured carries none and is
// resolved like a fresh login; one whose profile has since been removed is
// refused and left alone.
func TestSessionProfilesMFAChallengeWithoutOrWithRemovedProfile(t *testing.T) {
	env, secret, _ := spMFAEnv(t, nil)
	save := func(id, profile string) {
		t.Helper()
		err := env.engine.mfaLoginStore.Save(context.Background(), id, &stores.MFALoginChallenge{
			UserID: rsUserID, TenantID: "0", ExpiresAt: time.Now().Add(time.Hour).Unix(), Profile: profile,
		}, time.Hour)
		if err != nil {
			t.Fatalf("save challenge: %v", err)
		}
	}

	save("legacy-challenge", "")
	if raw := spChallengeBytes(t, env, "legacy-challenge"); raw[0] != 2 {
		t.Fatalf("a challenge without a profile must stay record v2, got version %d", raw[0])
	}
	done, err := env.engine.ConfirmLoginMFA(env.ctx(), "legacy-challenge", env.totp(secret))
	if err != nil {
		t.Fatalf("confirm of a profile-less challenge: %v", err)
	}
	spWantSession(t, env, done.RefreshToken, "web", 15*spDay) // the default

	save("stale-challenge", "retired")
	_, err = env.engine.ConfirmLoginMFA(env.ctx(), "stale-challenge", env.totp(secret))
	if !errors.Is(err, ErrUnknownSessionProfile) {
		t.Fatalf("confirm of a removed profile = %v, want ErrUnknownSessionProfile", err)
	}
	if _, gone := env.mr.Get("amc:stale-challenge"); gone != nil {
		t.Fatal("a refused confirm consumed the challenge")
	}
}

// AC4: an unknown profile fails with ErrUnknownSessionProfile before any
// work: no Redis command at all (so no limiter), no provider call (so no
// Argon2), on every session-creating entry point.
func TestSessionProfilesAC4UnknownProfileDoesNoWork(t *testing.T) {
	env, _, _ := spMFAEnv(t, nil)
	ctx := env.ctxFor("ghost")

	entry := map[string]func() error{
		"Login": func() error { _, _, err := env.engine.Login(ctx, rsIdentifier, rsPassword); return err },
		"LoginWithResult": func() error {
			_, err := env.engine.LoginWithResult(ctx, rsIdentifier, rsPassword)
			return err
		},
		"LoginWithOptions": func() error {
			_, err := env.engine.LoginWithOptions(ctx, rsIdentifier, rsPassword, LoginOptions{})
			return err
		},
		"LoginWithTOTP": func() error {
			_, _, err := env.engine.LoginWithTOTP(ctx, rsIdentifier, rsPassword, "123456")
			return err
		},
		"LoginWithBackupCode": func() error {
			_, _, err := env.engine.LoginWithBackupCode(ctx, rsIdentifier, rsPassword, "ABCD-EFGH")
			return err
		},
		"CreateAccount": func() error {
			_, err := env.engine.CreateAccount(ctx, CreateAccountRequest{Identifier: "x@example.com", Password: "brand-new-password-1", Role: "member"})
			return err
		},
	}
	for name, run := range entry {
		t.Run(name, func(t *testing.T) {
			env.cmds.reset()
			callsBefore := env.up.getByIdentifierCalls + env.up.tenantIdentifierCalls + env.up.createCalls
			err := run()
			if !errors.Is(err, ErrUnknownSessionProfile) {
				t.Fatalf("error = %v, want ErrUnknownSessionProfile", err)
			}
			var ae *AuthError
			if !errors.As(err, &ae) || ae.Code != string(CodeAuthUnknownSessionProfile) || ae.Category != CategoryAuthValidation {
				t.Fatalf("error = %#v, want the validation-category AUTH_UNKNOWN_SESSION_PROFILE", err)
			}
			if cmds := env.cmds.normalized(); len(cmds) != 0 {
				t.Fatalf("an unknown profile cost Redis commands: %v", cmds)
			}
			if calls := env.up.getByIdentifierCalls + env.up.tenantIdentifierCalls + env.up.createCalls; calls != callsBefore {
				t.Fatalf("an unknown profile reached the user provider (%d calls)", calls-callsBefore)
			}
		})
	}
	if keys := env.keys("rl:*"); len(keys) != 0 {
		t.Fatalf("limiter keys were written: %v", keys)
	}
}

// A profile named while none is configured cannot exist.
func TestSessionProfilesNamedWithoutConfiguration(t *testing.T) {
	env := newRSEnv(t)
	env.cmds.reset()
	_, _, err := env.engine.Login(WithSessionProfile(env.ctx(), "web"), rsIdentifier, rsPassword)
	if !errors.Is(err, ErrUnknownSessionProfile) {
		t.Fatalf("Login = %v, want ErrUnknownSessionProfile", err)
	}
	if cmds := env.cmds.normalized(); len(cmds) != 0 {
		t.Fatalf("commands issued: %v", cmds)
	}
	// Without a name the same engine logs in as it always did.
	_, refresh := env.login()
	if sess := env.peek(env.sidOf(refresh)); sess.Profile != "" || sess.SchemaVersion != 5 {
		t.Fatalf("legacy session = %+v", sess)
	}
}

// The remember-me mapping and its conflicts, on login and account creation.
func TestSessionProfilesRememberMeMapping(t *testing.T) {
	withMapping := func(c *Config) { c.SessionProfiles.RememberMeProfile = "mobile" }

	t.Run("RememberMe selects RememberMeProfile", func(t *testing.T) {
		env := newSPEnv(t, withMapping)
		res, err := env.engine.LoginWithOptions(env.ctx(), rsIdentifier, rsPassword, LoginOptions{RememberMe: true})
		if err != nil {
			t.Fatalf("LoginWithOptions: %v", err)
		}
		spWantSession(t, env, res.RefreshToken, "mobile", 90*spDay)

		// Without RememberMe the default still applies.
		_, refresh := env.loginAs("")
		spWantSession(t, env, refresh, "web", 15*spDay)
	})

	t.Run("RememberMe survives the MFA step", func(t *testing.T) {
		env, secret, _ := spMFAEnv(t, withMapping)
		res, err := env.engine.LoginWithOptions(env.ctx(), rsIdentifier, rsPassword, LoginOptions{RememberMe: true})
		if err != nil || !res.MFARequired {
			t.Fatalf("step 1: %v %+v", err, res)
		}
		done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, env.totp(secret))
		if err != nil {
			t.Fatalf("confirm: %v", err)
		}
		spWantSession(t, env, done.RefreshToken, "mobile", 90*spDay)
	})

	t.Run("RememberMe with an explicit profile conflicts", func(t *testing.T) {
		env := newSPEnv(t, withMapping)
		env.cmds.reset()
		_, err := env.engine.LoginWithOptions(env.ctxFor("agent"), rsIdentifier, rsPassword, LoginOptions{RememberMe: true})
		if !errors.Is(err, ErrSessionProfileConflict) {
			t.Fatalf("error = %v, want ErrSessionProfileConflict", err)
		}
		if cmds := env.cmds.normalized(); len(cmds) != 0 || env.up.getByIdentifierCalls != 0 {
			t.Fatalf("a conflict did work: commands %v, provider calls %d", cmds, env.up.getByIdentifierCalls)
		}
	})

	t.Run("RememberMe with no RememberMeProfile conflicts", func(t *testing.T) {
		env := newSPEnv(t, nil)
		env.cmds.reset()
		_, err := env.engine.LoginWithOptions(env.ctx(), rsIdentifier, rsPassword, LoginOptions{RememberMe: true})
		if !errors.Is(err, ErrSessionProfileConflict) {
			t.Fatalf("error = %v, want ErrSessionProfileConflict", err)
		}
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Code != string(CodeAuthSessionProfileConflict) || ae.Category != CategoryAuthValidation {
			t.Fatalf("error = %#v", err)
		}
		if cmds := env.cmds.normalized(); len(cmds) != 0 {
			t.Fatalf("commands issued: %v", cmds)
		}
	})

	t.Run("CreateAccount follows the same rules", func(t *testing.T) {
		env := newSPEnv(t, withMapping)
		res, err := env.engine.CreateAccount(env.ctx(), CreateAccountRequest{
			Identifier: "a@example.com", Password: "brand-new-password-1", Role: "member", RememberMe: true,
		})
		if err != nil {
			t.Fatalf("CreateAccount: %v", err)
		}
		spWantSession(t, env, res.RefreshToken, "mobile", 90*spDay)

		env.cmds.reset()
		createsBefore := env.up.createCalls
		_, err = env.engine.CreateAccount(env.ctxFor("agent"), CreateAccountRequest{
			Identifier: "b@example.com", Password: "brand-new-password-1", Role: "member", RememberMe: true,
		})
		if !errors.Is(err, ErrSessionProfileConflict) {
			t.Fatalf("explicit profile with RememberMe = %v, want ErrSessionProfileConflict", err)
		}
		if env.up.createCalls != createsBefore || len(env.cmds.normalized()) != 0 {
			t.Fatal("a conflicting CreateAccount created the user or touched Redis")
		}

		noMapping := newSPEnv(t, nil)
		_, err = noMapping.engine.CreateAccount(noMapping.ctx(), CreateAccountRequest{
			Identifier: "c@example.com", Password: "brand-new-password-1", Role: "member", RememberMe: true,
		})
		if !errors.Is(err, ErrSessionProfileConflict) {
			t.Fatalf("RememberMe with no mapping = %v, want ErrSessionProfileConflict", err)
		}
	})
}

// The session profile choice is only about sessions: account creation
// without auto-login ignores the profile entirely, as it ignores RememberMe.
func TestSessionProfilesCreateAccountWithoutAutoLoginIgnoresProfile(t *testing.T) {
	env := newSPEnv(t, func(c *Config) { c.Account.AutoLogin = false })
	res, err := env.engine.CreateAccount(env.ctxFor("ghost"), CreateAccountRequest{
		Identifier: "n@example.com", Password: "brand-new-password-1", Role: "member", RememberMe: true,
	})
	if err != nil || res.UserID == "" || res.RefreshToken != "" {
		t.Fatalf("CreateAccount = %+v, %v", res, err)
	}
}
