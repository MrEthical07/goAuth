package goAuth

import (
	"errors"
	"testing"
)

// Only ErrUserNotFound means the signed-in user is gone. Any other lookup error
// is an outage and is reported as one; before, every error read as "account
// not found", which told a client to sign the user out during a database blip.
//
// FAILED-BEFORE for the outage rows; the not-found rows are ALREADY-TRUE.
func TestExternalManagedUserLookupDistinguishesNotFoundFromOutage(t *testing.T) {
	calls := map[string]func(env *extEnv, userID string) error{
		"link": func(env *extEnv, userID string) error {
			token, nonce := env.linkToken(extTokenSpec{sub: "sub-x"})
			_, err := env.engine.LinkExternalIdentity(env.ctx(), userID, "google", token, nonce)
			return err
		},
		"unlink": func(env *extEnv, userID string) error {
			return env.engine.UnlinkExternalIdentity(env.ctx(), userID, "google", "sub-x")
		},
		"list": func(env *extEnv, userID string) error {
			_, err := env.engine.ListExternalIdentities(env.ctx(), userID)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name+"/missing user", func(t *testing.T) {
			env := newExtEnv(t)
			requireCode(t, call(env, "nobody"), CodeAuthAccountNotFound)
		})
		t.Run(name+"/provider outage", func(t *testing.T) {
			env := newExtEnv(t)
			env.up.idErr = errors.New("db down")
			ae := requireCode(t, call(env, extLocalUserID), CodeSystemUnavailable)
			if ae.Category != CategorySystem {
				t.Fatalf("category = %s, want SYSTEM", ae.Category)
			}
		})
		t.Run(name+"/empty user id", func(t *testing.T) {
			env := newExtEnv(t)
			requireCode(t, call(env, ""), CodeAuthAccountNotFound)
		})
	}
}

// A failed unlink is audited, with the reason, like a failed link.
//
// NEW-API (external_identity_unlink_failure).
func TestUnlinkExternalIdentityAuditsFailures(t *testing.T) {
	type row struct {
		name   string
		reason string
		code   AuthCode
		setup  func(env *extEnv) string // returns the user ID to unlink for
		opts   []extOption
	}
	rows := []row{
		{name: "disabled", reason: "disabled", code: CodeAuthExternalDisabled,
			opts:  []extOption{extConfig(func(c *Config) { c.ExternalAuth.Enabled = false })},
			setup: func(env *extEnv) string { return extLocalUserID }},
		{name: "user not found", reason: "user_not_found", code: CodeAuthAccountNotFound,
			setup: func(env *extEnv) string { return "nobody" }},
		{name: "account status", reason: "account_status", code: CodeAuthAccountDisabled,
			setup: func(env *extEnv) string {
				u := env.up.users[extLocalUserID]
				u.Status = AccountDisabled
				env.up.users[extLocalUserID] = u
				return extLocalUserID
			}},
		{name: "last login method", reason: "last_login_method", code: CodeAuthLastLoginMethod,
			setup: func(env *extEnv) string {
				env.addLocal(UserRecord{UserID: "u-nopw", Identifier: "nopw@example.com", Status: AccountActive})
				env.link("google", "sub-only", "u-nopw")
				return "u-nopw"
			}},
		{name: "unavailable (identity list)", reason: "unavailable", code: CodeSystemUnavailable,
			setup: func(env *extEnv) string { env.up.listErr = errors.New("db down"); return extLocalUserID }},
		{name: "unavailable (user lookup)", reason: "unavailable", code: CodeSystemUnavailable,
			setup: func(env *extEnv) string { env.up.idErr = errors.New("db down"); return extLocalUserID }},
		{name: "unavailable (unlink write)", reason: "unavailable", code: CodeSystemUnavailable,
			setup: func(env *extEnv) string {
				env.link("google", "sub-only", extLocalUserID)
				env.up.unlinkErr = errors.New("db down")
				return extLocalUserID
			}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := newExtEnv(t, r.opts...)
			uid := r.setup(env)
			err := env.engine.UnlinkExternalIdentity(env.ctx(), uid, "google", "sub-only")
			requireCode(t, err, r.code)

			ev := env.waitForAudit(auditEventExternalUnlinkFailure, r.reason)
			if ev.Success {
				t.Fatalf("failure event reports success: %+v", ev)
			}
			if ev.Metadata["provider"] != "google" || ev.Metadata["reason"] != r.reason {
				t.Fatalf("metadata = %v", ev.Metadata)
			}
			if len(env.events(auditEventExternalUnlinked)) != 0 {
				t.Fatal("a failed unlink emitted the success event")
			}
		})
	}

	t.Run("a hostile provider name is not echoed", func(t *testing.T) {
		env := newExtEnv(t)
		_ = env.engine.UnlinkExternalIdentity(env.ctx(), "nobody", "Bad Provider\n<script>", "x")
		ev := env.waitForAudit(auditEventExternalUnlinkFailure, "user_not_found")
		if ev.Metadata["provider"] != "invalid" {
			t.Fatalf("provider = %q, want invalid", ev.Metadata["provider"])
		}
	})

	t.Run("success and no-op are not failures", func(t *testing.T) {
		env := newExtEnv(t)
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "google", "never-linked"); err != nil {
			t.Fatal(err)
		}
		if n := len(env.events(auditEventExternalUnlinkFailure)); n != 0 {
			t.Fatalf("%d failure events for a no-op", n)
		}
	})
}
