package goAuth

import (
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// A session's role-switch MFA-proof key ("asa:<tenant>:<id>") is removed with
// the session by every engine entry point that ends one. Before v0.8.0 the key
// was left to age out by its TTL.
func TestEngineEndingASessionRemovesItsMFAProofKey(t *testing.T) {
	held := session.Assurance{MFAAt: time.Now().Unix(), MFAMethod: "totp", AuthAt: time.Now().Unix()}

	paths := []struct {
		name string
		end  func(t *testing.T, env *rsEnv, access, refresh string)
	}{
		{"Logout", func(t *testing.T, env *rsEnv, _, refresh string) {
			if err := env.engine.Logout(env.ctx(), env.sidOf(refresh)); err != nil {
				t.Fatalf("Logout: %v", err)
			}
		}},
		{"LogoutInTenant", func(t *testing.T, env *rsEnv, _, refresh string) {
			if err := env.engine.LogoutInTenant(env.ctx(), env.tenant, env.sidOf(refresh)); err != nil {
				t.Fatalf("LogoutInTenant: %v", err)
			}
		}},
		{"LogoutByAccessToken", func(t *testing.T, env *rsEnv, access, _ string) {
			if err := env.engine.LogoutByAccessToken(env.ctx(), access); err != nil {
				t.Fatalf("LogoutByAccessToken: %v", err)
			}
		}},
		{"LogoutAll", func(t *testing.T, env *rsEnv, _, _ string) {
			if err := env.engine.LogoutAll(env.ctx(), rsUserID); err != nil {
				t.Fatalf("LogoutAll: %v", err)
			}
		}},
		{"LogoutAllInTenant", func(t *testing.T, env *rsEnv, _, _ string) {
			if err := env.engine.LogoutAllInTenant(env.ctx(), env.tenant, rsUserID); err != nil {
				t.Fatalf("LogoutAllInTenant: %v", err)
			}
		}},
		{"InvalidateUserSessions", func(t *testing.T, env *rsEnv, _, _ string) {
			if err := env.engine.InvalidateUserSessions(env.ctx(), rsUserID); err != nil {
				t.Fatalf("InvalidateUserSessions: %v", err)
			}
		}},
		{"ChangePassword (invalidates every session)", func(t *testing.T, env *rsEnv, _, _ string) {
			if err := env.engine.ChangePassword(env.ctx(), rsUserID, rsPassword, "another-password-789"); err != nil {
				t.Fatalf("ChangePassword: %v", err)
			}
		}},
		{"refresh-token reuse", func(t *testing.T, env *rsEnv, _, refresh string) {
			if _, _, err := env.engine.Refresh(env.ctx(), refresh); err != nil {
				t.Fatalf("first refresh: %v", err)
			}
			if _, _, err := env.engine.Refresh(env.ctx(), refresh); err == nil {
				t.Fatal("reusing a rotated refresh token must be refused")
			}
		}},
		{"strict validation of an expired session", func(t *testing.T, env *rsEnv, access, refresh string) {
			sess := env.peek(env.sidOf(refresh))
			sess.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			if err := env.engine.sessionStore.Save(env.ctx(), sess, time.Hour); err != nil {
				t.Fatalf("re-save: %v", err)
			}
			if _, err := env.validate(access, ModeStrict); err == nil {
				t.Fatal("an expired session must not validate")
			}
		}},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			env := newRSEnv(t, rsConfig(func(c *Config) { c.Session.JitterEnabled = false }))
			access, refresh := env.login()
			sid := env.sidOf(refresh)
			env.setAssurance(sid, held)
			if env.assurance(sid) == nil {
				t.Fatal("test setup: assurance not stored")
			}

			p.end(t, env, access, refresh)

			if env.assurance(sid) != nil {
				t.Fatalf("%s left the MFA-proof key behind", p.name)
			}
			if keys := env.keys("asa:*"); len(keys) != 0 {
				t.Fatalf("%s left MFA-proof keys %v", p.name, keys)
			}
		})
	}
}
