package goAuth

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// engine_roleswitch.go is not scanned by TestEngineErrorBoundaryStatic_EngineMethods
// (it only parses engine.go, like engine_webauthn.go is not). This applies the
// same rule to the role-switch file: every error leaving an error-returning
// method must be nil, wrapped by mapToAuthError*, or delegated to another
// method held to the same rule.
func TestRoleSwitchErrorBoundaryStatic(t *testing.T) {
	t.Parallel()

	audited := map[string]struct{}{
		"SwitchRole":        {},
		"roleSwitchFailure": {},
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "engine_roleswitch.go", nil, 0)
	if err != nil {
		t.Fatalf("parse engine_roleswitch.go: %v", err)
	}

	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || receiverTypeName(fn) != "Engine" {
			continue
		}
		if _, ok := audited[fn.Name.Name]; !ok {
			continue
		}
		seen[fn.Name.Name] = true

		resultCnt, errIdx, ok := functionResultShape(fn.Type)
		if !ok {
			t.Fatalf("%s: expected an error in the return signature", fn.Name.Name)
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			line := fset.Position(ret.Pos()).Line
			errExpr, tupleReturn, ok, msg := returnErrorExpr(ret, resultCnt, errIdx)
			if !ok {
				t.Errorf("%s line %d: %s", fn.Name.Name, line, msg)
				return true
			}
			kind, delegate, reason := classifyBoundaryExpr(errExpr, tupleReturn)
			switch kind {
			case "safe":
			case "delegate":
				if _, ok := audited[delegate]; !ok {
					t.Errorf("%s line %d: delegates to unaudited method %q", fn.Name.Name, line, delegate)
				}
			default:
				t.Errorf("%s line %d: %s (%s)", fn.Name.Name, line, reason, exprString(fset, errExpr))
			}
			return true
		})
	}
	for name := range audited {
		if !seen[name] {
			t.Errorf("audited method %q not found in engine_roleswitch.go", name)
		}
	}
}

// Every failure path returns a canonical *AuthError, and the result is nil
// unless the failure is ErrStepUpRequired.
func TestSwitchRoleFailuresAreAuthErrorsWithNilResult(t *testing.T) {
	type scenario struct {
		name string
		want error
		run  func(env *rsEnv) (*RoleSwitchResult, error)
	}

	scenarios := []scenario{
		{"malformed token", ErrRefreshInvalid, func(env *rsEnv) (*RoleSwitchResult, error) {
			return env.switchRole("not-a-refresh-token", "admin", RoleSwitchOptions{})
		}},
		{"unknown session", ErrSessionNotFound, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			if err := env.engine.Logout(env.ctx(), env.sidOf(refresh)); err != nil {
				t.Fatalf("logout: %v", err)
			}
			return env.switchRole(refresh, "admin", RoleSwitchOptions{})
		}},
		{"stale token", ErrRefreshReuse, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, r1 := env.login()
			if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
				t.Fatalf("refresh: %v", err)
			}
			return env.switchRole(r1, "admin", RoleSwitchOptions{})
		}},
		{"same role", ErrRoleSwitchSameRole, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			return env.switchRole(refresh, "teacher", RoleSwitchOptions{})
		}},
		{"unknown role", ErrRoleNotAllowed, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			return env.switchRole(refresh, "ghost", RoleSwitchOptions{})
		}},
		{"provider says no", ErrRoleNotAllowed, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			env.up.revoke(rsUserID, "admin")
			return env.switchRole(refresh, "admin", RoleSwitchOptions{})
		}},
		{"provider unavailable", ErrSystemUnavailable, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			env.up.setCanErr(errors.New("raw-provider-failure"))
			return env.switchRole(refresh, "admin", RoleSwitchOptions{})
		}},
		{"disabled account", ErrAccountDisabled, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			user := env.up.users[rsUserID]
			user.Status = AccountDisabled
			env.up.users[rsUserID] = user
			return env.switchRole(refresh, "admin", RoleSwitchOptions{})
		}},
		{"rate limited", ErrRoleSwitchRateLimited, func(env *rsEnv) (*RoleSwitchResult, error) {
			_, refresh := env.login()
			var res *RoleSwitchResult
			var err error
			for i := 0; i < 3; i++ {
				res, err = env.switchRole(refresh, "teacher", RoleSwitchOptions{})
			}
			return res, err
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			env := newRSEnv(t, rsConfig(func(c *Config) {
				c.RoleSwitch.MaxAttempts = 2
				c.RoleSwitch.Cooldown = time.Minute
			}))
			res, err := sc.run(env)
			ae := assertBoundaryAuthError(t, err, sc.want)
			if strings.Contains(ae.Error(), "raw-provider-failure") {
				t.Fatalf("raw provider error leaked: %v", ae)
			}
			if res != nil {
				t.Fatalf("a %v failure must not carry a result, got %+v", sc.want, res)
			}
		})
	}
}

func TestSwitchRoleResultShapeOnSuccess(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if err != nil {
		t.Fatalf("SwitchRole failed: %v", err)
	}
	if res == nil || res.AccessToken == "" || res.RefreshToken == "" || res.Role != "admin" {
		t.Fatalf("incomplete success result: %+v", res)
	}
	if res.StepUpRequired || res.StepUpFactors != nil {
		t.Fatalf("a successful switch must not carry step-up fields: %+v", res)
	}
}
