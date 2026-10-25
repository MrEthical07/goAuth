package goAuth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every call to a limiter backend in the engine must be classified here, and
// every one that gates a request must route a backend error through
// Engine.limiterOutage, the single place that honors
// Security.LimiterFailClosed. A new limiter (a field of Engine whose type comes
// from internal/limiters or internal/rate) or a new call site fails this test
// until it is classified, so a limiter cannot be added without deciding what
// its outage means.
//
// Kinds:
//
//	gate     a check or count that decides whether the request proceeds; the
//	         enclosing function must return limiterOutage's result
//	cleanup  a reset after a success; it only removes counts and never blocks,
//	         so it goes through limiterCleanupFailed (or logs a warning)
//	key      builds a key, touches no backend
//	lockout  the auto-lockout counter, a separate mechanism whose outage is
//	         documented as not covered by LimiterFailClosed
var limiterCallSites = map[string]string{
	"reservePasswordVerifyAttempt|passwordVerifyLimiter.Reserve":                 "gate",
	"resetPasswordVerifyLimiter|passwordVerifyLimiter.Reset":                     "cleanup",
	"ChangePassword|rateLimiter.ResetLogin":                                      "cleanup",
	"ChangePassword|rateLimiter.ResetLoginUser":                                  "cleanup",
	"configureAccountLimiterDeps|accountLimiter.Enforce":                         "gate",
	"backupCodeFlowDeps|backupLimiter.Reserve":                                   "gate",
	"backupCodeFlowDeps|backupLimiter.Release":                                   "cleanup",
	"backupCodeFlowDeps|backupLimiter.Reset":                                     "cleanup",
	"configureEmailVerificationLimiterDeps|verificationLimiter.CheckRequest":     "gate",
	"configureEmailVerificationLimiterDeps|verificationLimiter.CheckRequestUser": "gate",
	"configureEmailVerificationLimiterDeps|verificationLimiter.CheckConfirm":     "gate",
	"configureLoginRateLimiterDeps|rateLimiter.ReserveLogin":                     "gate",
	"configureLoginRateLimiterDeps|rateLimiter.IncrementLogin":                   "gate",
	"configureLoginRateLimiterDeps|rateLimiter.ResetLogin":                       "cleanup",
	"configureLoginRateLimiterDeps|rateLimiter.ReserveLoginUser":                 "gate",
	"configureLoginRateLimiterDeps|rateLimiter.ReserveLoginIP":                   "gate",
	"configureLoginRateLimiterDeps|rateLimiter.ReleaseLoginIP":                   "cleanup",
	"configureLoginRateLimiterDeps|rateLimiter.ResetLoginUser":                   "cleanup",
	"configurePasswordResetLimiterDeps|resetLimiter.CheckRequest":                "gate",
	"configurePasswordResetLimiterDeps|resetLimiter.CheckRequestUser":            "gate",
	"configurePasswordResetLimiterDeps|resetLimiter.CheckConfirm":                "gate",
	"configureLoginTOTPLimiterDeps|totpLimiter.Reserve":                          "gate",
	"configureLoginTOTPLimiterDeps|totpLimiter.Release":                          "cleanup",
	"configureLoginTOTPLimiterDeps|totpLimiter.Reset":                            "cleanup",
	"configureTOTPLimiterDeps|totpLimiter.Check":                                 "gate",
	"configureTOTPLimiterDeps|totpLimiter.Reserve":                               "gate",
	"configureTOTPLimiterDeps|totpLimiter.Release":                               "cleanup",
	"configureTOTPLimiterDeps|totpLimiter.Reset":                                 "cleanup",
	"reserveExternal|externalLimiter.Reserve":                                    "gate",
	"resetExternal|externalLimiter.Reset":                                        "cleanup",
	"verifyExternalToken|externalLimiter.SourceKey":                              "key",
	"verifyExternalToken|externalLimiter.SubjectKey":                             "key",
	"enforceExternalSignupLimit|accountLimiter.Enforce":                          "gate",
	"reserveEmailChangeRequest|emailChangeLimiter.Reserve":                       "gate",
	"reserveRoleSwitchAttempt|roleSwitchLimiter.Reserve":                         "gate",
	"resetRoleSwitchAttempts|roleSwitchLimiter.Reset":                            "cleanup",
	"EnableAccount|lockoutLimiter.Reset":                                         "lockout",
	"loginFlowDeps|lockoutLimiter.RecordFailure":                                 "lockout",
	"loginFlowDeps|lockoutLimiter.Reset":                                         "lockout",
}

type limiterCall struct {
	fn, field, method string
}

func TestLimiterCallSitesAreClassifiedAndRouteThroughTheCentralHelper(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed = append(parsed, f)
	}

	// 1. The limiter fields are whatever Engine declares with a limiters.* or
	// rate.* type.
	limiterFields := map[string]bool{}
	for _, f := range parsed {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Engine" {
					continue
				}
				st := ts.Type.(*ast.StructType)
				for _, field := range st.Fields.List {
					star, ok := field.Type.(*ast.StarExpr)
					if !ok {
						continue
					}
					sel, ok := star.X.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || (pkg.Name != "limiters" && pkg.Name != "rate") {
						continue
					}
					for _, n := range field.Names {
						limiterFields[n.Name] = true
					}
				}
			}
		}
	}
	if len(limiterFields) < 9 {
		t.Fatalf("expected to find the engine's limiter fields, found %v", limiterFields)
	}

	// 2. Every call on a limiter field, with its enclosing top-level function,
	// whether the function routes through the central helpers, and whether the
	// helper's result is used.
	type funcInfo struct {
		callsOutage, callsCleanup, callsWarn bool
		outageUnused                         []string
	}
	infos := map[string]*funcInfo{}
	var calls []limiterCall
	directEmit := map[string]bool{}

	for _, f := range parsed {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			info := &funcInfo{}
			infos[fd.Name.Name] = info

			var stack []ast.Node
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "limiterOutage":
					info.callsOutage = true
					parent := stack[len(stack)-2]
					switch parent.(type) {
					case *ast.ReturnStmt, *ast.AssignStmt:
					default:
						info.outageUnused = append(info.outageUnused, fset.Position(call.Pos()).String())
					}
				case "limiterCleanupFailed":
					info.callsCleanup = true
				case "warn":
					info.callsWarn = true
				case "emitLimiterFailOpen":
					directEmit[fd.Name.Name] = true
				}
				inner, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := inner.X.(*ast.Ident)
				if !ok || recv.Name != "e" || !limiterFields[inner.Sel.Name] {
					return true
				}
				calls = append(calls, limiterCall{fn: fd.Name.Name, field: inner.Sel.Name, method: sel.Sel.Name})
				return true
			})
		}
	}

	// 3. Classification must match exactly.
	seen := map[string]bool{}
	var problems []string
	for _, c := range calls {
		key := fmt.Sprintf("%s|%s.%s", c.fn, c.field, c.method)
		seen[key] = true
		kind, ok := limiterCallSites[key]
		if !ok {
			problems = append(problems, "unclassified limiter call site: "+key+" (add it to limiterCallSites as gate, cleanup, key or lockout)")
			continue
		}
		info := infos[c.fn]
		switch kind {
		case "gate":
			if !info.callsOutage {
				problems = append(problems, key+" is a gate but "+c.fn+" never calls limiterOutage")
			}
			if len(info.outageUnused) > 0 {
				problems = append(problems, c.fn+" discards limiterOutage's result at "+strings.Join(info.outageUnused, ", "))
			}
		case "cleanup":
			if !info.callsCleanup && !info.callsWarn {
				problems = append(problems, key+" is a cleanup but "+c.fn+" neither calls limiterCleanupFailed nor logs")
			}
		}
	}
	for key := range limiterCallSites {
		if !seen[key] {
			problems = append(problems, "classified limiter call site no longer exists: "+key)
		}
	}

	// 4. The event emitter is only reachable through the two helpers.
	for fn := range directEmit {
		switch fn {
		case "limiterOutage", "limiterCleanupFailed":
		default:
			problems = append(problems, fn+" calls emitLimiterFailOpen directly; go through limiterOutage or limiterCleanupFailed")
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("limiter call-site audit failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
}
