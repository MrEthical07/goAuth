package goAuth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"sort"
	"strings"
	"testing"
)

var expectedEngineBoundaryMethods = map[string]struct{}{
	"ActiveSessionEstimate":              {},
	"ChangePassword":                     {},
	"ConfirmEmailVerification":           {},
	"ConfirmEmailVerificationCode":       {},
	"ConfirmLoginMFA":                    {},
	"ConfirmLoginMFAWithType":            {},
	"ConfirmPasswordReset":               {},
	"ConfirmPasswordResetWithBackupCode": {},
	"ConfirmPasswordResetWithMFA":        {},
	"ConfirmPasswordResetWithTOTP":       {},
	"ConfirmTOTPSetup":                   {},
	"CreateAccount":                      {},
	"DeleteAccount":                      {},
	"DisableAccount":                     {},
	"DisableTOTP":                        {},
	"EnableAccount":                      {},
	"GenerateBackupCodes":                {},
	"GenerateTOTPSetup":                  {},
	"GetActiveSessionCount":              {},
	"GetLoginAttempts":                   {},
	"GetSessionInfo":                     {},
	"InvalidateUserSessions":             {},
	"ListActiveSessions":                 {},
	"LockAccount":                        {},
	"Login":                              {},
	"LoginWithBackupCode":                {},
	"LoginWithResult":                    {},
	"LoginWithTOTP":                      {},
	"Logout":                             {},
	"LogoutAll":                          {},
	"LogoutAllInTenant":                  {},
	"LogoutByAccessToken":                {},
	"LogoutInTenant":                     {},
	"ProvisionTOTP":                      {},
	"Refresh":                            {},
	"RegenerateBackupCodes":              {},
	"RequestEmailVerification":           {},
	"RequestPasswordReset":               {},
	"UnlockAccount":                      {},
	"Validate":                           {},
	"ValidateAccess":                     {},
	"VerifyBackupCode":                   {},
	"VerifyBackupCodeInTenant":           {},
	"VerifyTOTP":                         {},
}

var flowEntryRawErrBudget = map[string]map[string]int{
	"internal/flows/login.go": {
		"RunConfirmLoginMFAWithType": 1,
		"RunCreateMFALoginChallenge": 0,
		"RunIssueLoginSessionTokens": 5,
		"RunLoginWithResult":         3,
	},
	"internal/flows/password_reset.go": {
		"RunConfirmPasswordResetWithMFA": 1,
		"RunRequestPasswordReset":        1,
	},
	"internal/flows/email_verification.go": {
		"RunConfirmEmailVerification":     1,
		"RunConfirmEmailVerificationCode": 1,
		"RunRequestEmailVerification":     2,
	},
	"internal/flows/account.go": {
		"RunCreateAccount":             1,
		"RunIssueAccountSessionTokens": 5,
	},
}

type boundaryMethodAudit struct {
	name      string
	resultCnt int
	errorIdx  int
	unsafe    []string
	delegates map[string]struct{}
}

func TestEngineErrorBoundaryStatic_EngineMethods(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "engine.go", nil, 0)
	if err != nil {
		t.Fatalf("parse engine.go: %v", err)
	}

	methodDecls := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil || !fn.Name.IsExported() {
			continue
		}
		if receiverTypeName(fn) != "Engine" {
			continue
		}
		if _, _, ok := functionResultShape(fn.Type); !ok {
			continue
		}
		methodDecls[fn.Name.Name] = fn
	}

	missing := keyDifference(expectedEngineBoundaryMethods, methodDecls)
	extra := keyDifference(methodDecls, expectedEngineBoundaryMethods)
	if len(missing) > 0 || len(extra) > 0 {
		var b strings.Builder
		if len(missing) > 0 {
			fmt.Fprintf(&b, "missing audited engine boundary methods: %s\n", strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			fmt.Fprintf(&b, "new exported error-returning Engine methods must be audited: %s", strings.Join(extra, ", "))
		}
		t.Fatal(strings.TrimSpace(b.String()))
	}

	audits := make(map[string]*boundaryMethodAudit, len(methodDecls))
	for name, fn := range methodDecls {
		resultCnt, errIdx, ok := functionResultShape(fn.Type)
		if !ok {
			t.Fatalf("%s: expected error in return signature", name)
		}
		audit := &boundaryMethodAudit{
			name:      name,
			resultCnt: resultCnt,
			errorIdx:  errIdx,
			delegates: map[string]struct{}{},
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}

			errExpr, tupleReturn, ok, msg := returnErrorExpr(ret, resultCnt, errIdx)
			line := fset.Position(ret.Pos()).Line
			if !ok {
				audit.unsafe = append(audit.unsafe, fmt.Sprintf("line %d: %s", line, msg))
				return true
			}

			kind, delegate, reason := classifyBoundaryExpr(errExpr, tupleReturn)
			switch kind {
			case "safe":
				return true
			case "delegate":
				audit.delegates[delegate] = struct{}{}
				return true
			default:
				audit.unsafe = append(audit.unsafe, fmt.Sprintf("line %d: %s (%s)", line, reason, exprString(fset, errExpr)))
				return true
			}
		})

		audits[name] = audit
	}

	unsafeReports := make([]string, 0)
	memo := map[string]bool{}
	visiting := map[string]bool{}

	var safeMethod func(string) bool
	safeMethod = func(name string) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		audit, ok := audits[name]
		if !ok {
			memo[name] = false
			return false
		}
		if visiting[name] {
			memo[name] = false
			return false
		}
		visiting[name] = true
		defer func() { visiting[name] = false }()

		if len(audit.unsafe) > 0 {
			memo[name] = false
			return false
		}

		for delegate := range audit.delegates {
			if _, ok := audits[delegate]; !ok {
				audit.unsafe = append(audit.unsafe, fmt.Sprintf("delegates to non-audited method %q", delegate))
				memo[name] = false
				return false
			}
			if !safeMethod(delegate) {
				audit.unsafe = append(audit.unsafe, fmt.Sprintf("delegates to unsafe method %q", delegate))
				memo[name] = false
				return false
			}
		}

		memo[name] = true
		return true
	}

	names := sortedKeys(expectedEngineBoundaryMethods)
	for _, name := range names {
		if safeMethod(name) {
			continue
		}
		audit := audits[name]
		if len(audit.unsafe) == 0 {
			unsafeReports = append(unsafeReports, fmt.Sprintf("%s: unsafe delegate chain", name))
			continue
		}
		unsafeReports = append(unsafeReports, fmt.Sprintf("%s:\n  - %s", name, strings.Join(audit.unsafe, "\n  - ")))
	}

	if len(unsafeReports) > 0 {
		t.Fatalf("engine boundary static check failed:\n%s", strings.Join(unsafeReports, "\n"))
	}
}

func TestEngineErrorBoundaryStatic_FlowEntrypoints(t *testing.T) {
	t.Parallel()

	for filePath, expectedFns := range flowEntryRawErrBudget {
		filePath := filePath
		expectedFns := expectedFns

		t.Run(filePath, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filePath, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", filePath, err)
			}

			funcDecls := map[string]*ast.FuncDecl{}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name == nil {
					continue
				}
				if !strings.HasPrefix(fn.Name.Name, "Run") {
					continue
				}
				if _, _, ok := functionResultShape(fn.Type); !ok {
					continue
				}
				funcDecls[fn.Name.Name] = fn
			}

			missing := keyDifference(expectedFns, funcDecls)
			extra := keyDifference(funcDecls, expectedFns)
			if len(missing) > 0 || len(extra) > 0 {
				var b strings.Builder
				if len(missing) > 0 {
					fmt.Fprintf(&b, "missing audited flow entrypoints: %s\n", strings.Join(missing, ", "))
				}
				if len(extra) > 0 {
					fmt.Fprintf(&b, "new Run* entrypoints must be audited for raw error passthrough: %s", strings.Join(extra, ", "))
				}
				t.Fatal(strings.TrimSpace(b.String()))
			}

			for fnName, budget := range expectedFns {
				fn := funcDecls[fnName]
				resultCnt, errIdx, ok := functionResultShape(fn.Type)
				if !ok {
					t.Fatalf("%s: expected error in return signature", fnName)
				}

				rawErrReturns := 0
				forbiddenReports := make([]string, 0)

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, ok := n.(*ast.FuncLit); ok {
						return false
					}
					ret, ok := n.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					errExpr, _, ok, msg := returnErrorExpr(ret, resultCnt, errIdx)
					line := fset.Position(ret.Pos()).Line
					if !ok {
						forbiddenReports = append(forbiddenReports, fmt.Sprintf("line %d: %s", line, msg))
						return true
					}

					if isForbiddenErrorConstructor(errExpr) {
						forbiddenReports = append(forbiddenReports, fmt.Sprintf("line %d: forbidden ad-hoc error constructor in return (%s)", line, exprString(fset, errExpr)))
						return true
					}
					if id, ok := errExpr.(*ast.Ident); ok && id.Name == "err" {
						rawErrReturns++
					}
					return true
				})

				if len(forbiddenReports) > 0 {
					t.Fatalf("%s failed static flow checks:\n  - %s", fnName, strings.Join(forbiddenReports, "\n  - "))
				}
				if rawErrReturns > budget {
					t.Fatalf("%s raw err passthrough increased: got %d, budget %d", fnName, rawErrReturns, budget)
				}
			}
		})
	}
}

func receiverTypeName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if ptr, ok := t.(*ast.StarExpr); ok {
		t = ptr.X
	}
	id, ok := t.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

func functionResultShape(ft *ast.FuncType) (resultCount int, errorIndex int, ok bool) {
	if ft == nil || ft.Results == nil {
		return 0, -1, false
	}

	errorIndex = -1
	for _, field := range ft.Results.List {
		names := len(field.Names)
		if names == 0 {
			names = 1
		}
		for i := 0; i < names; i++ {
			if isErrorType(field.Type) {
				errorIndex = resultCount + i
			}
		}
		resultCount += names
	}

	if errorIndex < 0 {
		return resultCount, errorIndex, false
	}
	return resultCount, errorIndex, true
}

func isErrorType(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "error"
}

func returnErrorExpr(ret *ast.ReturnStmt, resultCount, errorIndex int) (expr ast.Expr, tupleReturn bool, ok bool, msg string) {
	if ret == nil {
		return nil, false, false, "nil return statement"
	}
	if len(ret.Results) == 0 {
		return nil, false, false, "named returns are not allowed for boundary checks"
	}
	if len(ret.Results) == resultCount {
		if errorIndex < 0 || errorIndex >= len(ret.Results) {
			return nil, false, false, "invalid error return index"
		}
		return ret.Results[errorIndex], false, true, ""
	}
	if len(ret.Results) == 1 && resultCount > 1 {
		return ret.Results[0], true, true, ""
	}
	return nil, false, false, fmt.Sprintf("return expression count %d does not match signature result count %d", len(ret.Results), resultCount)
}

func classifyBoundaryExpr(expr ast.Expr, tupleReturn bool) (kind string, delegate string, reason string) {
	if tupleReturn {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return "unsafe", "", "tuple return must delegate through an Engine method call"
		}
		if target, ok := receiverCallTarget(call, "e"); ok {
			return "delegate", target, ""
		}
		return "unsafe", "", "tuple return must call receiver method e.<Method>(...)"
	}

	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name == "nil" {
			return "safe", "", ""
		}
		return "unsafe", "", fmt.Sprintf("raw identifier %q returned at boundary", e.Name)
	case *ast.CallExpr:
		if fn, ok := e.Fun.(*ast.Ident); ok {
			if fn.Name == "mapToAuthError" || fn.Name == "mapToAuthErrorOrNil" {
				return "safe", "", ""
			}
		}
		if target, ok := receiverCallTarget(e, "e"); ok {
			return "delegate", target, ""
		}
		return "unsafe", "", "error return call must be wrapped with mapToAuthError* or delegate to another Engine method"
	default:
		return "unsafe", "", "unsupported error return expression"
	}
}

func receiverCallTarget(call *ast.CallExpr, receiverName string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != receiverName {
		return "", false
	}
	return sel.Sel.Name, true
}

func isForbiddenErrorConstructor(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if pkg.Name == "errors" && sel.Sel.Name == "New" {
		return true
	}
	if pkg.Name == "fmt" && sel.Sel.Name == "Errorf" {
		return true
	}
	return false
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var b strings.Builder
	_ = printer.Fprint(&b, fset, expr)
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keyDifference[A any, B any](left map[string]A, right map[string]B) []string {
	missing := make([]string, 0)
	for k := range left {
		if _, ok := right[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}
