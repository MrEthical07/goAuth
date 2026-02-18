package test

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestEngine_DelegateMethodComplexity ensures that public methods on Engine
// in engine.go stay below a maximum line count. Methods exceeding this
// threshold likely contain inline business logic that should be in
// internal/flows/*.
//
// Allowed exceptions are explicitly listed below with mandatory metadata:
// - Reason: why the exception exists
// - Target: the internal/flows file it should migrate to
// - RemoveBy: a version or milestone when the exception should be removed
//
// Exceptions without this metadata are rejected at test time to prevent
// permanent exception creep.
func TestEngine_DelegateMethodComplexity(t *testing.T) {
	const maxLines = 50
	const filename = "../engine.go"

	// delegateException describes one allowed exception to the delegate
	// complexity limit. All fields are required — if an entry is missing
	// reason, target, or removeBy, the test will fail to force cleanup.
	type delegateException struct {
		limit    int    // maximum allowed lines for this method
		reason   string // why the exception is needed
		target   string // target internal flow file (e.g. "internal/flows/login.go")
		removeBy string // version or milestone when this should be removed (e.g. "v1.0.0")
	}

	// Known legacy methods that haven't been fully migrated to flows yet.
	exceptions := map[string]delegateException{
		"loginInternal":                    {400, "large legacy login path", "internal/flows/login.go", "v1.0.0"},
		"LoginWithResult":                  {200, "MFA routing logic", "internal/flows/login.go", "v1.0.0"},
		"LoginWithTOTP":                    {60, "MFA error mapping", "internal/flows/mfa_totp.go", "v1.0.0"},
		"LoginWithBackupCode":              {60, "MFA error mapping", "internal/flows/backup_codes.go", "v1.0.0"},
		"Refresh":                          {100, "metric/audit dispatch", "internal/flows/refresh.go", "v1.0.0"},
		"Validate":                         {60, "result building", "internal/flows/validate.go", "v1.0.0"},
		"ChangePassword":                   {120, "not yet migrated", "internal/flows/account.go", "v1.0.0"},
		"enforceSessionHardeningOnLogin":   {80, "helper with session state", "internal/flows/login.go", "v1.0.0"},
		"enforceTOTPForLogin":              {100, "helper with TOTP state", "internal/flows/mfa_totp.go", "v1.0.0"},
		"CreateAccount":                    {60, "delegate + error mapping", "internal/flows/account.go", "v1.0.0"},
		"accountFlowDeps":                  {100, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"accountSessionDeps":               {60, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"accountStatusFlowDeps":            {120, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"updateAccountStatusAndInvalidate": {100, "not yet migrated", "internal/flows/account_status.go", "v1.0.0"},
		"validateDeviceBinding":            {80, "helper with device state", "internal/flows/device_binding.go", "v1.0.0"},
		"backupCodeFlowDeps":               {200, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"initFlowDeps":                     {100, "one-time wiring", "internal/flows/deps.go", "v1.0.0"},
		"ConfirmLoginMFA":                  {100, "not yet migrated", "internal/flows/mfa_totp.go", "v1.0.0"},
		"ConfirmLoginMFAWithType":          {100, "not yet migrated", "internal/flows/mfa_totp.go", "v1.0.0"},
		"RequestPasswordReset":             {100, "not yet migrated", "internal/flows/password_reset.go", "v1.0.0"},
		"ConfirmPasswordReset":             {200, "not yet migrated", "internal/flows/password_reset.go", "v1.0.0"},
		"RequestEmailVerification":         {100, "not yet migrated", "internal/flows/email_verification.go", "v1.0.0"},
		"ConfirmEmailVerification":         {200, "not yet migrated", "internal/flows/email_verification.go", "v1.0.0"},
		"SetupTOTP":                        {100, "not yet migrated", "internal/flows/mfa_totp.go", "v1.0.0"},
		"VerifyTOTP":                       {100, "not yet migrated", "internal/flows/mfa_totp.go", "v1.0.0"},
		"DisableTOTP":                      {80, "not yet migrated", "internal/flows/mfa_totp.go", "v1.0.0"},
		"GenerateBackupCodes":              {60, "delegate", "internal/flows/backup_codes.go", "v1.0.0"},
		"RegenerateBackupCodes":            {60, "delegate", "internal/flows/backup_codes.go", "v1.0.0"},
		"VerifyBackupCode":                 {60, "delegate", "internal/flows/backup_codes.go", "v1.0.0"},
		"VerifyBackupCodeInTenant":         {60, "delegate", "internal/flows/backup_codes.go", "v1.0.0"},
		"emitAudit":                        {60, "utility", "internal/flows/service.go", "v1.0.0"},
		"emitRateLimit":                    {60, "utility", "internal/flows/service.go", "v1.0.0"},
		"IntrospectSessions":               {60, "delegate", "internal/flows/introspection.go", "v1.0.0"},
		"IntrospectSessionsInTenant":       {80, "delegate", "internal/flows/introspection.go", "v1.0.0"},
		"emailVerificationFlowDeps":        {120, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"loginFlowDeps":                    {200, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"passwordResetFlowDeps":            {150, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"totpFlowDeps":                     {100, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"deviceBindingFlowDeps":            {80, "wiring function", "internal/flows/deps.go", "v1.0.0"},
		"introspectionFlowDeps":            {80, "wiring function", "internal/flows/deps.go", "v1.0.0"},
	}

	// Validate that every exception has complete metadata — prevents "permanent exceptions".
	for name, exc := range exceptions {
		if exc.reason == "" {
			t.Errorf("exception %q missing reason", name)
		}
		if exc.target == "" {
			t.Errorf("exception %q missing target flow file", name)
		}
		if exc.removeBy == "" {
			t.Errorf("exception %q missing removeBy version/milestone", name)
		}
	}

	funcSig := regexp.MustCompile(`^func \(e \*Engine\) ([A-Za-z]\w*)\(`)

	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("open %s: %v", filename, err)
	}
	defer f.Close()

	type methodInfo struct {
		name  string
		start int
		depth int
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	var current *methodInfo
	var violations []string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if current == nil {
			if m := funcSig.FindStringSubmatch(line); m != nil {
				current = &methodInfo{
					name:  m[1],
					start: lineNum,
					depth: strings.Count(line, "{") - strings.Count(line, "}"),
				}
				continue
			}
		}

		if current != nil {
			current.depth += strings.Count(line, "{") - strings.Count(line, "}")
			if current.depth <= 0 {
				length := lineNum - current.start + 1
				limit := maxLines
				if exc, ok := exceptions[current.name]; ok {
					limit = exc.limit
				}
				if length > limit {
					violations = append(violations, current.name)
					t.Errorf("%s:%d: method %s is %d lines (limit %d); move business logic to internal/flows/",
						filename, current.start, current.name, length, limit)
				}
				current = nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", filename, err)
	}

	if len(violations) > 0 {
		t.Logf("Detected %d method(s) exceeding their line budget. "+
			"Business logic should live in internal/flows/*, "+
			"root methods should be thin delegates.",
			len(violations))
	}
}
