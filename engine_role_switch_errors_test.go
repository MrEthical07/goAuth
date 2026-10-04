package goAuth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MrEthical07/goAuth/internal/limiters"
)

func TestRoleSwitchSentinels(t *testing.T) {
	tests := []struct {
		name      string
		err       *AuthError
		code      AuthCode
		category  ErrorCategory
		auditCode AuditErrorCode
	}{
		{"disabled", ErrRoleSwitchDisabled, CodeAuthRoleSwitchDisabled, CategoryAuthState, auditErrRoleSwitchDisabled},
		{"not allowed", ErrRoleNotAllowed, CodeAuthRoleNotAllowed, CategoryAuthState, auditErrRoleNotAllowed},
		{"same role", ErrRoleSwitchSameRole, CodeAuthRoleSwitchSameRole, CategoryAuthValidation, auditErrRoleSwitchSameRole},
		{"step-up required", ErrStepUpRequired, CodeAuthStepUpRequired, CategoryAuthState, auditErrStepUpRequired},
		{"rate limited", ErrRoleSwitchRateLimited, CodeAuthRoleSwitchRateLimited, CategoryAuthAbuse, auditErrRoleSwitchRateLimited},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != string(tc.code) {
				t.Fatalf("code = %q, want %q", tc.err.Code, tc.code)
			}
			if tc.err.Category != tc.category {
				t.Fatalf("category = %q, want %q", tc.err.Category, tc.category)
			}
			if tc.err.Message == "" {
				t.Fatal("sentinel has no message")
			}
			if got := auditErrorCode(tc.err); got != tc.auditCode {
				t.Fatalf("audit code = %q, want %q", got, tc.auditCode)
			}

			// Wrapped values keep their identity through the public mapper.
			wrapped := fmt.Errorf("context: %w", tc.err)
			mapped := mapToAuthError(wrapped)
			if !errors.Is(mapped, tc.err) || mapped.Code != tc.err.Code {
				t.Fatalf("mapToAuthError lost the sentinel: %v", mapped)
			}
		})
	}
}

func TestRoleSwitchSentinelCodesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, s := range publicAuthSentinels {
		if prev, dup := seen[s.Code]; dup {
			t.Fatalf("code %q used by both %q and %q", s.Code, prev, s.Message)
		}
		seen[s.Code] = s.Message
	}
}

func TestRoleSwitchLimiterErrorMapping(t *testing.T) {
	if got := mapToAuthError(limiters.ErrRoleSwitchRateLimited); !errors.Is(got, ErrRoleSwitchRateLimited) {
		t.Fatalf("rate-limited limiter error mapped to %v", got)
	}
	if got := mapToAuthError(limiters.ErrRoleSwitchUnavailable); !errors.Is(got, ErrSystemUnavailable) {
		t.Fatalf("unavailable limiter error mapped to %v", got)
	}
}
