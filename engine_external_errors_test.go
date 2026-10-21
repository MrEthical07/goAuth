package goAuth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/oidc"
)

// NEW-API.
func TestExternalSentinelsCodesCategoriesAndAuditCodes(t *testing.T) {
	cases := []struct {
		err      *AuthError
		code     AuthCode
		wire     string
		category ErrorCategory
		audit    AuditErrorCode
	}{
		{ErrExternalAuthDisabled, CodeAuthExternalDisabled, "AUTH_EXTERNAL_DISABLED", CategoryAuthState, auditErrExternalDisabled},
		{ErrExternalProviderUnknown, CodeAuthExternalProviderUnknown, "AUTH_EXTERNAL_PROVIDER_UNKNOWN", CategoryAuthValidation, auditErrExternalProvider},
		{ErrExternalTokenInvalid, CodeAuthExternalTokenInvalid, "AUTH_EXTERNAL_TOKEN_INVALID", CategoryAuthValidation, auditErrExternalTokenInvalid},
		{ErrExternalTokenReplayed, CodeAuthExternalTokenReplayed, "AUTH_EXTERNAL_TOKEN_REPLAYED", CategoryAuthAbuse, auditErrExternalTokenReplayed},
		{ErrExternalProviderUnavailable, CodeSystemUnavailableExternalProvider, "SYSTEM_UNAVAILABLE_EXTERNAL_PROVIDER", CategorySystem, auditErrExternalUnavailable},
		{ErrExternalEmailUnverified, CodeAuthExternalEmailUnverified, "AUTH_EXTERNAL_EMAIL_UNVERIFIED", CategoryAuthState, auditErrExternalEmailUnver},
		{ErrExternalAccountNotFound, CodeAuthExternalAccountNotFound, "AUTH_EXTERNAL_ACCOUNT_NOT_FOUND", CategoryAuthState, auditErrExternalNotFound},
		{ErrExternalAccountLinkRequired, CodeAuthExternalLinkRequired, "AUTH_EXTERNAL_LINK_REQUIRED", CategoryAuthState, auditErrExternalLinkRequired},
		{ErrExternalLinkRequiresVerification, CodeAuthExternalLinkRequiresVerify, "AUTH_EXTERNAL_LINK_REQUIRES_VERIFICATION", CategoryAuthState, auditErrExternalLinkVerify},
		{ErrExternalIdentityInUse, CodeAuthExternalIdentityInUse, "AUTH_EXTERNAL_IDENTITY_IN_USE", CategoryAuthState, auditErrExternalInUse},
		{ErrLastLoginMethod, CodeAuthLastLoginMethod, "AUTH_LAST_LOGIN_METHOD", CategoryAuthState, auditErrLastLoginMethod},
		{ErrPasswordNotSet, CodeAuthPasswordNotSet, "AUTH_PASSWORD_NOT_SET", CategoryAuthState, auditErrPasswordNotSet},
		{ErrExternalLoginRateLimited, CodeAuthExternalLoginRateLimited, "AUTH_EXTERNAL_LOGIN_RATE_LIMITED", CategoryAuthAbuse, auditErrRateLimited},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.wire, func(t *testing.T) {
			if string(tc.code) != tc.wire || tc.err.Code != tc.wire {
				t.Fatalf("code = %q / %q, want %q", tc.code, tc.err.Code, tc.wire)
			}
			if tc.err.Category != tc.category {
				t.Fatalf("category = %s, want %s", tc.err.Category, tc.category)
			}
			if seen[tc.wire] {
				t.Fatalf("duplicate code %s", tc.wire)
			}
			seen[tc.wire] = true

			// The sentinel passes through the boundary unchanged, and a wrapped
			// copy is recognised by errors.Is.
			if got := mapToAuthError(tc.err); got != tc.err {
				t.Fatalf("mapToAuthError changed the sentinel: %v", got)
			}
			wrapped := fmt.Errorf("provider said: %w", tc.err)
			mapped := mapToAuthError(wrapped)
			if mapped.Code != tc.wire || !errors.Is(mapped, tc.err) {
				t.Fatalf("wrapped sentinel mapped to %+v", mapped)
			}
			if got := auditErrorCode(tc.err); got != tc.audit {
				t.Fatalf("audit code = %q, want %q", got, tc.audit)
			}
			inList := false
			for _, s := range publicAuthSentinels {
				if s == tc.err {
					inList = true
				}
			}
			if !inList {
				t.Fatal("sentinel missing from publicAuthSentinels")
			}
		})
	}
}

// Internal verification and limiter errors reach callers as the public
// sentinels, never as raw internals.
//
// NEW-API.
func TestExternalInternalErrorsMapToPublicSentinels(t *testing.T) {
	cases := []struct {
		in   error
		want *AuthError
	}{
		{oidc.ErrInvalid, ErrExternalTokenInvalid},
		{fmt.Errorf("%w: signature", oidc.ErrInvalid), ErrExternalTokenInvalid},
		{oidc.ErrReplayed, ErrExternalTokenReplayed},
		{oidc.ErrUnavailable, ErrExternalProviderUnavailable},
		{fmt.Errorf("%w: no key set", oidc.ErrUnavailable), ErrExternalProviderUnavailable},
		{oidc.ErrStore, ErrSystemUnavailable},
		{limiters.ErrExternalRateLimited, ErrExternalLoginRateLimited},
		{limiters.ErrExternalUnavailable, ErrSystemUnavailable},
	}
	for _, tc := range cases {
		got := mapToAuthError(tc.in)
		if got.Code != tc.want.Code || got.Category != tc.want.Category {
			t.Errorf("%v mapped to %s/%s, want %s/%s", tc.in, got.Code, got.Category, tc.want.Code, tc.want.Category)
		}
	}
}
