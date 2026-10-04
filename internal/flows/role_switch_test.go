package flows

import (
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

func TestPolicySatisfied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }

	tests := []struct {
		name   string
		policy RoleStepUpPolicy
		sess   session.Session
		held   *session.Assurance
		want   bool
	}{
		{
			name:   "empty policy is always satisfied",
			policy: RoleStepUpPolicy{},
			sess:   session.Session{CreatedAt: ago(100 * time.Hour)},
			want:   true,
		},
		{
			name:   "require mfa without any assurance",
			policy: RoleStepUpPolicy{RequireMFA: true},
			sess:   session.Session{CreatedAt: ago(time.Minute)},
			want:   false,
		},
		{
			name:   "require mfa with an assurance that only records a password proof",
			policy: RoleStepUpPolicy{RequireMFA: true},
			sess:   session.Session{CreatedAt: ago(time.Minute)},
			held:   &session.Assurance{AuthAt: ago(time.Minute)},
			want:   false,
		},
		{
			name:   "require mfa, no age limit, ancient assurance",
			policy: RoleStepUpPolicy{RequireMFA: true},
			sess:   session.Session{CreatedAt: ago(500 * time.Hour)},
			held:   &session.Assurance{MFAAt: ago(500 * time.Hour), MFAMethod: "totp", AuthAt: ago(500 * time.Hour)},
			want:   true,
		},
		{
			name:   "require mfa within max age",
			policy: RoleStepUpPolicy{RequireMFA: true, MaxAge: 10 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Hour)},
			held:   &session.Assurance{MFAAt: ago(5 * time.Minute), MFAMethod: "totp"},
			want:   true,
		},
		{
			name:   "require mfa past max age",
			policy: RoleStepUpPolicy{RequireMFA: true, MaxAge: 10 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Minute)},
			held:   &session.Assurance{MFAAt: ago(11 * time.Minute), MFAMethod: "totp"},
			want:   false,
		},
		{
			name:   "require mfa at the exact max age boundary",
			policy: RoleStepUpPolicy{RequireMFA: true, MaxAge: 10 * time.Minute},
			sess:   session.Session{},
			held:   &session.Assurance{MFAAt: ago(10 * time.Minute), MFAMethod: "totp"},
			want:   true,
		},
		{
			name:   "recent auth satisfied by session creation",
			policy: RoleStepUpPolicy{MaxAge: 5 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Minute)},
			want:   true,
		},
		{
			name:   "recent auth not satisfied by an old session",
			policy: RoleStepUpPolicy{MaxAge: 5 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Hour)},
			want:   false,
		},
		{
			name:   "recent auth takes the newest of creation, mfa and password proof",
			policy: RoleStepUpPolicy{MaxAge: 5 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Hour)},
			held:   &session.Assurance{MFAAt: ago(30 * time.Minute), AuthAt: ago(time.Minute)},
			want:   true,
		},
		{
			name:   "recent auth with only an old assurance",
			policy: RoleStepUpPolicy{MaxAge: 5 * time.Minute},
			sess:   session.Session{CreatedAt: ago(time.Hour)},
			held:   &session.Assurance{MFAAt: ago(30 * time.Minute), AuthAt: ago(20 * time.Minute)},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := tc.sess
			if got := policySatisfied(tc.policy, &sess, tc.held, now); got != tc.want {
				t.Fatalf("policySatisfied = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsInlineMFAType(t *testing.T) {
	for typ, want := range map[string]bool{
		"totp":        true,
		"backup_code": true,
		"backup":      false,
		"webauthn":    false,
		"password":    false,
		"":            false,
		"TOTP":        false,
	} {
		if got := isInlineMFAType(typ); got != want {
			t.Fatalf("isInlineMFAType(%q) = %v, want %v", typ, got, want)
		}
	}
}
