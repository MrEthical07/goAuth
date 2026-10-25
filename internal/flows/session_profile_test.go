package flows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

var (
	errUnknownProfile  = errors.New("unknown profile")
	errProfileConflict = errors.New("profile conflict")
)

// profileLoginDeps are deps for the profile-resolution tests: every costly
// dependency counts its calls, so a test can prove a rejected profile does
// none of that work.
type profileLoginDeps struct {
	deps    LoginDeps
	limiter int
	lookups int
	verify  int
	saved   []*session.Session
	ttls    []time.Duration
}

func newProfileLoginDeps(resolve SessionProfileResolver) *profileLoginDeps {
	p := &profileLoginDeps{}
	p.deps = LoginDeps{
		ResolveSessionProfile: resolve,
		SessionProfileLifetime: func(profile string, now time.Time) (int64, time.Duration, error) {
			return now.Add(90 * 24 * time.Hour).Unix(), 24 * time.Hour, nil
		},
		AccountStatusError: func(uint8) error { return nil },
		ReserveLoginRate:   func(context.Context, string) error { p.limiter++; return nil },
		IncrementLoginRate: func(context.Context, string) error { p.limiter++; return nil },
		GetUserByIdentifier: func(context.Context, string) (LoginUserRecord, error) {
			p.lookups++
			return LoginUserRecord{UserID: "u1", Role: "member", PasswordHash: "h"}, nil
		},
		VerifyPassword:          func(string, string) (bool, error) { p.verify++; return true, nil },
		EnforceSessionHardening: func(context.Context, string, string) error { return nil },
		GetRoleMask:             func(string) (interface{}, bool) { return nil, true },
		NewSessionID:            func() (string, error) { return "sid", nil },
		NewRefreshSecret:        func() ([32]byte, error) { return [32]byte{1}, nil },
		HashRefreshSecret:       func(s [32]byte) [32]byte { return s },
		EncodeRefreshToken:      func(string, [32]byte) (string, error) { return "refresh", nil },
		HashBindingValue:        func(string) [32]byte { return [32]byte{} },
		SessionLifetime:         func(bool) time.Duration { return 7 * 24 * time.Hour },
		Now:                     func() time.Time { return time.Unix(1_700_000_000, 0) },
		SaveSession: func(_ context.Context, s *session.Session, ttl time.Duration) error {
			p.saved = append(p.saved, s)
			p.ttls = append(p.ttls, ttl)
			return nil
		},
		IssueAccessToken: func(*session.Session) (string, error) { return "access", nil },
		Errors: LoginErrors{
			EngineNotReady:         errors.New("not ready"),
			UnknownSessionProfile:  errUnknownProfile,
			SessionProfileConflict: errProfileConflict,
		},
	}
	p.deps.IssueLoginSessionTokens = func(ctx context.Context, username string, user LoginUserRecord, tenantID string, rememberMe bool) (string, string, error) {
		return RunIssueLoginSessionTokens(ctx, username, user, tenantID, rememberMe, p.deps)
	}
	return p
}

func fixedResolver(name string, status SessionProfileStatus) SessionProfileResolver {
	return func(context.Context, bool) (string, SessionProfileStatus) { return name, status }
}

// The profile is resolved before any limiter is read, any password verified
// or any provider called, and a rejection returns the host's sentinel.
func TestLoginResolvesProfileBeforeAnyWork(t *testing.T) {
	for name, tc := range map[string]struct {
		status SessionProfileStatus
		want   error
	}{
		"unknown":  {SessionProfileUnknown, errUnknownProfile},
		"conflict": {SessionProfileConflict, errProfileConflict},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProfileLoginDeps(fixedResolver("", tc.status))
			_, err := RunLoginWithResult(context.Background(), "alice", "pw", LoginOptions{}, p.deps)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if p.limiter != 0 || p.lookups != 0 || p.verify != 0 || len(p.saved) != 0 {
				t.Fatalf("a rejected profile did work: limiter %d, lookups %d, verify %d, sessions %d", p.limiter, p.lookups, p.verify, len(p.saved))
			}
		})
	}
}

// A resolved profile reaches the stored session: its name, the profile's
// ceiling and the profile's TTL replace the legacy lifetime.
func TestLoginAppliesProfileLifetime(t *testing.T) {
	p := newProfileLoginDeps(fixedResolver("mobile", SessionProfileOK))
	res, err := RunLoginWithResult(context.Background(), "alice", "pw", LoginOptions{}, p.deps)
	if err != nil || res.RefreshToken == "" {
		t.Fatalf("login: %v %+v", err, res)
	}
	if len(p.saved) != 1 {
		t.Fatalf("sessions saved = %d", len(p.saved))
	}
	got, ttl := p.saved[0], p.ttls[0]
	now := time.Unix(1_700_000_000, 0)
	if got.Profile != "mobile" || got.CreatedAt != now.Unix() || got.ExpiresAt != now.Add(90*24*time.Hour).Unix() || ttl != 24*time.Hour {
		t.Fatalf("session = %+v ttl %v", got, ttl)
	}
}

// With no resolver (profiles unconfigured) the session is exactly the legacy
// one: no profile, the engine's lifetime for both ExpiresAt and TTL.
func TestLoginWithoutResolverIsLegacy(t *testing.T) {
	p := newProfileLoginDeps(nil)
	p.deps.SessionProfileLifetime = nil
	if _, err := RunLoginWithResult(context.Background(), "alice", "pw", LoginOptions{RememberMe: true}, p.deps); err != nil {
		t.Fatalf("login: %v", err)
	}
	got, ttl := p.saved[0], p.ttls[0]
	now := time.Unix(1_700_000_000, 0)
	if got.Profile != "" || got.ExpiresAt != now.Add(7*24*time.Hour).Unix() || ttl != 7*24*time.Hour {
		t.Fatalf("session = %+v ttl %v", got, ttl)
	}
}

// Token issuance applies a profile even when no earlier step resolved one,
// so any session-creating path is covered.
func TestIssueSessionTokensResolvesProfileItself(t *testing.T) {
	p := newProfileLoginDeps(fixedResolver("web", SessionProfileOK))
	if _, _, err := RunIssueLoginSessionTokens(context.Background(), "alice", LoginUserRecord{UserID: "u1", Role: "member"}, "t1", false, p.deps); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if p.saved[0].Profile != "web" {
		t.Fatalf("profile = %q, want web", p.saved[0].Profile)
	}

	rejecting := newProfileLoginDeps(fixedResolver("", SessionProfileConflict))
	_, _, err := RunIssueLoginSessionTokens(context.Background(), "alice", LoginUserRecord{UserID: "u1", Role: "member"}, "t1", false, rejecting.deps)
	if !errors.Is(err, errProfileConflict) || len(rejecting.saved) != 0 {
		t.Fatalf("issue = %v, sessions %d", err, len(rejecting.saved))
	}
}

// An MFA confirm that the profile check refuses consumes nothing: the
// challenge is not deleted, no attempt is recorded and no session is issued.
func TestConfirmLoginMFAProfileConflictConsumesNothing(t *testing.T) {
	var deleted, failures, issued int
	deps := LoginDeps{
		TOTPEnabled:         true,
		RequireTOTPForLogin: true,
		MFALoginMaxAttempts: 3,
		AccountStatusError:  func(uint8) error { return nil },
		GetMFAChallenge: func(context.Context, string) (*MFALoginChallengeRecord, error) {
			return &MFALoginChallengeRecord{UserID: "u1", TenantID: "t1", Profile: "mobile"}, nil
		},
		ConfirmSessionProfile: func(_ context.Context, stored string, _ bool) (string, SessionProfileStatus) {
			if stored != "mobile" {
				t.Errorf("the confirmer saw stored profile %q", stored)
			}
			return "", SessionProfileConflict
		},
		DeleteMFAChallenge: func(context.Context, string) (bool, error) { deleted++; return true, nil },
		RecordMFAFailure:   func(context.Context, string, int) (bool, error) { failures++; return false, nil },
		GetUserByID:        func(context.Context, string) (LoginUserRecord, error) { return LoginUserRecord{UserID: "u1"}, nil },
		GetTOTPSecret: func(context.Context, string) (*LoginTOTPRecord, error) {
			return &LoginTOTPRecord{Enabled: true, Secret: []byte("s")}, nil
		},
		VerifyTOTPCode:            func([]byte, string, time.Time) (bool, int64, error) { return true, 1, nil },
		UpdateTOTPLastUsedCounter: func(context.Context, string, int64) error { return nil },
		VerifyBackupCodeInTenant:  func(context.Context, string, string, string) error { return nil },
		IssueLoginSessionTokens: func(context.Context, string, LoginUserRecord, string, bool) (string, string, error) {
			issued++
			return "a", "r", nil
		},
		Errors: LoginErrors{UnknownSessionProfile: errUnknownProfile, SessionProfileConflict: errProfileConflict, MFALoginInvalid: errors.New("invalid")},
	}
	_, err := RunConfirmLoginMFAWithType(context.Background(), "challenge", "123456", "totp", deps)
	if !errors.Is(err, errProfileConflict) {
		t.Fatalf("error = %v, want the conflict sentinel", err)
	}
	if deleted != 0 || failures != 0 || issued != 0 {
		t.Fatalf("a refused confirm consumed state: deleted %d, failures %d, issued %d", deleted, failures, issued)
	}
}

// A challenge carries the profile resolved at step one.
func TestCreateMFALoginChallengeStoresProfile(t *testing.T) {
	var saved *MFALoginChallengeRecord
	deps := LoginDeps{
		SaveMFAChallenge: func(_ context.Context, _ string, r *MFALoginChallengeRecord, _ time.Duration) error {
			saved = r
			return nil
		},
		NewSessionID: func() (string, error) { return "c", nil },
		Now:          func() time.Time { return time.Unix(0, 0) },
	}
	ctx := withResolvedSessionProfile(context.Background(), "agent")
	if _, err := RunCreateMFALoginChallenge(ctx, "u1", "t1", true, deps); err != nil || saved.Profile != "agent" || !saved.RememberMe {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if _, err := RunCreateMFALoginChallenge(context.Background(), "u1", "t1", false, deps); err != nil || saved.Profile != "" {
		t.Fatalf("with no resolved profile saved = %+v, %v", saved, err)
	}
}

// Account creation with auto-login picks the profile before the limiter, the
// hash or the provider; without auto-login it never resolves one.
func TestCreateAccountResolvesProfileFirst(t *testing.T) {
	var limiter, hashed, created int
	base := func(autoLogin bool, resolve SessionProfileResolver) AccountDeps {
		return AccountDeps{
			Enabled:               true,
			AutoLogin:             autoLogin,
			RefreshTTL:            time.Hour,
			DefaultRole:           "member",
			ResolveSessionProfile: resolve,
			EnforceAccountLimiter: func(context.Context, string, string) error { limiter++; return nil },
			RoleExists:            func(string) bool { return true },
			HashPassword:          func(string) (string, error) { hashed++; return "h", nil },
			CreateUser: func(context.Context, AccountCreateUserInput) (AccountUserRecord, error) {
				created++
				return AccountUserRecord{UserID: "u1", Role: "member"}, nil
			},
			IssueSessionTokens: func(ctx context.Context, _ AccountUserRecord, _ bool) (string, string, error) {
				if got := ResolvedSessionProfile(ctx); got != "mobile" {
					t.Errorf("the issuer saw profile %q, want mobile", got)
				}
				return "a", "r", nil
			},
			Errors: AccountErrors{UnknownSessionProfile: errUnknownProfile, SessionProfileConflict: errProfileConflict},
		}
	}
	req := AccountCreateRequest{Identifier: "x", Password: "p"}

	for status, want := range map[SessionProfileStatus]error{SessionProfileUnknown: errUnknownProfile, SessionProfileConflict: errProfileConflict} {
		_, err := RunCreateAccount(context.Background(), req, base(true, fixedResolver("", status)))
		if !errors.Is(err, want) || limiter != 0 || hashed != 0 || created != 0 {
			t.Fatalf("status %d: error %v, limiter %d, hashed %d, created %d", status, err, limiter, hashed, created)
		}
	}

	if _, err := RunCreateAccount(context.Background(), req, base(true, fixedResolver("mobile", SessionProfileOK))); err != nil {
		t.Fatalf("create: %v", err)
	}

	called := false
	if _, err := RunCreateAccount(context.Background(), req, base(false, func(context.Context, bool) (string, SessionProfileStatus) {
		called = true
		return "", SessionProfileUnknown
	})); err != nil || called {
		t.Fatalf("without auto-login: error %v, resolver called %v", err, called)
	}
}
