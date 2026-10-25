package flows

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// LoginOptions carries per-login options threaded from the public API.
type LoginOptions struct {
	RememberMe bool
}

// LoginResult is the flow-local login response shape.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	MFARequired  bool
	MFAType      string
	MFASession   string
	MFATypes     []string
}

// LoginUserRecord is a flow-local user model used by login/mfa flows.
type LoginUserRecord struct {
	UserID            string
	Identifier        string
	TenantID          string
	PasswordHash      string
	Role              string
	Status            uint8
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

// LoginTOTPRecord is a flow-local TOTP provider record.
type LoginTOTPRecord struct {
	Secret          []byte
	Enabled         bool
	LastUsedCounter int64
}

// MFALoginChallengeRecord is a flow-local MFA challenge record.
type MFALoginChallengeRecord struct {
	UserID     string
	TenantID   string
	ExpiresAt  int64
	Attempts   uint16
	RememberMe bool
	// Profile is the session profile resolved at login, so the session
	// issued after the second factor receives it. Empty when no profiles
	// are configured.
	Profile string
}

// LoginMetrics carries metric IDs needed by login/mfa flows.
type LoginMetrics struct {
	LoginSuccess     int
	LoginFailure     int
	LoginRateLimited int
	LockoutTrigger   int
	SessionCreated   int
	MFALoginRequired int
	MFALoginSuccess  int
	MFALoginFailure  int
	MFAReplayAttempt int
}

// LoginEvents carries audit event names used by login/mfa flows.
type LoginEvents struct {
	LoginSuccess        string
	LoginFailure        string
	LoginRateLimited    string
	MFARequired         string
	MFASuccess          string
	MFAFailure          string
	MFAAttemptsExceeded string
}

// LoginErrors carries host-level sentinel errors used by login/mfa flows.
type LoginErrors struct {
	EngineNotReady           error
	InvalidCredentials       error
	LoginRateLimited         error
	AccountUnverified        error
	AccountLocked            error
	DeviceBindingRejected    error
	TOTPFeatureDisabled      error
	MFALoginInvalid          error
	MFALoginExpired          error
	MFALoginAttemptsExceeded error
	MFALoginReplay           error
	MFALoginUnavailable      error
	UserNotFound             error
	BackupCodeRateLimited    error
	BackupCodeInvalid        error
	BackupCodesNotConfigured error
	WebAuthnCloneDetected    error
	WebAuthnCeremonyExpired  error
	WebAuthnUnavailable      error

	// UnknownSessionProfile and SessionProfileConflict are returned when the
	// requested session profile does not exist or is requested in two
	// incompatible ways. They are only used while profiles are configured.
	UnknownSessionProfile  error
	SessionProfileConflict error

	// SystemUnavailable is what the login limiter hooks return when the
	// limiter backend is down and Security.LimiterFailClosed is on. Any other
	// error from a hook means "rate limited". Nil keeps that meaning for every
	// error.
	SystemUnavailable error
}

// LoginDeps captures login+mfa dependencies.
type LoginDeps struct {
	TOTPEnabled               bool
	RequireTOTPForLogin       bool
	WebAuthnEnabled           bool
	WebAuthnRequireForLogin   bool
	EnforceReplayProtection   bool
	RequireVerified           bool
	PendingVerificationStatus uint8
	PasswordUpgradeOnLogin    bool
	MFALoginMaxAttempts       int
	MFALoginChallengeTTL      time.Duration
	DeviceBindingEnabled      bool
	EnforceIPBinding          bool
	EnforceUserAgentBinding   bool

	TenantIDFromContext  func(context.Context) string
	ClientIPFromContext  func(context.Context) string
	UserAgentFromContext func(context.Context) string
	Now                  func() time.Time
	AccountStatusError   func(status uint8) error

	// ReserveLoginRate claims one attempt of the identifier's budget before
	// the password is verified; any error it returns means "rate limited"
	// unless it is Errors.SystemUnavailable (a fail-closed limiter outage).
	// The claim is kept whatever the outcome, so concurrent requests cannot
	// verify more passwords than the budget allows; ResetLoginRate clears it
	// once the password is verified.
	ReserveLoginRate func(context.Context, string) error
	// IncrementLoginRate records a failure after the password was already
	// verified (a role that no longer resolves).
	IncrementLoginRate func(context.Context, string) error
	ResetLoginRate     func(context.Context, string) error

	// Auto-lockout hooks: RecordLockoutFailure returns true when threshold is reached.
	AutoLockoutEnabled   bool
	RecordLockoutFailure func(context.Context, string) (bool, error)
	ResetLockoutCounter  func(context.Context, string) error
	LockAccount          func(context.Context, string) error

	// EnforceTenantMatch requires a resolved user's TenantID to equal the
	// request's tenant. Set only when multi-tenancy is enabled; with it
	// false the flow behaves exactly as it did before tenant scoping.
	EnforceTenantMatch bool

	// GetUserByIdentifier and GetUserByID take a context so the engine can
	// scope the lookup to the request's tenant when multi-tenancy is on.
	GetUserByIdentifier func(context.Context, string) (LoginUserRecord, error)
	GetUserByID         func(context.Context, string) (LoginUserRecord, error)
	UpdatePasswordHash  func(string, string) error
	// UpdatePasswordHashInTenant, when set, replaces UpdatePasswordHash for
	// the rehash-on-login write. The engine sets it only when multi-tenancy
	// is enabled and the provider can scope the write to a tenant.
	UpdatePasswordHashInTenant func(context.Context, string, string, string) error
	GetTOTPSecret              func(context.Context, string) (*LoginTOTPRecord, error)
	UpdateTOTPLastUsedCounter  func(context.Context, string, int64) error

	VerifyPassword           func(string, string) (bool, error)
	PasswordNeedsUpgrade     func(string) (bool, error)
	HashPassword             func(string) (string, error)
	VerifyTOTPCode           func([]byte, string, time.Time) (bool, int64, error)
	VerifyBackupCodeInTenant func(context.Context, string, string, string) error

	GetMFAChallenge    func(context.Context, string) (*MFALoginChallengeRecord, error)
	SaveMFAChallenge   func(context.Context, string, *MFALoginChallengeRecord, time.Duration) error
	DeleteMFAChallenge func(context.Context, string) (bool, error)
	// ReserveMFAAttempt claims one attempt of the challenge before a factor
	// is evaluated and returns how many have been used including this one; a
	// claim past limit deletes the challenge and returns a store error that
	// MapMFAStoreError maps to Errors.MFALoginAttemptsExceeded.
	ReserveMFAAttempt func(ctx context.Context, challengeID string, limit int) (int, error)
	// ReleaseMFAAttempt gives a claim back for a request that evaluated no
	// factor. Optional.
	ReleaseMFAAttempt func(ctx context.Context, challengeID string)
	MapMFAStoreError  func(error) error

	// RecordAssurance, when set, records that the session just issued after
	// a successful second factor holds an MFA assurance. It receives the
	// refresh token of the new session (which names its ID) and the factor
	// ("totp", "backup_code" or "webauthn"). The engine sets it only while
	// role-switch step-up policies are configured; it is best effort, since
	// a missing assurance only means a later step-up asks for the factor
	// again.
	RecordAssurance func(ctx context.Context, tenantID, refreshToken, method string, rememberMe bool)

	CreateMFALoginChallenge func(context.Context, string, string, bool) (string, error)
	IssueLoginSessionTokens func(context.Context, string, LoginUserRecord, string, bool) (string, string, error)
	EnforceSessionHardening func(context.Context, string, string) error

	// WebAuthn second-factor hooks (nil when the feature is disabled).
	HasWebAuthnCredentials   func(context.Context, string) (bool, error)
	ConfirmWebAuthnAssertion func(context.Context, string, string, []byte) error

	GetRoleMask        func(string) (interface{}, bool)
	NewSessionID       func() (string, error)
	NewRefreshSecret   func() ([32]byte, error)
	HashRefreshSecret  func([32]byte) [32]byte
	EncodeRefreshToken func(string, [32]byte) (string, error)
	HashBindingValue   func(string) [32]byte
	SessionLifetime    func(rememberMe bool) time.Duration
	SaveSession        func(context.Context, *session.Session, time.Duration) error
	IssueAccessToken   func(*session.Session) (string, error)

	// Session profiles; all three are nil unless profiles are configured, and
	// a nil ResolveSessionProfile leaves every login exactly as it was.
	ResolveSessionProfile  SessionProfileResolver
	ConfirmSessionProfile  SessionProfileConfirmer
	SessionProfileLifetime SessionProfileLifetime

	MetricInc     func(int)
	EmitAudit     func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit func(context.Context, string, string, func() map[string]string)
	Warn          func(string, ...any)

	Metrics LoginMetrics
	Events  LoginEvents
	Errors  LoginErrors
}

// profileRejection maps a failed profile resolution to the host's sentinel,
// or nil when the profile was resolved.
func (d LoginDeps) profileRejection(status SessionProfileStatus) error {
	switch status {
	case SessionProfileUnknown:
		return d.Errors.UnknownSessionProfile
	case SessionProfileConflict:
		return d.Errors.SessionProfileConflict
	}
	return nil
}

// dummyTimingHash is a syntactically valid Argon2id hash used to equalize
// response time on rejection paths that have no real hash to verify against
// (empty password, unknown identifier). Skipping the dummy verification on
// any credential-rejection path would create a measurable timing oracle.
const dummyTimingHash = DummyTimingHash

// DummyTimingHash is the hash verified in place of a real one when there is
// none to verify, so every rejection costs one Argon2 verification.
const DummyTimingHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// DummyTimingPassword is the password verified against DummyTimingHash.
const DummyTimingPassword = "dummy-timing-equalization"

// errTenantMismatch marks a lookup discarded because the record belonged to
// a different tenant than the request. It never reaches the caller: it only
// selects the audit reason on a path that otherwise behaves exactly like an
// unknown identifier.
var errTenantMismatch = errors.New("goauth: user belongs to a different tenant")

// normalizeLoginDeps fills the optional hooks every login entry point may
// leave nil.
func normalizeLoginDeps(deps *LoginDeps) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.EmitRateLimit == nil {
		deps.EmitRateLimit = func(context.Context, string, string, func() map[string]string) {}
	}
	if deps.Warn == nil {
		deps.Warn = func(string, ...any) {}
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.ClientIPFromContext == nil {
		deps.ClientIPFromContext = func(context.Context) string { return "" }
	}
	if deps.UserAgentFromContext == nil {
		deps.UserAgentFromContext = func(context.Context) string { return "" }
	}
}

// RunLoginWithResult executes the login flow and either issues tokens or returns MFA challenge details.
func RunLoginWithResult(ctx context.Context, username, password string, opts LoginOptions, deps LoginDeps) (*LoginResult, error) {
	normalizeLoginDeps(&deps)
	if deps.AccountStatusError == nil ||
		deps.GetUserByIdentifier == nil ||
		deps.VerifyPassword == nil ||
		deps.IssueLoginSessionTokens == nil ||
		deps.EnforceSessionHardening == nil {
		return nil, deps.Errors.EngineNotReady
	}

	tenantID := deps.TenantIDFromContext(ctx)

	// Choose the session profile first: an unknown or conflicting request is
	// refused before any limiter is read, any password is hashed and any
	// provider is called.
	if deps.ResolveSessionProfile != nil {
		name, status := deps.ResolveSessionProfile(ctx, opts.RememberMe)
		if rejected := deps.profileRejection(status); rejected != nil {
			deps.EmitAudit(ctx, deps.Events.LoginFailure, false, "", tenantID, "", rejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "session_profile",
				}
			})
			return nil, rejected
		}
		ctx = withResolvedSessionProfile(ctx, name)
	}

	if deps.ReserveLoginRate != nil {
		if err := deps.ReserveLoginRate(ctx, username); err != nil {
			return nil, deps.loginRateRefusal(ctx, err, "", tenantID, username)
		}
	}

	if password == "" {
		// Perform a dummy password verification to prevent timing oracle.
		// Without this, an attacker could distinguish empty-password rejections
		// from wrong-password rejections by measuring response time.
		if deps.VerifyPassword != nil {
			_, _ = deps.VerifyPassword("dummy-timing-equalization", dummyTimingHash)
		}
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, "", tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "empty_password",
			}
		})
		return nil, deps.Errors.InvalidCredentials
	}

	user, err := deps.GetUserByIdentifier(ctx, username)
	if err == nil && deps.EnforceTenantMatch && tenantID != "" && user.TenantID != tenantID {
		// The lookup is already tenant-scoped when multi-tenancy is on, so
		// this is a defence-in-depth backstop against a provider that
		// ignores the tenant argument. Discard the record and fall into the
		// unknown-identifier path below: the caller must not be able to tell
		// a foreign-tenant account from one that does not exist.
		deps.Warn("goAuth: tenant-scoped lookup returned a user from another tenant; check the TenantAwareUserProvider implementation")
		user = LoginUserRecord{}
		err = errTenantMismatch
	}
	if err != nil {
		// Perform a dummy password verification so unknown identifiers cost
		// the same as wrong passwords; returning immediately would let an
		// attacker enumerate valid usernames by measuring response time.
		if deps.VerifyPassword != nil {
			_, _ = deps.VerifyPassword("dummy-timing-equalization", dummyTimingHash)
		}
		// The audit trail distinguishes a cross-tenant attempt from an
		// unknown identifier; the caller-facing response deliberately does
		// not. Audit events must not be surfaced to end users.
		reason := "user_not_found"
		if errors.Is(err, errTenantMismatch) {
			reason = "tenant_mismatch"
		}
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, "", tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     reason,
			}
		})
		return nil, deps.Errors.InvalidCredentials
	}

	var ok bool
	mismatchReason := "password_mismatch"
	if user.PasswordHash == "" {
		// An account created through external sign-in has no password. Verify
		// a dummy hash so it costs what a wrong password costs, and let it
		// fall through the wrong-password path -- the same lockout, limiter
		// and error -- so nothing tells it apart from one that has a password.
		_, _ = deps.VerifyPassword(DummyTimingPassword, DummyTimingHash)
		mismatchReason = "password_not_set"
	} else {
		ok, err = deps.VerifyPassword(password, user.PasswordHash)
	}
	if err != nil || !ok {
		// Auto-lockout: record failure and lock if threshold reached.
		if deps.AutoLockoutEnabled && deps.RecordLockoutFailure != nil && deps.LockAccount != nil {
			if shouldLock, lockErr := deps.RecordLockoutFailure(ctx, user.UserID); lockErr == nil && shouldLock {
				deps.MetricInc(deps.Metrics.LockoutTrigger)
				_ = deps.LockAccount(ctx, user.UserID)
				deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.AccountLocked, func() map[string]string {
					return map[string]string{
						"identifier": username,
						"reason":     "auto_lockout",
					}
				})
				return nil, deps.Errors.AccountLocked
			}
		}

		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     mismatchReason,
			}
		})
		return nil, deps.Errors.InvalidCredentials
	}

	// The password is right: the claim made before verification is not a
	// failure, whatever the account's status or second factor turns out to be.
	if deps.ResetLoginRate != nil {
		_ = deps.ResetLoginRate(ctx, username)
	}

	return runCompleteLogin(ctx, username, user, tenantID, opts, deps, func() {
		if deps.PasswordUpgradeOnLogin {
			if needsUpgrade, err := deps.PasswordNeedsUpgrade(user.PasswordHash); err == nil && needsUpgrade {
				if upgradedHash, err := deps.HashPassword(password); err == nil {
					var updateErr error
					if deps.UpdatePasswordHashInTenant != nil {
						updateErr = deps.UpdatePasswordHashInTenant(ctx, tenantID, user.UserID, upgradedHash)
					} else {
						updateErr = deps.UpdatePasswordHash(user.UserID, upgradedHash)
					}
					if updateErr != nil {
						deps.Warn("goAuth: password hash upgrade update failed")
					}
				} else {
					deps.Warn("goAuth: password hash upgrade generation failed")
				}
			}
		}
		password = ""
	})
}

// RunCompleteLogin finishes a login whose primary factor the caller already
// verified (a password, or an external identity): account status, device
// binding, session hardening, the MFA decision with its challenge, and session
// issuance. username is the identifier the audit trail and the login limiter
// know the account by.
func RunCompleteLogin(ctx context.Context, username string, user LoginUserRecord, opts LoginOptions, deps LoginDeps) (*LoginResult, error) {
	normalizeLoginDeps(&deps)
	if deps.AccountStatusError == nil ||
		deps.IssueLoginSessionTokens == nil ||
		deps.EnforceSessionHardening == nil {
		return nil, deps.Errors.EngineNotReady
	}
	return runCompleteLogin(ctx, username, user, deps.TenantIDFromContext(ctx), opts, deps, nil)
}

// runCompleteLogin is the part of a login that follows the primary factor,
// shared by every way of authenticating so that they cannot drift apart. The
// caller has resolved the session profile and consumed its limiters.
// afterAccountChecks, when set, runs once the account is known to be usable
// and before anything is issued; the password path uses it for the
// rehash-on-login upgrade.
func runCompleteLogin(
	ctx context.Context,
	username string,
	user LoginUserRecord,
	tenantID string,
	opts LoginOptions,
	deps LoginDeps,
	afterAccountChecks func(),
) (*LoginResult, error) {
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "account_status",
			}
		})
		return nil, statusErr
	}

	if deps.RequireVerified && user.Status == deps.PendingVerificationStatus {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.AccountUnverified, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "pending_verification",
			}
		})
		return nil, deps.Errors.AccountUnverified
	}

	if afterAccountChecks != nil {
		afterAccountChecks()
	}

	if deps.DeviceBindingEnabled {
		if deps.EnforceIPBinding && deps.ClientIPFromContext(ctx) == "" {
			deps.MetricInc(deps.Metrics.LoginFailure)
			deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.DeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_ip_context",
				}
			})
			return nil, deps.Errors.DeviceBindingRejected
		}
		if deps.EnforceUserAgentBinding && deps.UserAgentFromContext(ctx) == "" {
			deps.MetricInc(deps.Metrics.LoginFailure)
			deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.DeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_user_agent_context",
				}
			})
			return nil, deps.Errors.DeviceBindingRejected
		}
	}

	if err := deps.EnforceSessionHardening(ctx, tenantID, user.UserID); err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_hardening",
			}
		})
		return nil, err
	}

	mfaTypes := make([]string, 0, 2)
	if deps.TOTPEnabled && deps.RequireTOTPForLogin {
		record, err := deps.GetTOTPSecret(ctx, user.UserID)
		if err != nil {
			deps.MetricInc(deps.Metrics.MFALoginFailure)
			deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, tenantID, "", deps.Errors.MFALoginUnavailable, nil)
			return nil, deps.Errors.MFALoginUnavailable
		}
		if record != nil && record.Enabled && len(record.Secret) > 0 {
			mfaTypes = append(mfaTypes, "totp")
		}
	}
	if deps.WebAuthnEnabled && deps.WebAuthnRequireForLogin && deps.HasWebAuthnCredentials != nil {
		has, err := deps.HasWebAuthnCredentials(ctx, user.UserID)
		if err != nil {
			deps.MetricInc(deps.Metrics.MFALoginFailure)
			deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, tenantID, "", deps.Errors.MFALoginUnavailable, nil)
			return nil, deps.Errors.MFALoginUnavailable
		}
		if has {
			// Phishing-resistant factor first: webauthn is the preferred type.
			mfaTypes = append([]string{"webauthn"}, mfaTypes...)
		}
	}
	if len(mfaTypes) > 0 {
		challengeID, err := deps.CreateMFALoginChallenge(ctx, user.UserID, tenantID, opts.RememberMe)
		if err != nil {
			deps.MetricInc(deps.Metrics.MFALoginFailure)
			deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, tenantID, "", err, nil)
			return nil, err
		}
		deps.MetricInc(deps.Metrics.MFALoginRequired)
		deps.EmitAudit(ctx, deps.Events.MFARequired, true, user.UserID, tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier": username,
			}
		})
		return &LoginResult{
			MFARequired: true,
			MFAType:     mfaTypes[0],
			MFATypes:    mfaTypes,
			MFASession:  challengeID,
		}, nil
	}

	access, refresh, err := deps.IssueLoginSessionTokens(ctx, username, user, tenantID, opts.RememberMe)
	if err != nil {
		return nil, err
	}
	// Reset lockout counter on successful login.
	if deps.AutoLockoutEnabled && deps.ResetLockoutCounter != nil {
		_ = deps.ResetLockoutCounter(ctx, user.UserID)
	}
	return &LoginResult{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// RunConfirmLoginMFAWithType executes MFA challenge confirmation and session issuance.
func RunConfirmLoginMFAWithType(ctx context.Context, challengeID, code, mfaType string, deps LoginDeps) (*LoginResult, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.MapMFAStoreError == nil {
		deps.MapMFAStoreError = func(error) error { return deps.Errors.MFALoginUnavailable }
	}

	totpConfigured := deps.TOTPEnabled && deps.RequireTOTPForLogin
	webauthnConfigured := deps.WebAuthnEnabled && deps.WebAuthnRequireForLogin
	if !totpConfigured && !webauthnConfigured {
		return nil, deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetMFAChallenge == nil ||
		deps.DeleteMFAChallenge == nil ||
		deps.ReserveMFAAttempt == nil ||
		deps.GetUserByID == nil ||
		deps.GetTOTPSecret == nil ||
		deps.VerifyTOTPCode == nil ||
		deps.VerifyBackupCodeInTenant == nil ||
		deps.AccountStatusError == nil ||
		deps.IssueLoginSessionTokens == nil ||
		deps.UpdateTOTPLastUsedCounter == nil {
		return nil, deps.Errors.EngineNotReady
	}
	if challengeID == "" {
		return nil, deps.Errors.MFALoginInvalid
	}

	record, err := deps.GetMFAChallenge(ctx, challengeID)
	if err != nil {
		mapped := deps.MapMFAStoreError(err)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, "", deps.TenantIDFromContext(ctx), "", mapped, func() map[string]string {
			return map[string]string{
				"reason": "challenge_load_failed",
			}
		})
		return nil, mapped
	}

	// The profile resolved at login wins. A confirm that names a different
	// profile is refused here, before anything is consumed or counted, so the
	// challenge stays usable with the right profile.
	if deps.ConfirmSessionProfile != nil {
		name, status := deps.ConfirmSessionProfile(ctx, record.Profile, record.RememberMe)
		if rejected := deps.profileRejection(status); rejected != nil {
			deps.EmitAudit(ctx, deps.Events.MFAFailure, false, record.UserID, record.TenantID, "", rejected, func() map[string]string {
				return map[string]string{
					"reason": "session_profile",
				}
			})
			return nil, rejected
		}
		ctx = withResolvedSessionProfile(ctx, name)
	} else if record.Profile != "" {
		// The challenge was created under a profile this engine no longer
		// has configured.
		return nil, deps.Errors.UnknownSessionProfile
	}

	if tenant := deps.TenantIDFromContext(ctx); tenant != "" && record.TenantID != "" && tenant != record.TenantID {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, "", tenant, "", deps.Errors.MFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "tenant_mismatch",
			}
		})
		return nil, deps.Errors.MFALoginInvalid
	}

	user, err := deps.GetUserByID(ctx, record.UserID)
	if err != nil {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, record.UserID, record.TenantID, "", deps.Errors.UserNotFound, nil)
		return nil, deps.Errors.UserNotFound
	}

	// The check above compares the context tenant to the CHALLENGE's tenant.
	// This one compares it to the resolved USER's tenant — a challenge whose
	// record points at a user in another tenant must never complete, however
	// that mismatch arose.
	if contextTenant := deps.TenantIDFromContext(ctx); deps.EnforceTenantMatch &&
		contextTenant != "" && user.TenantID != contextTenant {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, contextTenant, "", deps.Errors.MFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "tenant_mismatch",
			}
		})
		return nil, deps.Errors.MFALoginInvalid
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return nil, statusErr
	}
	if deps.RequireVerified && user.Status == deps.PendingVerificationStatus {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.AccountUnverified, nil)
		return nil, deps.Errors.AccountUnverified
	}

	// Every factor evaluation is preceded by a claim on the challenge's
	// attempts, made in one atomic step, so concurrent confirmations cannot
	// evaluate more codes than MFALoginMaxAttempts allows.
	var attempt int
	claim := func() error {
		var claimErr error
		attempt, claimErr = claimLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps)
		return claimErr
	}
	fail := func(cause error) (*LoginResult, error) {
		return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, attempt, cause, deps)
	}

	switch strings.ToLower(strings.TrimSpace(mfaType)) {
	case "", "totp":
		totpRecord, terr := loadLoginTOTPRecord(ctx, challengeID, user.UserID, record.TenantID, deps)
		if terr != nil {
			return nil, terr
		}
		if err := claim(); err != nil {
			return nil, err
		}
		if code == "" {
			return fail(deps.Errors.MFALoginInvalid)
		}
		ok, counter, verr := deps.VerifyTOTPCode(totpRecord.Secret, code, deps.Now())
		if verr != nil || !ok {
			return fail(deps.Errors.MFALoginInvalid)
		}

		if deps.EnforceReplayProtection {
			if counter <= totpRecord.LastUsedCounter {
				releaseLoginMFAAttempt(ctx, challengeID, deps)
				deps.MetricInc(deps.Metrics.MFAReplayAttempt)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginReplay, nil)
				return nil, deps.Errors.MFALoginReplay
			}
			if err := deps.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
				releaseLoginMFAAttempt(ctx, challengeID, deps)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginUnavailable, nil)
				return nil, deps.Errors.MFALoginUnavailable
			}
		}
	case "backup":
		if _, terr := loadLoginTOTPRecord(ctx, challengeID, user.UserID, record.TenantID, deps); terr != nil {
			return nil, terr
		}
		if err := claim(); err != nil {
			return nil, err
		}
		if code == "" {
			return fail(deps.Errors.MFALoginInvalid)
		}
		if berr := deps.VerifyBackupCodeInTenant(ctx, record.TenantID, user.UserID, code); berr != nil {
			switch {
			case errors.Is(berr, deps.Errors.BackupCodeRateLimited):
				return fail(deps.Errors.MFALoginAttemptsExceeded)
			case errors.Is(berr, deps.Errors.BackupCodeInvalid), errors.Is(berr, deps.Errors.BackupCodesNotConfigured):
				return fail(deps.Errors.MFALoginInvalid)
			default:
				return fail(deps.Errors.MFALoginUnavailable)
			}
		}
	case "webauthn":
		if err := claim(); err != nil {
			return nil, err
		}
		if !webauthnConfigured || deps.ConfirmWebAuthnAssertion == nil {
			return fail(deps.Errors.MFALoginInvalid)
		}
		if code == "" {
			return fail(deps.Errors.MFALoginInvalid)
		}
		if werr := deps.ConfirmWebAuthnAssertion(ctx, challengeID, user.UserID, []byte(code)); werr != nil {
			switch {
			case errors.Is(werr, deps.Errors.WebAuthnCloneDetected):
				// A cloned authenticator is a compromise signal, not a typo:
				// destroy the challenge instead of consuming an attempt.
				_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
				deps.MetricInc(deps.Metrics.MFAReplayAttempt)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", werr, func() map[string]string {
					return map[string]string{
						"reason": "webauthn_clone_detected",
					}
				})
				return nil, werr
			case errors.Is(werr, deps.Errors.WebAuthnCeremonyExpired):
				// No verification happened; surface "call BeginWebAuthnLogin
				// (again)" without consuming a challenge attempt.
				releaseLoginMFAAttempt(ctx, challengeID, deps)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", werr, func() map[string]string {
					return map[string]string{
						"reason": "webauthn_ceremony_expired",
					}
				})
				return nil, werr
			case errors.Is(werr, deps.Errors.WebAuthnUnavailable):
				releaseLoginMFAAttempt(ctx, challengeID, deps)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginUnavailable, nil)
				return nil, deps.Errors.MFALoginUnavailable
			default:
				return fail(deps.Errors.MFALoginInvalid)
			}
		}
	default:
		if err := claim(); err != nil {
			return nil, err
		}
		return fail(deps.Errors.MFALoginInvalid)
	}

	deleted, err := deps.DeleteMFAChallenge(ctx, challengeID)
	if err != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginUnavailable, nil)
		return nil, deps.Errors.MFALoginUnavailable
	}
	if !deleted {
		deps.MetricInc(deps.Metrics.MFAReplayAttempt)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginReplay, nil)
		return nil, deps.Errors.MFALoginReplay
	}

	identifier := user.Identifier
	if identifier == "" {
		identifier = user.UserID
	}
	access, refresh, err := deps.IssueLoginSessionTokens(ctx, identifier, user, record.TenantID, record.RememberMe)
	if err != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", err, nil)
		return nil, err
	}

	if deps.RecordAssurance != nil {
		deps.RecordAssurance(ctx, record.TenantID, refresh, loginAssuranceMethod(mfaType), record.RememberMe)
	}

	deps.MetricInc(deps.Metrics.MFALoginSuccess)
	var successMeta func() map[string]string
	if profile := ResolvedSessionProfile(ctx); profile != "" {
		successMeta = func() map[string]string { return profileMeta(nil, profile) }
	}
	deps.EmitAudit(ctx, deps.Events.MFASuccess, true, user.UserID, record.TenantID, "", nil, successMeta)
	return &LoginResult{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// loginAssuranceMethod maps the login confirmation type to the factor name
// stored in a session assurance.
func loginAssuranceMethod(mfaType string) string {
	switch strings.ToLower(strings.TrimSpace(mfaType)) {
	case "backup":
		return StepUpMethodBackupCode
	case "webauthn":
		return "webauthn"
	default:
		return StepUpMethodTOTP
	}
}

// loadLoginTOTPRecord fetches and gates the user's TOTP record for the
// totp/backup confirm paths, preserving the pre-webauthn error semantics:
// store errors are unavailable (attempt kept), disabled/missing TOTP deletes
// the challenge and reports invalid.
func loadLoginTOTPRecord(
	ctx context.Context,
	challengeID string,
	userID string,
	tenantID string,
	deps LoginDeps,
) (*LoginTOTPRecord, error) {
	totpRecord, err := deps.GetTOTPSecret(ctx, userID)
	if err != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, userID, tenantID, "", deps.Errors.MFALoginUnavailable, nil)
		return nil, deps.Errors.MFALoginUnavailable
	}
	if totpRecord == nil || !totpRecord.Enabled || len(totpRecord.Secret) == 0 {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, userID, tenantID, "", deps.Errors.MFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "totp_disabled_or_missing",
			}
		})
		return nil, deps.Errors.MFALoginInvalid
	}
	return totpRecord, nil
}

// mfaAttemptLimit is the number of factor evaluations one challenge allows.
func (d LoginDeps) mfaAttemptLimit() int {
	if d.MFALoginMaxAttempts < 1 {
		return 1
	}
	return d.MFALoginMaxAttempts
}

// claimLoginMFAAttempt claims one attempt of the challenge before a factor is
// evaluated. A refusal (the challenge is gone, expired, or this claim is past
// the limit and deleted it) is returned as the error the confirmation ends
// with.
func claimLoginMFAAttempt(ctx context.Context, challengeID, userID, tenantID string, deps LoginDeps) (int, error) {
	attempt, err := deps.ReserveMFAAttempt(ctx, challengeID, deps.mfaAttemptLimit())
	if err == nil {
		return attempt, nil
	}
	deps.MetricInc(deps.Metrics.MFALoginFailure)
	mapped := deps.MapMFAStoreError(err)
	event := deps.Events.MFAFailure
	if errors.Is(mapped, deps.Errors.MFALoginAttemptsExceeded) {
		event = deps.Events.MFAAttemptsExceeded
	}
	deps.EmitAudit(ctx, event, false, userID, tenantID, "", mapped, nil)
	return 0, mapped
}

// releaseLoginMFAAttempt gives back a claim for a request that evaluated no
// factor.
func releaseLoginMFAAttempt(ctx context.Context, challengeID string, deps LoginDeps) {
	if deps.ReleaseMFAAttempt != nil {
		deps.ReleaseMFAAttempt(ctx, challengeID)
	}
}

// runFailLoginMFAAttempt ends a confirmation whose factor was wrong. attempt
// is the claim it made; when that claim took the last attempt the challenge is
// destroyed and the caller learns the attempts are exhausted.
func runFailLoginMFAAttempt(
	ctx context.Context,
	challengeID string,
	userID string,
	tenantID string,
	attempt int,
	cause error,
	deps LoginDeps,
) (*LoginResult, error) {
	if attempt >= deps.mfaAttemptLimit() {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAAttemptsExceeded, false, userID, tenantID, "", deps.Errors.MFALoginAttemptsExceeded, nil)
		return nil, deps.Errors.MFALoginAttemptsExceeded
	}
	deps.MetricInc(deps.Metrics.MFALoginFailure)
	if cause == nil {
		cause = deps.Errors.MFALoginInvalid
	}
	deps.EmitAudit(ctx, deps.Events.MFAFailure, false, userID, tenantID, "", cause, nil)
	return nil, cause
}

// RunCreateMFALoginChallenge creates and stores a new MFA challenge.
// rememberMe is persisted with the challenge so the durable-session choice
// made at step 1 survives to token issuance after MFA confirmation.
func RunCreateMFALoginChallenge(ctx context.Context, userID, tenantID string, rememberMe bool, deps LoginDeps) (string, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.SaveMFAChallenge == nil || deps.NewSessionID == nil {
		return "", deps.Errors.EngineNotReady
	}
	challengeID, err := deps.NewSessionID()
	if err != nil {
		return "", deps.Errors.MFALoginUnavailable
	}

	ttl := deps.MFALoginChallengeTTL
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	record := &MFALoginChallengeRecord{
		UserID:     userID,
		TenantID:   tenantID,
		ExpiresAt:  deps.Now().Add(ttl).Unix(),
		Attempts:   0,
		RememberMe: rememberMe,
		Profile:    ResolvedSessionProfile(ctx),
	}

	if err := deps.SaveMFAChallenge(ctx, challengeID, record, ttl); err != nil {
		return "", deps.MapMFAStoreError(err)
	}
	return challengeID, nil
}

// RunIssueLoginSessionTokens issues access/refresh tokens after successful login or MFA.
func RunIssueLoginSessionTokens(
	ctx context.Context,
	username string,
	user LoginUserRecord,
	tenantID string,
	rememberMe bool,
	deps LoginDeps,
) (string, string, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.EmitRateLimit == nil {
		deps.EmitRateLimit = func(context.Context, string, string, func() map[string]string) {}
	}
	if deps.ClientIPFromContext == nil {
		deps.ClientIPFromContext = func(context.Context) string { return "" }
	}
	if deps.UserAgentFromContext == nil {
		deps.UserAgentFromContext = func(context.Context) string { return "" }
	}
	if deps.GetRoleMask == nil ||
		deps.NewSessionID == nil ||
		deps.NewRefreshSecret == nil ||
		deps.HashRefreshSecret == nil ||
		deps.EncodeRefreshToken == nil ||
		deps.HashBindingValue == nil ||
		deps.SessionLifetime == nil ||
		deps.SaveSession == nil ||
		deps.IssueAccessToken == nil {
		return "", "", deps.Errors.EngineNotReady
	}

	// Every session-creating path applies a profile: one a flow resolved up
	// front, or else a fresh resolution here.
	profile, profileStatus := sessionProfileFor(ctx, rememberMe, deps.ResolveSessionProfile)
	if rejected := deps.profileRejection(profileStatus); rejected != nil {
		return "", "", rejected
	}
	if profile != "" && deps.SessionProfileLifetime == nil {
		return "", "", deps.Errors.EngineNotReady
	}

	mask, ok := deps.GetRoleMask(user.Role)
	if !ok {
		if deps.IncrementLoginRate != nil {
			if err := deps.IncrementLoginRate(ctx, username); err != nil {
				if isLoginLimiterOutage(err, deps) {
					return "", "", deps.Errors.SystemUnavailable
				}
				deps.MetricInc(deps.Metrics.LoginRateLimited)
				deps.EmitAudit(ctx, deps.Events.LoginRateLimited, false, user.UserID, tenantID, "", deps.Errors.LoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				deps.EmitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return "", "", deps.Errors.LoginRateLimited
			}
		}
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "role_mask_missing",
			}
		})
		return "", "", deps.Errors.InvalidCredentials
	}

	sessionID, err := deps.NewSessionID()
	if err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_id_generation",
			}
		})
		return "", "", err
	}
	refreshSecret, err := deps.NewRefreshSecret()
	if err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "refresh_secret_generation",
			}
		})
		return "", "", err
	}

	now := deps.Now()
	sessionLifetime := deps.SessionLifetime(rememberMe)
	plan := legacyPlan(now, sessionLifetime)
	if profile != "" {
		var lifetimeErr error
		plan, lifetimeErr = profilePlan(profile, now, deps.SessionProfileLifetime)
		if lifetimeErr != nil {
			deps.MetricInc(deps.Metrics.LoginFailure)
			deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, sessionID, lifetimeErr, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "session_profile_lifetime",
				}
			})
			return "", "", lifetimeErr
		}
	}
	accountVersion := user.AccountVersion
	if accountVersion == 0 {
		accountVersion = 1
	}

	var ipHash [32]byte
	var userAgentHash [32]byte
	if deps.DeviceBindingEnabled {
		if ip := deps.ClientIPFromContext(ctx); ip != "" {
			ipHash = deps.HashBindingValue(ip)
		}
		if ua := deps.UserAgentFromContext(ctx); ua != "" {
			userAgentHash = deps.HashBindingValue(ua)
		}
	}

	sess := &session.Session{
		SessionID:         sessionID,
		UserID:            user.UserID,
		TenantID:          tenantID,
		Role:              user.Role,
		Mask:              mask,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    accountVersion,
		Status:            user.Status,
		RefreshHash:       deps.HashRefreshSecret(refreshSecret),
		IPHash:            ipHash,
		UserAgentHash:     userAgentHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         plan.expiresAt,
		Profile:           plan.profile,
	}

	if err := deps.SaveSession(ctx, sess, plan.ttl); err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_save_failed",
			}
		})
		return "", "", err
	}

	access, err := deps.IssueAccessToken(sess)
	if err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "issue_access_failed",
			}
		})
		return "", "", err
	}

	refresh, err := deps.EncodeRefreshToken(sessionID, refreshSecret)
	if err != nil {
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "encode_refresh_failed",
			}
		})
		return "", "", err
	}

	if deps.ResetLoginRate != nil {
		if err := deps.ResetLoginRate(ctx, username); err != nil {
			deps.MetricInc(deps.Metrics.LoginRateLimited)
			deps.EmitAudit(ctx, deps.Events.LoginRateLimited, false, user.UserID, tenantID, sessionID, deps.Errors.LoginRateLimited, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "reset_limiter_failed",
				}
			})
			return "", "", deps.Errors.LoginRateLimited
		}
	}

	deps.MetricInc(deps.Metrics.SessionCreated)
	deps.MetricInc(deps.Metrics.LoginSuccess)
	deps.EmitAudit(ctx, deps.Events.LoginSuccess, true, user.UserID, tenantID, sessionID, nil, func() map[string]string {
		return profileMeta(map[string]string{
			"identifier": username,
		}, plan.profile)
	})

	return access, refresh, nil
}

// loginRateRefusal turns a failed limiter reservation into the error the login
// returns, recording it as a rate-limit event unless the limiter backend was
// down and the engine fails closed.
func (d LoginDeps) loginRateRefusal(ctx context.Context, err error, userID, tenantID, username string) error {
	if isLoginLimiterOutage(err, d) {
		return d.Errors.SystemUnavailable
	}
	d.MetricInc(d.Metrics.LoginRateLimited)
	d.EmitAudit(ctx, d.Events.LoginRateLimited, false, userID, tenantID, "", d.Errors.LoginRateLimited, func() map[string]string {
		return map[string]string{
			"identifier": username,
		}
	})
	d.EmitRateLimit(ctx, "login", tenantID, func() map[string]string {
		return map[string]string{
			"identifier": username,
		}
	})
	return d.Errors.LoginRateLimited
}

// isLoginLimiterOutage reports whether a login limiter hook failed because the
// limiter backend is down and the engine is configured to fail closed, as
// opposed to the user being rate limited.
func isLoginLimiterOutage(err error, deps LoginDeps) bool {
	return deps.Errors.SystemUnavailable != nil && errors.Is(err, deps.Errors.SystemUnavailable)
}
