package flows

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// LoginResult is the flow-local login response shape.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	MFARequired  bool
	MFAType      string
	MFASession   string
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
	UserID    string
	TenantID  string
	ExpiresAt int64
	Attempts  uint16
}

// LoginMetrics carries metric IDs needed by login/mfa flows.
type LoginMetrics struct {
	LoginSuccess      int
	LoginFailure      int
	LoginRateLimited  int
	SessionCreated    int
	MFALoginRequired  int
	MFALoginSuccess   int
	MFALoginFailure   int
	MFAReplayAttempt  int
}

// LoginEvents carries audit event names used by login/mfa flows.
type LoginEvents struct {
	LoginSuccess      string
	LoginFailure      string
	LoginRateLimited  string
	MFARequired       string
	MFASuccess        string
	MFAFailure        string
	MFAAttemptsExceeded string
}

// LoginErrors carries host-level sentinel errors used by login/mfa flows.
type LoginErrors struct {
	EngineNotReady          error
	InvalidCredentials      error
	LoginRateLimited        error
	AccountUnverified       error
	DeviceBindingRejected   error
	TOTPFeatureDisabled     error
	MFALoginInvalid         error
	MFALoginExpired         error
	MFALoginAttemptsExceeded error
	MFALoginReplay          error
	MFALoginUnavailable     error
	UserNotFound            error
	BackupCodeRateLimited   error
	BackupCodeInvalid       error
	BackupCodesNotConfigured error
}

// LoginDeps captures login+mfa dependencies.
type LoginDeps struct {
	TOTPEnabled                 bool
	RequireTOTPForLogin         bool
	EnforceReplayProtection     bool
	RequireVerified             bool
	PendingVerificationStatus   uint8
	PasswordUpgradeOnLogin      bool
	MFALoginMaxAttempts         int
	MFALoginChallengeTTL        time.Duration
	DeviceBindingEnabled        bool
	EnforceIPBinding            bool
	EnforceUserAgentBinding     bool

	TenantIDFromContext         func(context.Context) string
	ClientIPFromContext         func(context.Context) string
	UserAgentFromContext        func(context.Context) string
	Now                         func() time.Time
	AccountStatusError          func(status uint8) error

	CheckLoginRate              func(context.Context, string, string) error
	IncrementLoginRate          func(context.Context, string, string) error
	ResetLoginRate              func(context.Context, string, string) error

	GetUserByIdentifier         func(string) (LoginUserRecord, error)
	GetUserByID                 func(string) (LoginUserRecord, error)
	UpdatePasswordHash          func(string, string) error
	GetTOTPSecret               func(context.Context, string) (*LoginTOTPRecord, error)
	UpdateTOTPLastUsedCounter   func(context.Context, string, int64) error

	VerifyPassword              func(string, string) (bool, error)
	PasswordNeedsUpgrade        func(string) (bool, error)
	HashPassword                func(string) (string, error)
	VerifyTOTPCode              func([]byte, string, time.Time) (bool, int64, error)
	VerifyBackupCodeInTenant    func(context.Context, string, string, string) error

	GetMFAChallenge             func(context.Context, string) (*MFALoginChallengeRecord, error)
	SaveMFAChallenge            func(context.Context, string, *MFALoginChallengeRecord, time.Duration) error
	DeleteMFAChallenge          func(context.Context, string) (bool, error)
	RecordMFAFailure            func(context.Context, string, int) (bool, error)
	MapMFAStoreError            func(error) error

	CreateMFALoginChallenge     func(context.Context, string, string) (string, error)
	IssueLoginSessionTokens     func(context.Context, string, LoginUserRecord, string) (string, string, error)
	EnforceSessionHardening     func(context.Context, string, string) error

	GetRoleMask                 func(string) (interface{}, bool)
	NewSessionID                func() (string, error)
	NewRefreshSecret            func() ([32]byte, error)
	HashRefreshSecret           func([32]byte) [32]byte
	EncodeRefreshToken          func(string, [32]byte) (string, error)
	HashBindingValue            func(string) [32]byte
	SessionLifetime             func() time.Duration
	SaveSession                 func(context.Context, *session.Session, time.Duration) error
	IssueAccessToken            func(*session.Session) (string, error)

	MetricInc                   func(int)
	EmitAudit                   func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit               func(context.Context, string, string, func() map[string]string)
	Warn                        func(string, ...any)

	Metrics                     LoginMetrics
	Events                      LoginEvents
	Errors                      LoginErrors
}

// RunLoginWithResult executes the login flow and either issues tokens or returns MFA challenge details.
func RunLoginWithResult(ctx context.Context, username, password string, deps LoginDeps) (*LoginResult, error) {
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
	if deps.AccountStatusError == nil ||
		deps.GetUserByIdentifier == nil ||
		deps.VerifyPassword == nil ||
		deps.IssueLoginSessionTokens == nil ||
		deps.EnforceSessionHardening == nil {
		return nil, deps.Errors.EngineNotReady
	}

	ip := deps.ClientIPFromContext(ctx)
	tenantID := deps.TenantIDFromContext(ctx)

	if deps.CheckLoginRate != nil {
		if err := deps.CheckLoginRate(ctx, username, ip); err != nil {
			deps.MetricInc(deps.Metrics.LoginRateLimited)
			deps.EmitAudit(ctx, deps.Events.LoginRateLimited, false, "", tenantID, "", deps.Errors.LoginRateLimited, func() map[string]string {
				return map[string]string{
					"identifier": username,
				}
			})
			deps.EmitRateLimit(ctx, "login", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": username,
				}
			})
			return nil, deps.Errors.LoginRateLimited
		}
	}

	if password == "" {
		if deps.IncrementLoginRate != nil {
			if err := deps.IncrementLoginRate(ctx, username, ip); err != nil {
				deps.MetricInc(deps.Metrics.LoginRateLimited)
				deps.EmitAudit(ctx, deps.Events.LoginRateLimited, false, "", tenantID, "", deps.Errors.LoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				deps.EmitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return nil, deps.Errors.LoginRateLimited
			}
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

	user, err := deps.GetUserByIdentifier(username)
	if err != nil {
		if deps.IncrementLoginRate != nil {
			if err := deps.IncrementLoginRate(ctx, username, ip); err != nil {
				deps.MetricInc(deps.Metrics.LoginRateLimited)
				deps.EmitAudit(ctx, deps.Events.LoginRateLimited, false, "", tenantID, "", deps.Errors.LoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				deps.EmitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return nil, deps.Errors.LoginRateLimited
			}
		}
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, "", tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "user_not_found",
			}
		})
		return nil, deps.Errors.InvalidCredentials
	}

	ok, err := deps.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		if deps.IncrementLoginRate != nil {
			if err := deps.IncrementLoginRate(ctx, username, ip); err != nil {
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
				return nil, deps.Errors.LoginRateLimited
			}
		}
		deps.MetricInc(deps.Metrics.LoginFailure)
		deps.EmitAudit(ctx, deps.Events.LoginFailure, false, user.UserID, tenantID, "", deps.Errors.InvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "password_mismatch",
			}
		})
		return nil, deps.Errors.InvalidCredentials
	}

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

	if deps.PasswordUpgradeOnLogin {
		if needsUpgrade, err := deps.PasswordNeedsUpgrade(user.PasswordHash); err == nil && needsUpgrade {
			if upgradedHash, err := deps.HashPassword(password); err == nil {
				if err := deps.UpdatePasswordHash(user.UserID, upgradedHash); err != nil {
					deps.Warn("goAuth: password hash upgrade update failed")
				}
			} else {
				deps.Warn("goAuth: password hash upgrade generation failed")
			}
		}
	}
	password = ""

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

	if deps.TOTPEnabled && deps.RequireTOTPForLogin {
		record, err := deps.GetTOTPSecret(ctx, user.UserID)
		if err != nil {
			deps.MetricInc(deps.Metrics.MFALoginFailure)
			deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, tenantID, "", deps.Errors.MFALoginUnavailable, nil)
			return nil, deps.Errors.MFALoginUnavailable
		}
		if record != nil && record.Enabled && len(record.Secret) > 0 {
			challengeID, err := deps.CreateMFALoginChallenge(ctx, user.UserID, tenantID)
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
				MFAType:     "totp",
				MFASession:  challengeID,
			}, nil
		}
	}

	access, refresh, err := deps.IssueLoginSessionTokens(ctx, username, user, tenantID)
	if err != nil {
		return nil, err
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

	if !deps.TOTPEnabled || !deps.RequireTOTPForLogin {
		return nil, deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetMFAChallenge == nil ||
		deps.DeleteMFAChallenge == nil ||
		deps.RecordMFAFailure == nil ||
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

	user, err := deps.GetUserByID(record.UserID)
	if err != nil {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, record.UserID, record.TenantID, "", deps.Errors.UserNotFound, nil)
		return nil, deps.Errors.UserNotFound
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

	totpRecord, err := deps.GetTOTPSecret(ctx, user.UserID)
	if err != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginUnavailable, nil)
		return nil, deps.Errors.MFALoginUnavailable
	}
	if totpRecord == nil || !totpRecord.Enabled || len(totpRecord.Secret) == 0 {
		_, _ = deps.DeleteMFAChallenge(ctx, challengeID)
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "totp_disabled_or_missing",
			}
		})
		return nil, deps.Errors.MFALoginInvalid
	}
	if code == "" {
		return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginInvalid, deps)
	}

	switch strings.ToLower(strings.TrimSpace(mfaType)) {
	case "", "totp":
		ok, counter, verr := deps.VerifyTOTPCode(totpRecord.Secret, code, deps.Now())
		if verr != nil || !ok {
			return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginInvalid, deps)
		}

		if deps.EnforceReplayProtection {
			if counter <= totpRecord.LastUsedCounter {
				deps.MetricInc(deps.Metrics.MFAReplayAttempt)
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginReplay, nil)
				return nil, deps.Errors.MFALoginReplay
			}
			if err := deps.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
				deps.MetricInc(deps.Metrics.MFALoginFailure)
				deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", deps.Errors.MFALoginUnavailable, nil)
				return nil, deps.Errors.MFALoginUnavailable
			}
		}
	case "backup":
		if berr := deps.VerifyBackupCodeInTenant(ctx, record.TenantID, user.UserID, code); berr != nil {
			switch {
			case errors.Is(berr, deps.Errors.BackupCodeRateLimited):
				return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginAttemptsExceeded, deps)
			case errors.Is(berr, deps.Errors.BackupCodeInvalid), errors.Is(berr, deps.Errors.BackupCodesNotConfigured):
				return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginInvalid, deps)
			default:
				return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginUnavailable, deps)
			}
		}
	default:
		return runFailLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, deps.Errors.MFALoginInvalid, deps)
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
	access, refresh, err := deps.IssueLoginSessionTokens(ctx, identifier, user, record.TenantID)
	if err != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, user.UserID, record.TenantID, "", err, nil)
		return nil, err
	}

	deps.MetricInc(deps.Metrics.MFALoginSuccess)
	deps.EmitAudit(ctx, deps.Events.MFASuccess, true, user.UserID, record.TenantID, "", nil, nil)
	return &LoginResult{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func runFailLoginMFAAttempt(
	ctx context.Context,
	challengeID string,
	userID string,
	tenantID string,
	cause error,
	deps LoginDeps,
) (*LoginResult, error) {
	exceeded, recErr := deps.RecordMFAFailure(ctx, challengeID, deps.MFALoginMaxAttempts)
	if recErr != nil {
		deps.MetricInc(deps.Metrics.MFALoginFailure)
		mapped := deps.MapMFAStoreError(recErr)
		deps.EmitAudit(ctx, deps.Events.MFAFailure, false, userID, tenantID, "", mapped, nil)
		return nil, mapped
	}
	if exceeded {
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
func RunCreateMFALoginChallenge(ctx context.Context, userID, tenantID string, deps LoginDeps) (string, error) {
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
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: deps.Now().Add(ttl).Unix(),
		Attempts:  0,
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

	ip := deps.ClientIPFromContext(ctx)
	mask, ok := deps.GetRoleMask(user.Role)
	if !ok {
		if deps.IncrementLoginRate != nil {
			if err := deps.IncrementLoginRate(ctx, username, ip); err != nil {
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
	sessionLifetime := deps.SessionLifetime()
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
		ExpiresAt:         now.Add(sessionLifetime).Unix(),
	}

	if err := deps.SaveSession(ctx, sess, sessionLifetime); err != nil {
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
		if err := deps.ResetLoginRate(ctx, username, ip); err != nil {
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
		return map[string]string{
			"identifier": username,
		}
	})

	return access, refresh, nil
}
