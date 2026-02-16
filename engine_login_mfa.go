package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/stores"
)

// LoginWithResult describes the loginwithresult operation and its observable behavior.
//
// LoginWithResult may return an error when input validation, dependency calls, or security checks fail.
// LoginWithResult does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LoginWithResult(ctx context.Context, username, password string) (*LoginResult, error) {
	result, err := internalflows.RunLoginWithResult(ctx, username, password, e.loginFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowLoginResult(result), nil
}

// ConfirmLoginMFA describes the confirmloginmfa operation and its observable behavior.
//
// ConfirmLoginMFA may return an error when input validation, dependency calls, or security checks fail.
// ConfirmLoginMFA does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmLoginMFA(ctx context.Context, challengeID, code string) (*LoginResult, error) {
	return e.ConfirmLoginMFAWithType(ctx, challengeID, code, "totp")
}

// ConfirmLoginMFAWithType describes the confirmloginmfawithtype operation and its observable behavior.
//
// ConfirmLoginMFAWithType may return an error when input validation, dependency calls, or security checks fail.
// ConfirmLoginMFAWithType does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmLoginMFAWithType(ctx context.Context, challengeID, code, mfaType string) (*LoginResult, error) {
	result, err := internalflows.RunConfirmLoginMFAWithType(ctx, challengeID, code, mfaType, e.loginFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowLoginResult(result), nil
}

func (e *Engine) loginWithResultInternal(ctx context.Context, username, password string) (*LoginResult, error) {
	return e.LoginWithResult(ctx, username, password)
}

func (e *Engine) createMFALoginChallenge(ctx context.Context, userID, tenantID string) (string, error) {
	return internalflows.RunCreateMFALoginChallenge(ctx, userID, tenantID, e.loginFlowDeps())
}

func (e *Engine) issueLoginSessionTokensForResult(
	ctx context.Context,
	username string,
	user UserRecord,
	tenantID string,
) (string, string, error) {
	return internalflows.RunIssueLoginSessionTokens(ctx, username, toFlowLoginUser(user), tenantID, e.loginFlowDeps())
}

func (e *Engine) loginFlowDeps() internalflows.LoginDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.LoginDeps{
		TOTPEnabled:               cfg.TOTP.Enabled,
		RequireTOTPForLogin:       cfg.TOTP.RequireForLogin,
		EnforceReplayProtection:   cfg.TOTP.EnforceReplayProtection,
		RequireVerified:           e != nil && e.shouldRequireVerified(),
		PendingVerificationStatus: uint8(AccountPendingVerification),
		PasswordUpgradeOnLogin:    cfg.Password.UpgradeOnLogin,
		MFALoginMaxAttempts:       cfg.TOTP.MFALoginMaxAttempts,
		MFALoginChallengeTTL:      cfg.TOTP.MFALoginChallengeTTL,
		DeviceBindingEnabled:      cfg.DeviceBinding.Enabled,
		EnforceIPBinding:          cfg.DeviceBinding.EnforceIPBinding,
		EnforceUserAgentBinding:   cfg.DeviceBinding.EnforceUserAgentBinding,
		TenantIDFromContext:       tenantIDFromContext,
		ClientIPFromContext:       clientIPFromContext,
		UserAgentFromContext:      userAgentFromContext,
		Now:                       time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MetricInc:   func(id int) { e.metricInc(MetricID(id)) },
		EmitAudit:   e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Warn:        e.warn,
		Errors: internalflows.LoginErrors{
			EngineNotReady:            ErrEngineNotReady,
			InvalidCredentials:        ErrInvalidCredentials,
			LoginRateLimited:          ErrLoginRateLimited,
			AccountUnverified:         ErrAccountUnverified,
			DeviceBindingRejected:     ErrDeviceBindingRejected,
			TOTPFeatureDisabled:       ErrTOTPFeatureDisabled,
			MFALoginInvalid:           ErrMFALoginInvalid,
			MFALoginExpired:           ErrMFALoginExpired,
			MFALoginAttemptsExceeded:  ErrMFALoginAttemptsExceeded,
			MFALoginReplay:            ErrMFALoginReplay,
			MFALoginUnavailable:       ErrMFALoginUnavailable,
			UserNotFound:              ErrUserNotFound,
			BackupCodeRateLimited:     ErrBackupCodeRateLimited,
			BackupCodeInvalid:         ErrBackupCodeInvalid,
			BackupCodesNotConfigured:  ErrBackupCodesNotConfigured,
		},
		Metrics: internalflows.LoginMetrics{
			LoginSuccess:       int(MetricLoginSuccess),
			LoginFailure:       int(MetricLoginFailure),
			LoginRateLimited:   int(MetricLoginRateLimited),
			SessionCreated:     int(MetricSessionCreated),
			MFALoginRequired:   int(MetricMFALoginRequired),
			MFALoginSuccess:    int(MetricMFALoginSuccess),
			MFALoginFailure:    int(MetricMFALoginFailure),
			MFAReplayAttempt:   int(MetricMFAReplayAttempt),
		},
		Events: internalflows.LoginEvents{
			LoginSuccess:        auditEventLoginSuccess,
			LoginFailure:        auditEventLoginFailure,
			LoginRateLimited:    auditEventLoginRateLimited,
			MFARequired:         auditEventMFARequired,
			MFASuccess:          auditEventMFASuccess,
			MFAFailure:          auditEventMFAFailure,
			MFAAttemptsExceeded: auditEventMFAAttemptsExceeded,
		},
	}

	if e != nil && e.rateLimiter != nil {
		deps.CheckLoginRate = e.rateLimiter.CheckLogin
		deps.IncrementLoginRate = e.rateLimiter.IncrementLogin
		deps.ResetLoginRate = e.rateLimiter.ResetLogin
	}
	if e != nil && e.userProvider != nil {
		deps.GetUserByIdentifier = func(identifier string) (internalflows.LoginUserRecord, error) {
			user, err := e.userProvider.GetUserByIdentifier(identifier)
			if err != nil {
				return internalflows.LoginUserRecord{}, err
			}
			return toFlowLoginUser(user), nil
		}
		deps.GetUserByID = func(userID string) (internalflows.LoginUserRecord, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.LoginUserRecord{}, err
			}
			return toFlowLoginUser(user), nil
		}
		deps.UpdatePasswordHash = e.userProvider.UpdatePasswordHash
		deps.GetTOTPSecret = func(ctx context.Context, userID string) (*internalflows.LoginTOTPRecord, error) {
			record, err := e.userProvider.GetTOTPSecret(ctx, userID)
			if err != nil {
				return nil, err
			}
			if record == nil {
				return nil, nil
			}
			return &internalflows.LoginTOTPRecord{
				Secret:          record.Secret,
				Enabled:         record.Enabled,
				LastUsedCounter: record.LastUsedCounter,
			}, nil
		}
		deps.UpdateTOTPLastUsedCounter = e.userProvider.UpdateTOTPLastUsedCounter
	}
	if e != nil && e.passwordHash != nil {
		deps.VerifyPassword = e.passwordHash.Verify
		deps.PasswordNeedsUpgrade = e.passwordHash.NeedsUpgrade
		deps.HashPassword = e.passwordHash.Hash
	}
	if e != nil && e.totp != nil {
		deps.VerifyTOTPCode = e.totp.VerifyCode
	}
	if e != nil {
		deps.VerifyBackupCodeInTenant = e.VerifyBackupCodeInTenant
		deps.CreateMFALoginChallenge = e.createMFALoginChallenge
		deps.IssueLoginSessionTokens = func(ctx context.Context, username string, user internalflows.LoginUserRecord, tenantID string) (string, string, error) {
			return e.issueLoginSessionTokensForResult(ctx, username, fromFlowLoginUser(user), tenantID)
		}
		deps.EnforceSessionHardening = e.enforceSessionHardeningOnLogin
	}
	if e != nil && e.mfaLoginStore != nil {
		deps.GetMFAChallenge = func(ctx context.Context, challengeID string) (*internalflows.MFALoginChallengeRecord, error) {
			record, err := e.mfaLoginStore.Get(ctx, challengeID)
			if err != nil {
				return nil, err
			}
			return &internalflows.MFALoginChallengeRecord{
				UserID:    record.UserID,
				TenantID:  record.TenantID,
				ExpiresAt: record.ExpiresAt,
				Attempts:  record.Attempts,
			}, nil
		}
		deps.SaveMFAChallenge = func(ctx context.Context, challengeID string, record *internalflows.MFALoginChallengeRecord, ttl time.Duration) error {
			return e.mfaLoginStore.Save(ctx, challengeID, &stores.MFALoginChallenge{
				UserID:    record.UserID,
				TenantID:  record.TenantID,
				ExpiresAt: record.ExpiresAt,
				Attempts:  record.Attempts,
			}, ttl)
		}
		deps.DeleteMFAChallenge = e.mfaLoginStore.Delete
		deps.RecordMFAFailure = e.mfaLoginStore.RecordFailure
	}
	deps.MapMFAStoreError = mapMFALoginStoreError
	if e != nil && e.roleManager != nil {
		deps.GetRoleMask = e.roleManager.GetMask
	}
	deps.NewSessionID = func() (string, error) {
		sid, err := internal.NewSessionID()
		if err != nil {
			return "", err
		}
		return sid.String(), nil
	}
	deps.NewRefreshSecret = internal.NewRefreshSecret
	deps.HashRefreshSecret = internal.HashRefreshSecret
	deps.EncodeRefreshToken = internal.EncodeRefreshToken
	deps.HashBindingValue = internal.HashBindingValue
	if e != nil {
		deps.SessionLifetime = e.sessionLifetime
		deps.IssueAccessToken = e.issueAccessToken
	}
	if e != nil && e.sessionStore != nil {
		deps.SaveSession = e.sessionStore.Save
	}

	return deps
}

func toFlowLoginUser(user UserRecord) internalflows.LoginUserRecord {
	return internalflows.LoginUserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Role:              user.Role,
		Status:            uint8(user.Status),
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowLoginUser(user internalflows.LoginUserRecord) UserRecord {
	return UserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Role:              user.Role,
		Status:            AccountStatus(user.Status),
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowLoginResult(result *internalflows.LoginResult) *LoginResult {
	if result == nil {
		return nil
	}
	return &LoginResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		MFARequired:  result.MFARequired,
		MFAType:      result.MFAType,
		MFASession:   result.MFASession,
	}
}

func mapMFALoginStoreError(err error) error {
	switch {
	case errors.Is(err, stores.ErrMFALoginChallengeNotFound):
		return ErrMFALoginInvalid
	case errors.Is(err, stores.ErrMFALoginChallengeExpired):
		return ErrMFALoginExpired
	case errors.Is(err, stores.ErrMFALoginChallengeExceeded):
		return ErrMFALoginAttemptsExceeded
	case errors.Is(err, stores.ErrMFALoginChallengeBackend):
		return ErrMFALoginUnavailable
	default:
		return ErrMFALoginUnavailable
	}
}
