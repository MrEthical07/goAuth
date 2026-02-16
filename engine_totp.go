package goAuth

import (
	"context"
	"errors"
	"time"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
)

// GenerateTOTPSetup describes the generatetotpsetup operation and its observable behavior.
//
// GenerateTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// GenerateTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateTOTPSetup(ctx context.Context, userID string) (*TOTPSetup, error) {
	setup, err := internalflows.RunGenerateTOTPSetup(ctx, userID, e.totpFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowTOTPSetup(setup), nil
}

// ProvisionTOTP describes the provisiontotp operation and its observable behavior.
//
// ProvisionTOTP may return an error when input validation, dependency calls, or security checks fail.
// ProvisionTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ProvisionTOTP(ctx context.Context, userID string) (*TOTPProvision, error) {
	provision, err := internalflows.RunProvisionTOTP(ctx, userID, e.totpFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowTOTPProvision(provision), nil
}

// ConfirmTOTPSetup describes the confirmtotpsetup operation and its observable behavior.
//
// ConfirmTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// ConfirmTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmTOTPSetup(ctx context.Context, userID, code string) error {
	return internalflows.RunConfirmTOTPSetup(ctx, userID, code, e.totpFlowDeps())
}

// VerifyTOTP describes the verifytotp operation and its observable behavior.
//
// VerifyTOTP may return an error when input validation, dependency calls, or security checks fail.
// VerifyTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyTOTP(ctx context.Context, userID, code string) error {
	return internalflows.RunVerifyTOTP(ctx, userID, code, e.totpFlowDeps())
}

// DisableTOTP describes the disabletotp operation and its observable behavior.
//
// DisableTOTP may return an error when input validation, dependency calls, or security checks fail.
// DisableTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DisableTOTP(ctx context.Context, userID string) error {
	return internalflows.RunDisableTOTP(ctx, userID, e.totpFlowDeps())
}

func (e *Engine) verifyTOTPForUser(ctx context.Context, user UserRecord, code string) error {
	return internalflows.RunVerifyTOTPForUser(ctx, toFlowTOTPUser(user), code, e.totpFlowDeps())
}

func (e *Engine) totpFlowDeps() internalflows.TOTPDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.TOTPDeps{
		Enabled:                 cfg.TOTP.Enabled,
		EnforceReplayProtection: cfg.TOTP.EnforceReplayProtection,
		Now:                     time.Now,
		TenantIDFromContext:     tenantIDFromContext,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		IsTOTPRateLimited: func(err error) bool {
			return errors.Is(err, limiters.ErrTOTPRateLimited)
		},
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit: e.emitAudit,
		Metrics: internalflows.TOTPMetrics{
			TOTPRequired: int(MetricTOTPRequired),
			TOTPFailure:  int(MetricTOTPFailure),
			TOTPSuccess:  int(MetricTOTPSuccess),
		},
		Events: internalflows.TOTPEvents{
			TOTPSetupRequested: auditEventTOTPSetupRequested,
			TOTPEnabled:        auditEventTOTPEnabled,
			TOTPDisabled:       auditEventTOTPDisabled,
			TOTPFailure:        auditEventTOTPFailure,
			TOTPSuccess:        auditEventTOTPSuccess,
		},
		Errors: internalflows.TOTPErrors{
			TOTPFeatureDisabled:       ErrTOTPFeatureDisabled,
			EngineNotReady:            ErrEngineNotReady,
			UserNotFound:              ErrUserNotFound,
			TOTPUnavailable:           ErrTOTPUnavailable,
			TOTPNotConfigured:         ErrTOTPNotConfigured,
			TOTPRequired:              ErrTOTPRequired,
			TOTPInvalid:               ErrTOTPInvalid,
			TOTPRateLimited:           ErrTOTPRateLimited,
			AccountVersionNotAdvanced: ErrAccountVersionNotAdvanced,
			SessionInvalidationFailed: ErrSessionInvalidationFailed,
		},
	}

	if e != nil && e.userProvider != nil {
		deps.GetUserByID = func(userID string) (internalflows.TOTPUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.TOTPUser{}, err
			}
			return toFlowTOTPUser(user), nil
		}
		deps.GetTOTPSecret = func(ctx context.Context, userID string) (*internalflows.TOTPRecord, error) {
			record, err := e.userProvider.GetTOTPSecret(ctx, userID)
			if err != nil {
				return nil, err
			}
			if record == nil {
				return nil, nil
			}
			return &internalflows.TOTPRecord{
				Secret:          record.Secret,
				Enabled:         record.Enabled,
				LastUsedCounter: record.LastUsedCounter,
			}, nil
		}
		deps.EnableTOTP = e.userProvider.EnableTOTP
		deps.DisableTOTP = e.userProvider.DisableTOTP
		deps.MarkTOTPVerified = e.userProvider.MarkTOTPVerified
		deps.UpdateTOTPLastUsedCounter = e.userProvider.UpdateTOTPLastUsedCounter
	}
	if e != nil {
		deps.LogoutAllInTenant = e.LogoutAllInTenant
	}
	if e != nil && e.totp != nil {
		deps.GenerateSecret = e.totp.GenerateSecret
		deps.ProvisionURI = e.totp.ProvisionURI
		deps.VerifyCode = e.totp.VerifyCode
	}
	if e != nil && e.totpLimiter != nil {
		deps.CheckTOTPLimiter = e.totpLimiter.Check
		deps.RecordTOTPLimiterFailure = e.totpLimiter.RecordFailure
		deps.ResetTOTPLimiter = e.totpLimiter.Reset
	}

	return deps
}

func toFlowTOTPUser(user UserRecord) internalflows.TOTPUser {
	return internalflows.TOTPUser{
		UserID:         user.UserID,
		Identifier:     user.Identifier,
		TenantID:       user.TenantID,
		Status:         uint8(user.Status),
		AccountVersion: user.AccountVersion,
	}
}

func fromFlowTOTPSetup(setup *internalflows.TOTPSetup) *TOTPSetup {
	if setup == nil {
		return nil
	}
	return &TOTPSetup{
		SecretBase32: setup.SecretBase32,
		QRCodeURL:    setup.QRCodeURL,
	}
}

func fromFlowTOTPProvision(provision *internalflows.TOTPProvision) *TOTPProvision {
	if provision == nil {
		return nil
	}
	return &TOTPProvision{
		Secret: provision.Secret,
		URI:    provision.URI,
	}
}
