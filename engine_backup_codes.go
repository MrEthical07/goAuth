package goAuth

import (
	"context"
	"errors"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
)

// GenerateBackupCodes describes the generatebackupcodes operation and its observable behavior.
//
// GenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// GenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	return internalflows.RunGenerateBackupCodes(ctx, userID, e.backupCodeFlowDeps())
}

// RegenerateBackupCodes describes the regeneratebackupcodes operation and its observable behavior.
//
// RegenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// RegenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	return internalflows.RunRegenerateBackupCodes(ctx, userID, totpCode, e.backupCodeFlowDeps())
}

// VerifyBackupCode describes the verifybackupcode operation and its observable behavior.
//
// VerifyBackupCode may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCode does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCode(ctx context.Context, userID, code string) error {
	return internalflows.RunVerifyBackupCode(ctx, userID, code, e.backupCodeFlowDeps())
}

// VerifyBackupCodeInTenant describes the verifybackupcodeintenant operation and its observable behavior.
//
// VerifyBackupCodeInTenant may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCodeInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCodeInTenant(ctx context.Context, tenantID, userID, code string) error {
	return internalflows.RunVerifyBackupCodeInTenant(ctx, tenantID, userID, code, e.backupCodeFlowDeps())
}

func (e *Engine) backupCodeFlowDeps() internalflows.BackupCodeDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.BackupCodeDeps{
		Enabled:             cfg.TOTP.Enabled,
		BackupCodeCount:     cfg.TOTP.BackupCodeCount,
		BackupCodeLength:    cfg.TOTP.BackupCodeLength,
		TenantIDFromContext: tenantIDFromContext,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		IsRateLimited: func(err error) bool {
			return errors.Is(err, limiters.ErrBackupCodeRateLimited)
		},
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit: e.emitAudit,
		Metrics: internalflows.BackupCodeMetrics{
			BackupCodeUsed:        int(MetricBackupCodeUsed),
			BackupCodeFailed:      int(MetricBackupCodeFailed),
			BackupCodeRegenerated: int(MetricBackupCodeRegenerated),
		},
		Events: internalflows.BackupCodeEvents{
			BackupCodesGenerated: auditEventBackupCodesGenerated,
			BackupCodeUsed:       auditEventBackupCodeUsed,
			BackupCodeFailed:     auditEventBackupCodeFailed,
		},
		Errors: internalflows.BackupCodeErrors{
			TOTPFeatureDisabled:                ErrTOTPFeatureDisabled,
			EngineNotReady:                     ErrEngineNotReady,
			UserNotFound:                       ErrUserNotFound,
			BackupCodeUnavailable:              ErrBackupCodeUnavailable,
			BackupCodeRegenerationRequiresTOTP: ErrBackupCodeRegenerationRequiresTOTP,
			BackupCodeInvalid:                  ErrBackupCodeInvalid,
			BackupCodeRateLimited:              ErrBackupCodeRateLimited,
		},
	}

	if e != nil && e.userProvider != nil {
		deps.GetUserByID = func(userID string) (internalflows.BackupCodeUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.BackupCodeUser{}, err
			}
			return toFlowBackupCodeUser(user), nil
		}
		deps.GetBackupCodes = func(ctx context.Context, userID string) ([]internalflows.BackupCodeRecord, error) {
			records, err := e.userProvider.GetBackupCodes(ctx, userID)
			if err != nil {
				return nil, err
			}
			return toFlowBackupCodeRecords(records), nil
		}
		deps.ReplaceBackupCodes = func(ctx context.Context, userID string, records []internalflows.BackupCodeRecord) error {
			return e.userProvider.ReplaceBackupCodes(ctx, userID, fromFlowBackupCodeRecords(records))
		}
		deps.ConsumeBackupCode = e.userProvider.ConsumeBackupCode
	}
	if e != nil {
		deps.VerifyTOTPForUser = func(ctx context.Context, user internalflows.BackupCodeUser, code string) error {
			return e.verifyTOTPForUser(ctx, fromFlowBackupCodeUser(user), code)
		}
	}
	if e != nil && e.backupLimiter != nil {
		deps.CheckLimiter = e.backupLimiter.Check
		deps.RecordLimiterFailure = e.backupLimiter.RecordFailure
		deps.ResetLimiter = e.backupLimiter.Reset
	}

	return deps
}

func toFlowBackupCodeUser(user UserRecord) internalflows.BackupCodeUser {
	return internalflows.BackupCodeUser{
		UserID:   user.UserID,
		TenantID: user.TenantID,
		Status:   uint8(user.Status),
	}
}

func fromFlowBackupCodeUser(user internalflows.BackupCodeUser) UserRecord {
	return UserRecord{
		UserID:   user.UserID,
		TenantID: user.TenantID,
		Status:   AccountStatus(user.Status),
	}
}

func toFlowBackupCodeRecords(records []BackupCodeRecord) []internalflows.BackupCodeRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]internalflows.BackupCodeRecord, 0, len(records))
	for _, record := range records {
		out = append(out, internalflows.BackupCodeRecord{
			Hash: record.Hash,
		})
	}
	return out
}

func fromFlowBackupCodeRecords(records []internalflows.BackupCodeRecord) []BackupCodeRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]BackupCodeRecord, 0, len(records))
	for _, record := range records {
		out = append(out, BackupCodeRecord{
			Hash: record.Hash,
		})
	}
	return out
}

func newBackupCode(length int) (string, error) {
	return internalflows.NewBackupCode(length, nil)
}

func formatBackupCode(code string) string {
	return internalflows.FormatBackupCode(code)
}

func canonicalizeBackupCode(code string) string {
	return internalflows.CanonicalizeBackupCode(code)
}

func backupCodeHash(userID, canonicalCode string) [32]byte {
	return internalflows.BackupCodeHash(userID, canonicalCode)
}
