package goAuth

import (
	"context"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
)

// DisableAccount describes the disableaccount operation and its observable behavior.
//
// DisableAccount may return an error when input validation, dependency calls, or security checks fail.
// DisableAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DisableAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountDisabled)
	if err == nil {
		e.metricInc(MetricAccountDisabled)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "disable",
		}
	})
	return err
}

// EnableAccount describes the enableaccount operation and its observable behavior.
//
// EnableAccount may return an error when input validation, dependency calls, or security checks fail.
// EnableAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) EnableAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountActive)
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "enable",
		}
	})
	return err
}

// LockAccount describes the lockaccount operation and its observable behavior.
//
// LockAccount may return an error when input validation, dependency calls, or security checks fail.
// LockAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LockAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountLocked)
	if err == nil {
		e.metricInc(MetricAccountLocked)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "lock",
		}
	})
	return err
}

// DeleteAccount describes the deleteaccount operation and its observable behavior.
//
// DeleteAccount may return an error when input validation, dependency calls, or security checks fail.
// DeleteAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DeleteAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountDeleted)
	if err == nil {
		e.metricInc(MetricAccountDeleted)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "delete",
		}
	})
	return err
}

func (e *Engine) updateAccountStatusAndInvalidate(ctx context.Context, userID string, status AccountStatus) error {
	if e == nil || e.userProvider == nil {
		return ErrEngineNotReady
	}

	return internalflows.RunUpdateAccountStatusAndInvalidate(ctx, userID, uint8(status), internalflows.UpdateAccountStatusDeps{
		GetUserByID: func(userID string) (internalflows.AccountStatusRecord, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.AccountStatusRecord{}, err
			}
			return internalflows.AccountStatusRecord{
				Status:         uint8(user.Status),
				AccountVersion: user.AccountVersion,
				TenantID:       user.TenantID,
			}, nil
		},
		UpdateAccountStatus: func(ctx context.Context, userID string, status uint8) (internalflows.AccountStatusRecord, error) {
			user, err := e.userProvider.UpdateAccountStatus(ctx, userID, AccountStatus(status))
			if err != nil {
				return internalflows.AccountStatusRecord{}, err
			}
			return internalflows.AccountStatusRecord{
				Status:         uint8(user.Status),
				AccountVersion: user.AccountVersion,
				TenantID:       user.TenantID,
			}, nil
		},
		LogoutAllInTenant:            e.LogoutAllInTenant,
		TenantIDFromContext:          tenantIDFromContext,
		ErrEngineNotReady:            ErrEngineNotReady,
		ErrUserNotFound:              ErrUserNotFound,
		ErrAccountVersionNotAdvanced: ErrAccountVersionNotAdvanced,
		ErrUnauthorized:              ErrUnauthorized,
		ErrSessionInvalidationFailed: ErrSessionInvalidationFailed,
	})
}

func accountStatusToError(status AccountStatus) error {
	switch status {
	case AccountActive:
		return nil
	case AccountPendingVerification:
		return nil
	case AccountDisabled:
		return ErrAccountDisabled
	case AccountLocked:
		return ErrAccountLocked
	case AccountDeleted:
		return ErrAccountDeleted
	default:
		return ErrUnauthorized
	}
}

func (e *Engine) shouldRequireVerified() bool {
	return e.config.EmailVerification.Enabled && e.config.EmailVerification.RequireForLogin
}
