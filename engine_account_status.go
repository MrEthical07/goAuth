package goAuth

import (
	"context"
	"errors"
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
	if e.userProvider == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}

	current, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	if current.Status == status {
		return nil
	}

	updated, err := e.userProvider.UpdateAccountStatus(ctx, userID, status)
	if err != nil {
		return err
	}
	if updated.AccountVersion <= current.AccountVersion {
		return ErrAccountVersionNotAdvanced
	}
	if updated.Status != status {
		return ErrUnauthorized
	}

	tenantID := tenantIDFromContext(ctx)
	if updated.TenantID != "" {
		tenantID = updated.TenantID
	}

	if err := e.LogoutAllInTenant(ctx, tenantID, userID); err != nil {
		return errors.Join(ErrSessionInvalidationFailed, err)
	}

	return nil
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
