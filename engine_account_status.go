package goAuth

import (
	"context"
	"errors"
)

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

func (e *Engine) EnableAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountActive)
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "enable",
		}
	})
	return err
}

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
