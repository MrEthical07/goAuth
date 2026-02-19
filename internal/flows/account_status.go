package flows

import (
	"context"
	"errors"
)

type AccountStatusRecord struct {
	Status         uint8
	AccountVersion uint32
	TenantID       string
}

type UpdateAccountStatusDeps struct {
	GetUserByID                 func(userID string) (AccountStatusRecord, error)
	UpdateAccountStatus         func(ctx context.Context, userID string, status uint8) (AccountStatusRecord, error)
	LogoutAllInTenant           func(ctx context.Context, tenantID, userID string) error
	TenantIDFromContext         func(context.Context) string
	ErrEngineNotReady           error
	ErrUserNotFound             error
	ErrAccountVersionNotAdvanced error
	ErrUnauthorized             error
	ErrSessionInvalidationFailed error
}

func RunUpdateAccountStatusAndInvalidate(
	ctx context.Context,
	userID string,
	status uint8,
	deps UpdateAccountStatusDeps,
) error {
	if deps.GetUserByID == nil || deps.UpdateAccountStatus == nil || deps.LogoutAllInTenant == nil || deps.TenantIDFromContext == nil {
		return deps.ErrEngineNotReady
	}
	if userID == "" {
		return deps.ErrUserNotFound
	}

	current, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.ErrUserNotFound
	}

	if current.Status == status {
		return nil
	}

	updated, err := deps.UpdateAccountStatus(ctx, userID, status)
	if err != nil {
		return err
	}
	if updated.AccountVersion <= current.AccountVersion {
		return deps.ErrAccountVersionNotAdvanced
	}
	if updated.Status != status {
		return deps.ErrUnauthorized
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if updated.TenantID != "" {
		tenantID = updated.TenantID
	}

	if err := deps.LogoutAllInTenant(ctx, tenantID, userID); err != nil {
		return errors.Join(deps.ErrSessionInvalidationFailed, err)
	}

	return nil
}
