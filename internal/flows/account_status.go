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
	GetUserByID                  func(ctx context.Context, userID string) (AccountStatusRecord, error)
	UpdateAccountStatus          func(ctx context.Context, userID string, status uint8) (AccountStatusRecord, error)
	LogoutAllInTenant            func(ctx context.Context, tenantID, userID string) error
	TenantIDFromContext          func(context.Context) string
	ErrEngineNotReady            error
	ErrUserNotFound              error
	ErrAccountVersionNotAdvanced error
	ErrUnauthorized              error
	ErrSessionInvalidationFailed error

	// ActiveStatus is the one status whose transition does not end the user's
	// sessions; every other target (disabled, locked, deleted) is blocking and
	// always revokes. The zero value is the engine's active status.
	ActiveStatus uint8
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

	blocking := status != deps.ActiveStatus
	tenantOf := func(rec AccountStatusRecord) string {
		if rec.TenantID != "" {
			return rec.TenantID
		}
		return deps.TenantIDFromContext(ctx)
	}
	revoke := func(rec AccountStatusRecord) error {
		if err := deps.LogoutAllInTenant(ctx, tenantOf(rec), userID); err != nil {
			return errors.Join(deps.ErrSessionInvalidationFailed, err)
		}
		return nil
	}

	current, err := deps.GetUserByID(ctx, userID)
	if err != nil {
		return deps.ErrUserNotFound
	}

	if current.Status == status {
		if !blocking {
			return nil
		}
		// A blocking status the provider already holds: an earlier call may
		// have committed it and then failed before the sessions were revoked
		// (or the host wrote it itself). A nil return must mean the user's
		// sessions are gone, so revoking is part of every call.
		return revoke(current)
	}

	updated, err := deps.UpdateAccountStatus(ctx, userID, status)
	if err != nil {
		return err
	}
	if updated.AccountVersion <= current.AccountVersion {
		if blocking {
			// The status is committed; revoke before reporting the failure.
			_ = revoke(updated)
		}
		return deps.ErrAccountVersionNotAdvanced
	}
	if updated.Status != status {
		if blocking {
			_ = revoke(updated)
		}
		return deps.ErrUnauthorized
	}

	return revoke(updated)
}
