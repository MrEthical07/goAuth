package goAuth

import "context"

// lockAccountFromActive is the account-status write of an automatic lockout:
// Active to Locked, and only from Active. Unlike [Engine.LockAccount], which
// an administrator calls and which locks whatever the account is, an automatic
// lockout is decided from a status read the login made earlier, so an
// administrator's disable or delete that landed since must stay in force (a
// later UnlockAccount would otherwise turn the account Active).
//
// With a provider that implements [AccountStatusCASUpdater] the write is exact.
// Without one the account is read again immediately before the write and
// skipped unless it is Active, which narrows the window to the gap between that
// read and the write but cannot close it.
//
// It reports whether this call wrote the lock. A skipped lock (false, nil)
// writes, revokes and audits nothing. The sessions are not revoked here: the
// login flow does that, once, with a retry (see revokeUserSessions).
func (e *Engine) lockAccountFromActive(ctx context.Context, recordTenant, userID string) (bool, error) {
	locked, err := e.writeLockFromActive(ctx, recordTenant, userID)
	if locked {
		e.metricInc(MetricAccountLocked)
	}
	if locked || err != nil {
		e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
			return map[string]string{
				"action": "lock",
			}
		})
	}
	return locked, err
}

func (e *Engine) writeLockFromActive(ctx context.Context, recordTenant, userID string) (bool, error) {
	if e == nil || e.userProvider == nil {
		return false, ErrEngineNotReady
	}
	if e.statusCAS != nil {
		tenant := recordTenant
		if tenant == "" {
			tenant = tenantIDFromContext(ctx)
		}
		return e.statusCAS.UpdateAccountStatusIf(ctx, tenant, userID, AccountActive, AccountLocked)
	}

	fresh, err := e.lookupUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if fresh.Status != AccountActive {
		return false, nil
	}
	if _, err := e.userProvider.UpdateAccountStatus(ctx, userID, AccountLocked); err != nil {
		return false, err
	}
	return true, nil
}
