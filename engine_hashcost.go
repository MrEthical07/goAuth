package goAuth

import (
	"context"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
)

// padCheapRejection runs after a password verification failed against
// storedHash, and makes the rejection cost at least what verifying a hash made
// under the configured parameters costs. An unknown identifier already pays that
// (one dummy verification, made at the configured cost), but a registered
// account is verified at the cost encoded in its own hash: a hash that predates
// a parameter increase is rejected several times faster, and one that does not
// parse as Argon2 at all is rejected in microseconds, so the response time told
// the account exists.
//
// A hash that is cheaper than the configured parameters (NeedsUpgrade), or does
// not parse, is followed by one dummy verification. A hash at or above the
// configured cost already costs enough and gets none. It is only called for a
// rejection: a successful verification is never padded, and a successful login
// still upgrades the hash (UpgradeOnLogin), after which the account is no longer
// padded.
func (e *Engine) padCheapRejection(storedHash string) {
	if e == nil || e.passwordHash == nil {
		return
	}
	if needsUpgrade, err := e.passwordHash.NeedsUpgrade(storedHash); err == nil && !needsUpgrade {
		return
	}
	_, _ = e.verifyHash(internalflows.DummyTimingPassword, e.dummyTimingHash())
}

// recordOrContextTenant is the tenant an audit event names for an account: the
// record's when it carries one, otherwise the request's.
func recordOrContextTenant(ctx context.Context, recordTenant string) string {
	if recordTenant != "" {
		return recordTenant
	}
	return tenantIDFromContext(ctx)
}
