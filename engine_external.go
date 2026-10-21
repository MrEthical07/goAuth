package goAuth

import (
	"context"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
)

// verifyHash verifies password against an encoded hash. Every password check
// in the engine goes through it, which gives tests one place to count Argon2
// verifications; in production it is exactly passwordHash.Verify.
func (e *Engine) verifyHash(password, encodedHash string) (bool, error) {
	if e.verifyHashFn != nil {
		return e.verifyHashFn(password, encodedHash)
	}
	return e.passwordHash.Verify(password, encodedHash)
}

// rejectPasswordless is the guard ChangePassword and VerifyPassword run after
// resolving the account. An account created through external sign-in has no
// password: there is nothing to verify, so the call fails with
// [ErrPasswordNotSet]. A dummy verification runs first so the response takes
// as long as one that did verify, and the attempt has already been counted by
// the password-verify limiter.
func (e *Engine) rejectPasswordless(ctx context.Context, event string, user UserRecord) error {
	if user.PasswordHash != "" {
		return nil
	}
	_, _ = e.verifyHash(internalflows.DummyTimingPassword, internalflows.DummyTimingHash)
	e.emitAudit(ctx, event, false, user.UserID, user.TenantID, "", ErrPasswordNotSet, func() map[string]string {
		return map[string]string{
			"reason": "password_not_set",
		}
	})
	return ErrPasswordNotSet
}
