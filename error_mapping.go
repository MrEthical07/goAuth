package goAuth

import (
	"context"
	"errors"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/rate"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

var publicAuthSentinels = []*AuthError{
	ErrUnauthorized,
	ErrInvalidCredentials,
	ErrUserNotFound,
	ErrLoginRateLimited,
	ErrAccountExists,
	ErrAccountCreationDisabled,
	ErrAccountCreationRateLimited,
	ErrAccountCreationUnavailable,
	ErrAccountCreationInvalid,
	ErrAccountRoleInvalid,
	ErrAccountUnverified,
	ErrAccountDisabled,
	ErrAccountLocked,
	ErrAccountDeleted,
	ErrAccountVersionNotAdvanced,
	ErrEmailVerificationDisabled,
	ErrEmailVerificationInvalid,
	ErrEmailVerificationRateLimited,
	ErrEmailVerificationUnavailable,
	ErrEmailVerificationAttempts,
	ErrPasswordResetDisabled,
	ErrPasswordResetInvalid,
	ErrPasswordResetRateLimited,
	ErrPasswordResetUnavailable,
	ErrPasswordResetAttempts,
	ErrPasswordPolicy,
	ErrPasswordReuse,
	ErrSessionCreationFailed,
	ErrSessionInvalidationFailed,
	ErrSessionLimitExceeded,
	ErrTenantSessionLimitExceeded,
	ErrDeviceBindingRejected,
	ErrTOTPFeatureDisabled,
	ErrTOTPRequired,
	ErrTOTPInvalid,
	ErrTOTPRateLimited,
	ErrTOTPNotConfigured,
	ErrTOTPUnavailable,
	ErrMFALoginRequired,
	ErrMFALoginInvalid,
	ErrMFALoginExpired,
	ErrMFALoginAttemptsExceeded,
	ErrMFALoginReplay,
	ErrMFALoginUnavailable,
	ErrBackupCodeInvalid,
	ErrBackupCodeRateLimited,
	ErrBackupCodeUnavailable,
	ErrBackupCodesNotConfigured,
	ErrBackupCodeRegenerationRequiresTOTP,
	ErrSessionNotFound,
	ErrTokenInvalid,
	ErrTokenClockSkew,
	ErrInvalidRouteMode,
	ErrStrictBackendDown,
	ErrRefreshInvalid,
	ErrRefreshReuse,
	ErrPermissionDenied,
	ErrEngineNotReady,
	ErrProviderDuplicateIdentifier,
	ErrSystemInternal,
	ErrSystemUnavailable,
}

// mapToAuthError converts any outward-facing error into a canonical AuthError.
// Unknown errors are collapsed to ErrSystemInternal.
func mapToAuthError(err error) *AuthError {
	if err == nil {
		return nil
	}
	if ae, ok := err.(*AuthError); ok {
		return ae
	}

	for _, sentinel := range publicAuthSentinels {
		if errors.Is(err, sentinel) {
			return WrapAuthError(sentinel, err)
		}
	}

	switch {
	case errors.Is(err, rate.ErrRateLimited):
		return WrapAuthError(ErrLoginRateLimited, err)
	case errors.Is(err, rate.ErrRedisUnavailable):
		return WrapAuthError(ErrSystemUnavailable, err)
	case errors.Is(err, limiters.ErrAccountRateLimited):
		return WrapAuthError(ErrAccountCreationRateLimited, err)
	case errors.Is(err, limiters.ErrAccountRedisUnavailable):
		return WrapAuthError(ErrAccountCreationUnavailable, err)
	case errors.Is(err, limiters.ErrResetRateLimited):
		return WrapAuthError(ErrPasswordResetRateLimited, err)
	case errors.Is(err, limiters.ErrResetRedisUnavailable):
		return WrapAuthError(ErrPasswordResetUnavailable, err)
	case errors.Is(err, limiters.ErrVerificationRateLimited):
		return WrapAuthError(ErrEmailVerificationRateLimited, err)
	case errors.Is(err, limiters.ErrVerificationLimiterUnavailable):
		return WrapAuthError(ErrEmailVerificationUnavailable, err)
	case errors.Is(err, limiters.ErrTOTPRateLimited):
		return WrapAuthError(ErrTOTPRateLimited, err)
	case errors.Is(err, limiters.ErrTOTPUnavailable):
		return WrapAuthError(ErrTOTPUnavailable, err)
	case errors.Is(err, limiters.ErrBackupCodeRateLimited):
		return WrapAuthError(ErrBackupCodeRateLimited, err)
	case errors.Is(err, limiters.ErrBackupCodeUnavailable):
		return WrapAuthError(ErrBackupCodeUnavailable, err)
	case errors.Is(err, limiters.ErrLockoutUnavailable):
		return WrapAuthError(ErrSystemUnavailable, err)
	case errors.Is(err, stores.ErrResetNotFound), errors.Is(err, stores.ErrResetSecretMismatch):
		return WrapAuthError(ErrPasswordResetInvalid, err)
	case errors.Is(err, stores.ErrResetAttemptsExceeded):
		return WrapAuthError(ErrPasswordResetAttempts, err)
	case errors.Is(err, stores.ErrResetRedisUnavailable):
		return WrapAuthError(ErrPasswordResetUnavailable, err)
	case errors.Is(err, stores.ErrVerificationNotFound), errors.Is(err, stores.ErrVerificationSecretMismatch):
		return WrapAuthError(ErrEmailVerificationInvalid, err)
	case errors.Is(err, stores.ErrVerificationAttemptsExceeded):
		return WrapAuthError(ErrEmailVerificationAttempts, err)
	case errors.Is(err, stores.ErrVerificationRedisUnavailable):
		return WrapAuthError(ErrEmailVerificationUnavailable, err)
	case errors.Is(err, stores.ErrMFALoginChallengeNotFound):
		return WrapAuthError(ErrMFALoginInvalid, err)
	case errors.Is(err, stores.ErrMFALoginChallengeExpired):
		return WrapAuthError(ErrMFALoginExpired, err)
	case errors.Is(err, stores.ErrMFALoginChallengeExceeded):
		return WrapAuthError(ErrMFALoginAttemptsExceeded, err)
	case errors.Is(err, stores.ErrMFALoginChallengeBackend):
		return WrapAuthError(ErrMFALoginUnavailable, err)
	case errors.Is(err, session.ErrRefreshHashMismatch):
		return WrapAuthError(ErrRefreshReuse, err)
	case errors.Is(err, session.ErrRefreshSessionNotFound), errors.Is(err, session.ErrRefreshSessionExpired), errors.Is(err, redis.Nil):
		return WrapAuthError(ErrSessionNotFound, err)
	case errors.Is(err, session.ErrRefreshSessionCorrupt):
		return WrapAuthError(ErrRefreshInvalid, err)
	case errors.Is(err, session.ErrRedisUnavailable):
		return WrapAuthError(ErrSystemUnavailable, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return WrapAuthError(ErrSystemUnavailable, err)
	default:
		return WrapAuthError(ErrSystemInternal, err)
	}
}

func mapToAuthErrorOrNil(err error) error {
	if err == nil {
		return nil
	}
	return mapToAuthError(err)
}
