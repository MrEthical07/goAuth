package goAuth

import "errors"

var (
	// ErrUnauthorized is an exported constant or variable used by the authentication engine.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrInvalidCredentials is an exported constant or variable used by the authentication engine.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotFound is an exported constant or variable used by the authentication engine.
	ErrUserNotFound = errors.New("user not found")
	// ErrLoginRateLimited is an exported constant or variable used by the authentication engine.
	ErrLoginRateLimited = errors.New("login rate limited")
	// ErrRefreshRateLimited is an exported constant or variable used by the authentication engine.
	ErrRefreshRateLimited = errors.New("refresh rate limited")
	// ErrAccountExists is an exported constant or variable used by the authentication engine.
	ErrAccountExists = errors.New("account already exists")
	// ErrAccountCreationDisabled is an exported constant or variable used by the authentication engine.
	ErrAccountCreationDisabled = errors.New("account creation disabled")
	// ErrAccountCreationRateLimited is an exported constant or variable used by the authentication engine.
	ErrAccountCreationRateLimited = errors.New("account creation rate limited")
	// ErrAccountCreationUnavailable is an exported constant or variable used by the authentication engine.
	ErrAccountCreationUnavailable = errors.New("account creation backend unavailable")
	// ErrAccountCreationInvalid is an exported constant or variable used by the authentication engine.
	ErrAccountCreationInvalid = errors.New("invalid account creation request")
	// ErrAccountRoleInvalid is an exported constant or variable used by the authentication engine.
	ErrAccountRoleInvalid = errors.New("invalid account role")
	// ErrAccountUnverified is an exported constant or variable used by the authentication engine.
	ErrAccountUnverified = errors.New("account unverified")
	// ErrAccountDisabled is an exported constant or variable used by the authentication engine.
	ErrAccountDisabled = errors.New("account disabled")
	// ErrAccountLocked is an exported constant or variable used by the authentication engine.
	ErrAccountLocked = errors.New("account locked")
	// ErrAccountDeleted is an exported constant or variable used by the authentication engine.
	ErrAccountDeleted = errors.New("account deleted")
	// ErrAccountVersionNotAdvanced is an exported constant or variable used by the authentication engine.
	ErrAccountVersionNotAdvanced = errors.New("account version not advanced on status change")
	// ErrEmailVerificationDisabled is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationDisabled = errors.New("email verification disabled")
	// ErrEmailVerificationInvalid is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationInvalid = errors.New("email verification challenge invalid")
	// ErrEmailVerificationRateLimited is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationRateLimited = errors.New("email verification rate limited")
	// ErrEmailVerificationUnavailable is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationUnavailable = errors.New("email verification backend unavailable")
	// ErrEmailVerificationAttempts is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationAttempts = errors.New("email verification attempts exceeded")
	// ErrPasswordResetDisabled is an exported constant or variable used by the authentication engine.
	ErrPasswordResetDisabled = errors.New("password reset disabled")
	// ErrPasswordResetInvalid is an exported constant or variable used by the authentication engine.
	ErrPasswordResetInvalid = errors.New("password reset challenge invalid")
	// ErrPasswordResetRateLimited is an exported constant or variable used by the authentication engine.
	ErrPasswordResetRateLimited = errors.New("password reset rate limited")
	// ErrPasswordResetUnavailable is an exported constant or variable used by the authentication engine.
	ErrPasswordResetUnavailable = errors.New("password reset backend unavailable")
	// ErrPasswordResetAttempts is an exported constant or variable used by the authentication engine.
	ErrPasswordResetAttempts = errors.New("password reset attempts exceeded")
	// ErrPasswordPolicy is an exported constant or variable used by the authentication engine.
	ErrPasswordPolicy = errors.New("password policy violation")
	// ErrPasswordReuse is an exported constant or variable used by the authentication engine.
	ErrPasswordReuse = errors.New("new password must be different from current password")
	// ErrSessionCreationFailed is an exported constant or variable used by the authentication engine.
	ErrSessionCreationFailed = errors.New("session creation failed")
	// ErrSessionInvalidationFailed is an exported constant or variable used by the authentication engine.
	ErrSessionInvalidationFailed = errors.New("session invalidation failed")
	// ErrSessionLimitExceeded is an exported constant or variable used by the authentication engine.
	ErrSessionLimitExceeded = errors.New("session limit exceeded")
	// ErrTenantSessionLimitExceeded is an exported constant or variable used by the authentication engine.
	ErrTenantSessionLimitExceeded = errors.New("tenant session limit exceeded")
	// ErrDeviceBindingRejected is an exported constant or variable used by the authentication engine.
	ErrDeviceBindingRejected = errors.New("device binding rejected")
	// ErrTOTPFeatureDisabled is an exported constant or variable used by the authentication engine.
	ErrTOTPFeatureDisabled = errors.New("totp feature disabled")
	// ErrTOTPRequired is an exported constant or variable used by the authentication engine.
	ErrTOTPRequired = errors.New("totp required")
	// ErrTOTPInvalid is an exported constant or variable used by the authentication engine.
	ErrTOTPInvalid = errors.New("invalid totp code")
	// ErrTOTPRateLimited is an exported constant or variable used by the authentication engine.
	ErrTOTPRateLimited = errors.New("totp attempts rate limited")
	// ErrTOTPNotConfigured is an exported constant or variable used by the authentication engine.
	ErrTOTPNotConfigured = errors.New("totp not configured")
	// ErrTOTPUnavailable is an exported constant or variable used by the authentication engine.
	ErrTOTPUnavailable = errors.New("totp backend unavailable")
	// ErrMFALoginRequired is an exported constant or variable used by the authentication engine.
	ErrMFALoginRequired = errors.New("mfa required")
	// ErrMFALoginInvalid is an exported constant or variable used by the authentication engine.
	ErrMFALoginInvalid = errors.New("mfa challenge invalid")
	// ErrMFALoginExpired is an exported constant or variable used by the authentication engine.
	ErrMFALoginExpired = errors.New("mfa challenge expired")
	// ErrMFALoginAttemptsExceeded is an exported constant or variable used by the authentication engine.
	ErrMFALoginAttemptsExceeded = errors.New("mfa challenge attempts exceeded")
	// ErrMFALoginReplay is an exported constant or variable used by the authentication engine.
	ErrMFALoginReplay = errors.New("mfa challenge replay detected")
	// ErrMFALoginUnavailable is an exported constant or variable used by the authentication engine.
	ErrMFALoginUnavailable = errors.New("mfa challenge backend unavailable")
	// ErrBackupCodeInvalid is an exported constant or variable used by the authentication engine.
	ErrBackupCodeInvalid = errors.New("invalid backup code")
	// ErrBackupCodeRateLimited is an exported constant or variable used by the authentication engine.
	ErrBackupCodeRateLimited = errors.New("backup code rate limited")
	// ErrBackupCodeUnavailable is an exported constant or variable used by the authentication engine.
	ErrBackupCodeUnavailable = errors.New("backup code backend unavailable")
	// ErrBackupCodesNotConfigured is an exported constant or variable used by the authentication engine.
	ErrBackupCodesNotConfigured = errors.New("backup codes not configured")
	// ErrBackupCodeRegenerationRequiresTOTP is an exported constant or variable used by the authentication engine.
	ErrBackupCodeRegenerationRequiresTOTP = errors.New("backup code regeneration requires totp verification")
	// ErrSessionNotFound is an exported constant or variable used by the authentication engine.
	ErrSessionNotFound = errors.New("session not found")
	// ErrTokenInvalid is an exported constant or variable used by the authentication engine.
	ErrTokenInvalid = errors.New("invalid token")
	// ErrTokenClockSkew is an exported constant or variable used by the authentication engine.
	ErrTokenClockSkew = errors.New("token clock skew exceeded")
	// ErrInvalidRouteMode is an exported constant or variable used by the authentication engine.
	ErrInvalidRouteMode = errors.New("invalid route validation mode")
	// ErrStrictBackendDown is an exported constant or variable used by the authentication engine.
	ErrStrictBackendDown = errors.New("strict validation backend unavailable")
	// ErrRefreshInvalid is an exported constant or variable used by the authentication engine.
	ErrRefreshInvalid = errors.New("invalid refresh token")
	// ErrRefreshReuse is an exported constant or variable used by the authentication engine.
	ErrRefreshReuse = errors.New("refresh token reuse detected")
	// ErrPermissionDenied is an exported constant or variable used by the authentication engine.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrEngineNotReady is an exported constant or variable used by the authentication engine.
	ErrEngineNotReady = errors.New("engine not initialized")
	// ErrProviderDuplicateIdentifier is an exported constant or variable used by the authentication engine.
	ErrProviderDuplicateIdentifier = errors.New("provider duplicate identifier")
)
