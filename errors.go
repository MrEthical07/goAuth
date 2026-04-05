package goAuth

// ErrorCategory classifies public authentication errors.
type ErrorCategory string

const (
	CategoryAuthAbuse      ErrorCategory = "AUTH_ABUSE"
	CategoryAuthState      ErrorCategory = "AUTH_STATE"
	CategoryAuthValidation ErrorCategory = "AUTH_VALIDATION"
	CategorySystem         ErrorCategory = "SYSTEM"
)

// AuthCode is the canonical registry key for public auth errors.
type AuthCode string

const (
	CodeAuthUnauthorized                   AuthCode = "AUTH_UNAUTHORIZED"
	CodeAuthInvalidCredentials             AuthCode = "AUTH_INVALID_CREDENTIALS"
	CodeAuthAccountNotFound                AuthCode = "AUTH_ACCOUNT_NOT_FOUND"
	CodeAuthTooManyAttempts                AuthCode = "AUTH_TOO_MANY_ATTEMPTS"
	CodeAuthLocked                         AuthCode = "AUTH_LOCKED"
	CodeAuthAccountExists                  AuthCode = "AUTH_ACCOUNT_EXISTS"
	CodeAuthAccountCreationDisabled        AuthCode = "AUTH_ACCOUNT_CREATION_DISABLED"
	CodeAuthAccountCreationLimited         AuthCode = "AUTH_ACCOUNT_CREATION_LIMITED"
	CodeSystemUnavailableAccountCreation   AuthCode = "SYSTEM_UNAVAILABLE_ACCOUNT_CREATION"
	CodeAuthAccountCreationInvalid         AuthCode = "AUTH_ACCOUNT_CREATION_INVALID"
	CodeAuthAccountRoleInvalid             AuthCode = "AUTH_ACCOUNT_ROLE_INVALID"
	CodeAuthVerificationRequired           AuthCode = "AUTH_VERIFICATION_REQUIRED"
	CodeAuthAccountDisabled                AuthCode = "AUTH_ACCOUNT_DISABLED"
	CodeAuthAccountLocked                  AuthCode = "AUTH_ACCOUNT_LOCKED"
	CodeAuthAccountDeleted                 AuthCode = "AUTH_ACCOUNT_DELETED"
	CodeSystemAccountVersionNotAdvanced    AuthCode = "SYSTEM_ACCOUNT_VERSION_NOT_ADVANCED"
	CodeAuthVerificationDisabled           AuthCode = "AUTH_VERIFICATION_DISABLED"
	CodeAuthVerificationInvalid            AuthCode = "AUTH_VERIFICATION_INVALID"
	CodeAuthVerificationExpired            AuthCode = "AUTH_VERIFICATION_EXPIRED"
	CodeAuthVerificationRequestLimited     AuthCode = "AUTH_VERIFICATION_REQUEST_LIMITED"
	CodeSystemUnavailableEmailVerification AuthCode = "SYSTEM_UNAVAILABLE_EMAIL_VERIFICATION"
	CodeAuthVerificationAttemptsExceeded   AuthCode = "AUTH_VERIFICATION_ATTEMPTS_EXCEEDED"
	CodeAuthResetDisabled                  AuthCode = "AUTH_RESET_DISABLED"
	CodeAuthResetInvalid                   AuthCode = "AUTH_RESET_INVALID"
	CodeAuthResetExpired                   AuthCode = "AUTH_RESET_EXPIRED"
	CodeAuthResetRequestLimited            AuthCode = "AUTH_RESET_REQUEST_LIMITED"
	CodeSystemUnavailablePasswordReset     AuthCode = "SYSTEM_UNAVAILABLE_PASSWORD_RESET"
	CodeAuthResetAttemptsExceeded          AuthCode = "AUTH_RESET_ATTEMPTS_EXCEEDED"
	CodeAuthPasswordPolicyViolation        AuthCode = "AUTH_PASSWORD_POLICY_VIOLATION"
	CodeAuthPasswordReuse                  AuthCode = "AUTH_PASSWORD_REUSE"
	CodeSystemSessionCreationFailed        AuthCode = "SYSTEM_SESSION_CREATION_FAILED"
	CodeSystemSessionInvalidationFailed    AuthCode = "SYSTEM_SESSION_INVALIDATION_FAILED"
	CodeAuthSessionLimitExceeded           AuthCode = "AUTH_SESSION_LIMIT_EXCEEDED"
	CodeAuthTenantSessionLimitExceeded     AuthCode = "AUTH_TENANT_SESSION_LIMIT_EXCEEDED"
	CodeAuthDeviceBindingRejected          AuthCode = "AUTH_DEVICE_BINDING_REJECTED"
	CodeAuthMFADisabled                    AuthCode = "AUTH_MFA_DISABLED"
	CodeAuthTOTPRequired                   AuthCode = "AUTH_TOTP_REQUIRED"
	CodeAuthTOTPInvalid                    AuthCode = "AUTH_TOTP_INVALID"
	CodeAuthTOTPRateLimited                AuthCode = "AUTH_TOTP_RATE_LIMITED"
	CodeAuthMFANotConfigured               AuthCode = "AUTH_MFA_NOT_CONFIGURED"
	CodeSystemUnavailableMFA               AuthCode = "SYSTEM_UNAVAILABLE_MFA"
	CodeAuthMFARequired                    AuthCode = "AUTH_MFA_REQUIRED"
	CodeAuthMFAInvalidCode                 AuthCode = "AUTH_MFA_INVALID_CODE"
	CodeAuthMFAExpired                     AuthCode = "AUTH_MFA_EXPIRED"
	CodeAuthMFAAttemptsExceeded            AuthCode = "AUTH_MFA_ATTEMPTS_EXCEEDED"
	CodeAuthMFAReplayDetected              AuthCode = "AUTH_MFA_REPLAY_DETECTED"
	CodeSystemUnavailableMFAChallenge      AuthCode = "SYSTEM_UNAVAILABLE_MFA_CHALLENGE"
	CodeAuthMFABackupInvalid               AuthCode = "AUTH_MFA_BACKUP_INVALID"
	CodeAuthMFABackupRateLimited           AuthCode = "AUTH_MFA_BACKUP_RATE_LIMITED"
	CodeSystemUnavailableMFABackup         AuthCode = "SYSTEM_UNAVAILABLE_MFA_BACKUP"
	CodeAuthMFABackupNotConfigured         AuthCode = "AUTH_MFA_BACKUP_NOT_CONFIGURED"
	CodeAuthMFABackupRegenRequiresTOTP     AuthCode = "AUTH_MFA_BACKUP_REGEN_REQUIRES_TOTP"
	CodeAuthSessionExpired                 AuthCode = "AUTH_SESSION_EXPIRED"
	CodeAuthInvalidToken                   AuthCode = "AUTH_INVALID_TOKEN"
	CodeAuthInvalidTokenClockSkew          AuthCode = "AUTH_INVALID_TOKEN_CLOCK_SKEW"
	CodeAuthInvalidRouteMode               AuthCode = "AUTH_INVALID_ROUTE_MODE"
	CodeSystemUnavailableStrictBackend     AuthCode = "SYSTEM_UNAVAILABLE_STRICT_BACKEND"
	CodeAuthRefreshInvalid                 AuthCode = "AUTH_REFRESH_INVALID"
	CodeAuthRefreshReuseDetected           AuthCode = "AUTH_REFRESH_REUSE_DETECTED"
	CodeAuthPermissionDenied               AuthCode = "AUTH_PERMISSION_DENIED"
	CodeSystemEngineNotReady               AuthCode = "SYSTEM_ENGINE_NOT_READY"
	CodeSystemProviderDuplicateIdentifier  AuthCode = "SYSTEM_PROVIDER_DUPLICATE_IDENTIFIER"
	CodeSystemInternalError                AuthCode = "SYSTEM_INTERNAL_ERROR"
	CodeSystemUnavailable                  AuthCode = "SYSTEM_UNAVAILABLE"
)

// AuthError is the canonical public error shape returned by engine entrypoints.
// It preserves errors.Is compatibility via stable error codes.
type AuthError struct {
	Category ErrorCategory
	Code     string
	Message  string
	cause    error
}

// NewAuthError creates a canonical auth error sentinel.
func NewAuthError(category ErrorCategory, code, message string) *AuthError {
	return &AuthError{Category: category, Code: code, Message: message}
}

// WrapAuthError creates a canonical auth error with an underlying cause.
func WrapAuthError(base *AuthError, cause error) *AuthError {
	if base == nil {
		return nil
	}
	return &AuthError{Category: base.Category, Code: base.Code, Message: base.Message, cause: cause}
}

func (e *AuthError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *AuthError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok || e == nil || t == nil {
		return false
	}
	return e.Code == t.Code
}

var (
	// ErrUnauthorized is an exported constant or variable used by the authentication engine.
	ErrUnauthorized = NewAuthError(CategoryAuthValidation, string(CodeAuthUnauthorized), "unauthorized")
	// ErrInvalidCredentials is an exported constant or variable used by the authentication engine.
	ErrInvalidCredentials = NewAuthError(CategoryAuthValidation, string(CodeAuthInvalidCredentials), "invalid credentials")
	// ErrUserNotFound is an exported constant or variable used by the authentication engine.
	ErrUserNotFound = NewAuthError(CategoryAuthState, string(CodeAuthAccountNotFound), "account not found")
	// ErrLoginRateLimited is an exported constant or variable used by the authentication engine.
	ErrLoginRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthTooManyAttempts), "too many attempts")
	// ErrAccountExists is an exported constant or variable used by the authentication engine.
	ErrAccountExists = NewAuthError(CategoryAuthState, string(CodeAuthAccountExists), "account already exists")
	// ErrAccountCreationDisabled is an exported constant or variable used by the authentication engine.
	ErrAccountCreationDisabled = NewAuthError(CategoryAuthState, string(CodeAuthAccountCreationDisabled), "account creation disabled")
	// ErrAccountCreationRateLimited is an exported constant or variable used by the authentication engine.
	ErrAccountCreationRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthAccountCreationLimited), "account creation rate limited")
	// ErrAccountCreationUnavailable is an exported constant or variable used by the authentication engine.
	ErrAccountCreationUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailableAccountCreation), "account creation unavailable")
	// ErrAccountCreationInvalid is an exported constant or variable used by the authentication engine.
	ErrAccountCreationInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthAccountCreationInvalid), "invalid account creation request")
	// ErrAccountRoleInvalid is an exported constant or variable used by the authentication engine.
	ErrAccountRoleInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthAccountRoleInvalid), "invalid account role")
	// ErrAccountUnverified is an exported constant or variable used by the authentication engine.
	ErrAccountUnverified = NewAuthError(CategoryAuthState, string(CodeAuthVerificationRequired), "verification required")
	// ErrAccountDisabled is an exported constant or variable used by the authentication engine.
	ErrAccountDisabled = NewAuthError(CategoryAuthState, string(CodeAuthAccountDisabled), "account disabled")
	// ErrAccountLocked is an exported constant or variable used by the authentication engine.
	ErrAccountLocked = NewAuthError(CategoryAuthState, string(CodeAuthAccountLocked), "account locked")
	// ErrAccountDeleted is an exported constant or variable used by the authentication engine.
	ErrAccountDeleted = NewAuthError(CategoryAuthState, string(CodeAuthAccountDeleted), "account deleted")
	// ErrAccountVersionNotAdvanced is an exported constant or variable used by the authentication engine.
	ErrAccountVersionNotAdvanced = NewAuthError(CategorySystem, string(CodeSystemAccountVersionNotAdvanced), "account state transition failed")
	// ErrEmailVerificationDisabled is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationDisabled = NewAuthError(CategoryAuthState, string(CodeAuthVerificationDisabled), "email verification disabled")
	// ErrEmailVerificationInvalid is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthVerificationInvalid), "verification challenge invalid")
	// ErrEmailVerificationRateLimited is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthVerificationRequestLimited), "verification requests rate limited")
	// ErrEmailVerificationUnavailable is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailableEmailVerification), "email verification unavailable")
	// ErrEmailVerificationAttempts is an exported constant or variable used by the authentication engine.
	ErrEmailVerificationAttempts = NewAuthError(CategoryAuthAbuse, string(CodeAuthVerificationAttemptsExceeded), "verification attempts exceeded")
	// ErrPasswordResetDisabled is an exported constant or variable used by the authentication engine.
	ErrPasswordResetDisabled = NewAuthError(CategoryAuthState, string(CodeAuthResetDisabled), "password reset disabled")
	// ErrPasswordResetInvalid is an exported constant or variable used by the authentication engine.
	ErrPasswordResetInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthResetInvalid), "password reset challenge invalid")
	// ErrPasswordResetRateLimited is an exported constant or variable used by the authentication engine.
	ErrPasswordResetRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthResetRequestLimited), "password reset requests rate limited")
	// ErrPasswordResetUnavailable is an exported constant or variable used by the authentication engine.
	ErrPasswordResetUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailablePasswordReset), "password reset unavailable")
	// ErrPasswordResetAttempts is an exported constant or variable used by the authentication engine.
	ErrPasswordResetAttempts = NewAuthError(CategoryAuthAbuse, string(CodeAuthResetAttemptsExceeded), "password reset attempts exceeded")
	// ErrPasswordPolicy is an exported constant or variable used by the authentication engine.
	ErrPasswordPolicy = NewAuthError(CategoryAuthValidation, string(CodeAuthPasswordPolicyViolation), "password policy violation")
	// ErrPasswordReuse is an exported constant or variable used by the authentication engine.
	ErrPasswordReuse = NewAuthError(CategoryAuthValidation, string(CodeAuthPasswordReuse), "password reuse rejected")
	// ErrSessionCreationFailed is an exported constant or variable used by the authentication engine.
	ErrSessionCreationFailed = NewAuthError(CategorySystem, string(CodeSystemSessionCreationFailed), "session creation failed")
	// ErrSessionInvalidationFailed is an exported constant or variable used by the authentication engine.
	ErrSessionInvalidationFailed = NewAuthError(CategorySystem, string(CodeSystemSessionInvalidationFailed), "session invalidation failed")
	// ErrSessionLimitExceeded is an exported constant or variable used by the authentication engine.
	ErrSessionLimitExceeded = NewAuthError(CategoryAuthAbuse, string(CodeAuthSessionLimitExceeded), "session limit exceeded")
	// ErrTenantSessionLimitExceeded is an exported constant or variable used by the authentication engine.
	ErrTenantSessionLimitExceeded = NewAuthError(CategoryAuthAbuse, string(CodeAuthTenantSessionLimitExceeded), "tenant session limit exceeded")
	// ErrDeviceBindingRejected is an exported constant or variable used by the authentication engine.
	ErrDeviceBindingRejected = NewAuthError(CategoryAuthState, string(CodeAuthDeviceBindingRejected), "device binding rejected")
	// ErrTOTPFeatureDisabled is an exported constant or variable used by the authentication engine.
	ErrTOTPFeatureDisabled = NewAuthError(CategoryAuthState, string(CodeAuthMFADisabled), "mfa disabled")
	// ErrTOTPRequired is an exported constant or variable used by the authentication engine.
	ErrTOTPRequired = NewAuthError(CategoryAuthState, string(CodeAuthTOTPRequired), "totp required")
	// ErrTOTPInvalid is an exported constant or variable used by the authentication engine.
	ErrTOTPInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthTOTPInvalid), "invalid totp code")
	// ErrTOTPRateLimited is an exported constant or variable used by the authentication engine.
	ErrTOTPRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthTOTPRateLimited), "totp attempts rate limited")
	// ErrTOTPNotConfigured is an exported constant or variable used by the authentication engine.
	ErrTOTPNotConfigured = NewAuthError(CategoryAuthState, string(CodeAuthMFANotConfigured), "totp not configured")
	// ErrTOTPUnavailable is an exported constant or variable used by the authentication engine.
	ErrTOTPUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailableMFA), "totp unavailable")
	// ErrMFALoginRequired is an exported constant or variable used by the authentication engine.
	ErrMFALoginRequired = NewAuthError(CategoryAuthState, string(CodeAuthMFARequired), "mfa required")
	// ErrMFALoginInvalid is an exported constant or variable used by the authentication engine.
	ErrMFALoginInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthMFAInvalidCode), "mfa code invalid")
	// ErrMFALoginExpired is an exported constant or variable used by the authentication engine.
	ErrMFALoginExpired = NewAuthError(CategoryAuthState, string(CodeAuthMFAExpired), "mfa challenge expired")
	// ErrMFALoginAttemptsExceeded is an exported constant or variable used by the authentication engine.
	ErrMFALoginAttemptsExceeded = NewAuthError(CategoryAuthAbuse, string(CodeAuthMFAAttemptsExceeded), "mfa attempts exceeded")
	// ErrMFALoginReplay is an exported constant or variable used by the authentication engine.
	ErrMFALoginReplay = NewAuthError(CategoryAuthAbuse, string(CodeAuthMFAReplayDetected), "mfa replay detected")
	// ErrMFALoginUnavailable is an exported constant or variable used by the authentication engine.
	ErrMFALoginUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailableMFAChallenge), "mfa challenge unavailable")
	// ErrBackupCodeInvalid is an exported constant or variable used by the authentication engine.
	ErrBackupCodeInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthMFABackupInvalid), "backup code invalid")
	// ErrBackupCodeRateLimited is an exported constant or variable used by the authentication engine.
	ErrBackupCodeRateLimited = NewAuthError(CategoryAuthAbuse, string(CodeAuthMFABackupRateLimited), "backup code attempts rate limited")
	// ErrBackupCodeUnavailable is an exported constant or variable used by the authentication engine.
	ErrBackupCodeUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailableMFABackup), "backup code unavailable")
	// ErrBackupCodesNotConfigured is an exported constant or variable used by the authentication engine.
	ErrBackupCodesNotConfigured = NewAuthError(CategoryAuthState, string(CodeAuthMFABackupNotConfigured), "backup codes not configured")
	// ErrBackupCodeRegenerationRequiresTOTP is an exported constant or variable used by the authentication engine.
	ErrBackupCodeRegenerationRequiresTOTP = NewAuthError(CategoryAuthState, string(CodeAuthMFABackupRegenRequiresTOTP), "backup code regeneration requires totp")
	// ErrSessionNotFound is an exported constant or variable used by the authentication engine.
	ErrSessionNotFound = NewAuthError(CategoryAuthState, string(CodeAuthSessionExpired), "session not found or expired")
	// ErrTokenInvalid is an exported constant or variable used by the authentication engine.
	ErrTokenInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthInvalidToken), "invalid token")
	// ErrTokenClockSkew is an exported constant or variable used by the authentication engine.
	ErrTokenClockSkew = NewAuthError(CategoryAuthValidation, string(CodeAuthInvalidTokenClockSkew), "token clock skew exceeded")
	// ErrInvalidRouteMode is an exported constant or variable used by the authentication engine.
	ErrInvalidRouteMode = NewAuthError(CategoryAuthValidation, string(CodeAuthInvalidRouteMode), "invalid route validation mode")
	// ErrStrictBackendDown is an exported constant or variable used by the authentication engine.
	ErrStrictBackendDown = NewAuthError(CategorySystem, string(CodeSystemUnavailableStrictBackend), "strict validation backend unavailable")
	// ErrRefreshInvalid is an exported constant or variable used by the authentication engine.
	ErrRefreshInvalid = NewAuthError(CategoryAuthValidation, string(CodeAuthRefreshInvalid), "invalid refresh token")
	// ErrRefreshReuse is an exported constant or variable used by the authentication engine.
	ErrRefreshReuse = NewAuthError(CategoryAuthAbuse, string(CodeAuthRefreshReuseDetected), "refresh token reuse detected")
	// ErrPermissionDenied is an exported constant or variable used by the authentication engine.
	ErrPermissionDenied = NewAuthError(CategoryAuthState, string(CodeAuthPermissionDenied), "permission denied")
	// ErrEngineNotReady is an exported constant or variable used by the authentication engine.
	ErrEngineNotReady = NewAuthError(CategorySystem, string(CodeSystemEngineNotReady), "engine not initialized")
	// ErrProviderDuplicateIdentifier is an exported constant or variable used by the authentication engine.
	ErrProviderDuplicateIdentifier = NewAuthError(CategorySystem, string(CodeSystemProviderDuplicateIdentifier), "provider duplicate identifier")
	// ErrSystemInternal is a canonical fallback for unexpected internal failures.
	ErrSystemInternal = NewAuthError(CategorySystem, string(CodeSystemInternalError), "internal error")
	// ErrSystemUnavailable is a canonical fallback for dependency or availability failures.
	ErrSystemUnavailable = NewAuthError(CategorySystem, string(CodeSystemUnavailable), "service unavailable")
)
