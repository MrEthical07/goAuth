# Error Model

goAuth exposes one public error contract for all exported `Engine` methods.

## Boundary Contract

- Every exported `Engine` method returns either `nil` or `*AuthError`.
- Internal and wrapped failures are normalized at the engine boundary via `mapToAuthError` in `error_mapping.go`.
- Existing `*AuthError` values are preserved.
- Known internal/store/limiter/session errors are mapped to stable exported sentinels.
- Unknown errors are collapsed to `ErrSystemInternal` (`SYSTEM_INTERNAL_ERROR`).
- Availability, backend, context cancellation, and timeout failures are mapped to `ErrSystemUnavailable` (`SYSTEM_UNAVAILABLE`) or a domain-specific unavailable sentinel.
- Sentinel matching remains stable through wrapping using `errors.Is`.

## Enforcement

The boundary contract is enforced in CI by dedicated tests:

- `engine_error_boundary_static_test.go`
    - Parses `engine.go` and fails if any exported `Engine` method returning `error` is added without audit coverage.
    - Fails if a boundary return path emits raw `err` (or any non-mapped error expression) instead of `mapToAuthError` / `mapToAuthErrorOrNil` or a verified safe delegate.
    - Audits selected outward flow entry files (`internal/flows/login.go`, `internal/flows/password_reset.go`, `internal/flows/email_verification.go`, `internal/flows/account.go`) and fails on forbidden ad-hoc constructors (`errors.New`, `fmt.Errorf`) or increased raw passthrough budget.
- `engine_error_boundary_runtime_test.go`
    - Executes negative-path scenarios across auth, MFA, token, reset, and system failures.
    - Asserts public failures always satisfy `errors.As(err, *AuthError)` and keep sentinel compatibility via `errors.Is`.

Any guardrail failure is a hard CI failure. There are no silent bypass paths for public boundary errors.

## `AuthError` Shape

| Field | Type | Description |
|-------|------|-------------|
| `Category` | `ErrorCategory` | Top-level classification (`AUTH_ABUSE`, `AUTH_STATE`, `AUTH_VALIDATION`, `SYSTEM`) |
| `Code` | `string` | Stable machine-readable error code |
| `Message` | `string` | Stable human-readable default message |
| `cause` | `error` | Optional wrapped internal cause (`Unwrap`) |

## Categories

| Constant | Wire Value | Use |
|----------|------------|-----|
| `CategoryAuthAbuse` | `AUTH_ABUSE` | Abuse controls, rate limits, replay detection, attempt ceilings |
| `CategoryAuthState` | `AUTH_STATE` | Account/session/MFA state transitions and policy gates |
| `CategoryAuthValidation` | `AUTH_VALIDATION` | Invalid credentials, malformed tokens/challenges, policy validation failures |
| `CategorySystem` | `SYSTEM` | Engine readiness, dependency outages, internal invariants, internal fallback |

## Canonical `AuthCode` Registry

| AuthCode Constant | Code |
|-------------------|------|
| `CodeAuthUnauthorized` | `AUTH_UNAUTHORIZED` |
| `CodeAuthInvalidCredentials` | `AUTH_INVALID_CREDENTIALS` |
| `CodeAuthAccountNotFound` | `AUTH_ACCOUNT_NOT_FOUND` |
| `CodeAuthTooManyAttempts` | `AUTH_TOO_MANY_ATTEMPTS` |
| `CodeAuthLocked` | `AUTH_LOCKED` |
| `CodeAuthAccountExists` | `AUTH_ACCOUNT_EXISTS` |
| `CodeAuthAccountCreationDisabled` | `AUTH_ACCOUNT_CREATION_DISABLED` |
| `CodeAuthAccountCreationLimited` | `AUTH_ACCOUNT_CREATION_LIMITED` |
| `CodeSystemUnavailableAccountCreation` | `SYSTEM_UNAVAILABLE_ACCOUNT_CREATION` |
| `CodeAuthAccountCreationInvalid` | `AUTH_ACCOUNT_CREATION_INVALID` |
| `CodeAuthAccountRoleInvalid` | `AUTH_ACCOUNT_ROLE_INVALID` |
| `CodeAuthVerificationRequired` | `AUTH_VERIFICATION_REQUIRED` |
| `CodeAuthAccountDisabled` | `AUTH_ACCOUNT_DISABLED` |
| `CodeAuthAccountLocked` | `AUTH_ACCOUNT_LOCKED` |
| `CodeAuthAccountDeleted` | `AUTH_ACCOUNT_DELETED` |
| `CodeSystemAccountVersionNotAdvanced` | `SYSTEM_ACCOUNT_VERSION_NOT_ADVANCED` |
| `CodeAuthVerificationDisabled` | `AUTH_VERIFICATION_DISABLED` |
| `CodeAuthVerificationInvalid` | `AUTH_VERIFICATION_INVALID` |
| `CodeAuthVerificationExpired` | `AUTH_VERIFICATION_EXPIRED` |
| `CodeAuthVerificationRequestLimited` | `AUTH_VERIFICATION_REQUEST_LIMITED` |
| `CodeSystemUnavailableEmailVerification` | `SYSTEM_UNAVAILABLE_EMAIL_VERIFICATION` |
| `CodeAuthVerificationAttemptsExceeded` | `AUTH_VERIFICATION_ATTEMPTS_EXCEEDED` |
| `CodeAuthResetDisabled` | `AUTH_RESET_DISABLED` |
| `CodeAuthResetInvalid` | `AUTH_RESET_INVALID` |
| `CodeAuthResetExpired` | `AUTH_RESET_EXPIRED` |
| `CodeAuthResetRequestLimited` | `AUTH_RESET_REQUEST_LIMITED` |
| `CodeSystemUnavailablePasswordReset` | `SYSTEM_UNAVAILABLE_PASSWORD_RESET` |
| `CodeAuthResetAttemptsExceeded` | `AUTH_RESET_ATTEMPTS_EXCEEDED` |
| `CodeAuthPasswordPolicyViolation` | `AUTH_PASSWORD_POLICY_VIOLATION` |
| `CodeAuthPasswordReuse` | `AUTH_PASSWORD_REUSE` |
| `CodeSystemSessionCreationFailed` | `SYSTEM_SESSION_CREATION_FAILED` |
| `CodeSystemSessionInvalidationFailed` | `SYSTEM_SESSION_INVALIDATION_FAILED` |
| `CodeAuthSessionLimitExceeded` | `AUTH_SESSION_LIMIT_EXCEEDED` |
| `CodeAuthTenantSessionLimitExceeded` | `AUTH_TENANT_SESSION_LIMIT_EXCEEDED` |
| `CodeAuthDeviceBindingRejected` | `AUTH_DEVICE_BINDING_REJECTED` |
| `CodeAuthMFADisabled` | `AUTH_MFA_DISABLED` |
| `CodeAuthTOTPRequired` | `AUTH_TOTP_REQUIRED` |
| `CodeAuthTOTPInvalid` | `AUTH_TOTP_INVALID` |
| `CodeAuthTOTPRateLimited` | `AUTH_TOTP_RATE_LIMITED` |
| `CodeAuthMFANotConfigured` | `AUTH_MFA_NOT_CONFIGURED` |
| `CodeSystemUnavailableMFA` | `SYSTEM_UNAVAILABLE_MFA` |
| `CodeAuthMFARequired` | `AUTH_MFA_REQUIRED` |
| `CodeAuthMFAInvalidCode` | `AUTH_MFA_INVALID_CODE` |
| `CodeAuthMFAExpired` | `AUTH_MFA_EXPIRED` |
| `CodeAuthMFAAttemptsExceeded` | `AUTH_MFA_ATTEMPTS_EXCEEDED` |
| `CodeAuthMFAReplayDetected` | `AUTH_MFA_REPLAY_DETECTED` |
| `CodeSystemUnavailableMFAChallenge` | `SYSTEM_UNAVAILABLE_MFA_CHALLENGE` |
| `CodeAuthMFABackupInvalid` | `AUTH_MFA_BACKUP_INVALID` |
| `CodeAuthMFABackupRateLimited` | `AUTH_MFA_BACKUP_RATE_LIMITED` |
| `CodeSystemUnavailableMFABackup` | `SYSTEM_UNAVAILABLE_MFA_BACKUP` |
| `CodeAuthMFABackupNotConfigured` | `AUTH_MFA_BACKUP_NOT_CONFIGURED` |
| `CodeAuthMFABackupRegenRequiresTOTP` | `AUTH_MFA_BACKUP_REGEN_REQUIRES_TOTP` |
| `CodeAuthSessionExpired` | `AUTH_SESSION_EXPIRED` |
| `CodeAuthInvalidToken` | `AUTH_INVALID_TOKEN` |
| `CodeAuthInvalidTokenClockSkew` | `AUTH_INVALID_TOKEN_CLOCK_SKEW` |
| `CodeAuthInvalidRouteMode` | `AUTH_INVALID_ROUTE_MODE` |
| `CodeSystemUnavailableStrictBackend` | `SYSTEM_UNAVAILABLE_STRICT_BACKEND` |
| `CodeAuthRefreshInvalid` | `AUTH_REFRESH_INVALID` |
| `CodeAuthRefreshReuseDetected` | `AUTH_REFRESH_REUSE_DETECTED` |
| `CodeAuthPermissionDenied` | `AUTH_PERMISSION_DENIED` |
| `CodeSystemEngineNotReady` | `SYSTEM_ENGINE_NOT_READY` |
| `CodeSystemProviderDuplicateIdentifier` | `SYSTEM_PROVIDER_DUPLICATE_IDENTIFIER` |
| `CodeSystemInternalError` | `SYSTEM_INTERNAL_ERROR` |
| `CodeSystemUnavailable` | `SYSTEM_UNAVAILABLE` |

## Exported `Err*` Sentinel Registry

| Sentinel | Category | AuthCode Constant | Default Message |
|----------|----------|-------------------|-----------------|
| `ErrUnauthorized` | `CategoryAuthValidation` | `CodeAuthUnauthorized` | `unauthorized` |
| `ErrInvalidCredentials` | `CategoryAuthValidation` | `CodeAuthInvalidCredentials` | `invalid credentials` |
| `ErrUserNotFound` | `CategoryAuthState` | `CodeAuthAccountNotFound` | `account not found` |
| `ErrLoginRateLimited` | `CategoryAuthAbuse` | `CodeAuthTooManyAttempts` | `too many attempts` |
| `ErrAccountExists` | `CategoryAuthState` | `CodeAuthAccountExists` | `account already exists` |
| `ErrAccountCreationDisabled` | `CategoryAuthState` | `CodeAuthAccountCreationDisabled` | `account creation disabled` |
| `ErrAccountCreationRateLimited` | `CategoryAuthAbuse` | `CodeAuthAccountCreationLimited` | `account creation rate limited` |
| `ErrAccountCreationUnavailable` | `CategorySystem` | `CodeSystemUnavailableAccountCreation` | `account creation unavailable` |
| `ErrAccountCreationInvalid` | `CategoryAuthValidation` | `CodeAuthAccountCreationInvalid` | `invalid account creation request` |
| `ErrAccountRoleInvalid` | `CategoryAuthValidation` | `CodeAuthAccountRoleInvalid` | `invalid account role` |
| `ErrAccountUnverified` | `CategoryAuthState` | `CodeAuthVerificationRequired` | `verification required` |
| `ErrAccountDisabled` | `CategoryAuthState` | `CodeAuthAccountDisabled` | `account disabled` |
| `ErrAccountLocked` | `CategoryAuthState` | `CodeAuthAccountLocked` | `account locked` |
| `ErrAccountDeleted` | `CategoryAuthState` | `CodeAuthAccountDeleted` | `account deleted` |
| `ErrAccountVersionNotAdvanced` | `CategorySystem` | `CodeSystemAccountVersionNotAdvanced` | `account state transition failed` |
| `ErrEmailVerificationDisabled` | `CategoryAuthState` | `CodeAuthVerificationDisabled` | `email verification disabled` |
| `ErrEmailVerificationInvalid` | `CategoryAuthValidation` | `CodeAuthVerificationInvalid` | `verification challenge invalid` |
| `ErrEmailVerificationRateLimited` | `CategoryAuthAbuse` | `CodeAuthVerificationRequestLimited` | `verification requests rate limited` |
| `ErrEmailVerificationUnavailable` | `CategorySystem` | `CodeSystemUnavailableEmailVerification` | `email verification unavailable` |
| `ErrEmailVerificationAttempts` | `CategoryAuthAbuse` | `CodeAuthVerificationAttemptsExceeded` | `verification attempts exceeded` |
| `ErrPasswordResetDisabled` | `CategoryAuthState` | `CodeAuthResetDisabled` | `password reset disabled` |
| `ErrPasswordResetInvalid` | `CategoryAuthValidation` | `CodeAuthResetInvalid` | `password reset challenge invalid` |
| `ErrPasswordResetRateLimited` | `CategoryAuthAbuse` | `CodeAuthResetRequestLimited` | `password reset requests rate limited` |
| `ErrPasswordResetUnavailable` | `CategorySystem` | `CodeSystemUnavailablePasswordReset` | `password reset unavailable` |
| `ErrPasswordResetAttempts` | `CategoryAuthAbuse` | `CodeAuthResetAttemptsExceeded` | `password reset attempts exceeded` |
| `ErrPasswordPolicy` | `CategoryAuthValidation` | `CodeAuthPasswordPolicyViolation` | `password policy violation` |
| `ErrPasswordReuse` | `CategoryAuthValidation` | `CodeAuthPasswordReuse` | `password reuse rejected` |
| `ErrSessionCreationFailed` | `CategorySystem` | `CodeSystemSessionCreationFailed` | `session creation failed` |
| `ErrSessionInvalidationFailed` | `CategorySystem` | `CodeSystemSessionInvalidationFailed` | `session invalidation failed` |
| `ErrSessionLimitExceeded` | `CategoryAuthAbuse` | `CodeAuthSessionLimitExceeded` | `session limit exceeded` |
| `ErrTenantSessionLimitExceeded` | `CategoryAuthAbuse` | `CodeAuthTenantSessionLimitExceeded` | `tenant session limit exceeded` |
| `ErrDeviceBindingRejected` | `CategoryAuthState` | `CodeAuthDeviceBindingRejected` | `device binding rejected` |
| `ErrTOTPFeatureDisabled` | `CategoryAuthState` | `CodeAuthMFADisabled` | `mfa disabled` |
| `ErrTOTPRequired` | `CategoryAuthState` | `CodeAuthTOTPRequired` | `totp required` |
| `ErrTOTPInvalid` | `CategoryAuthValidation` | `CodeAuthTOTPInvalid` | `invalid totp code` |
| `ErrTOTPRateLimited` | `CategoryAuthAbuse` | `CodeAuthTOTPRateLimited` | `totp attempts rate limited` |
| `ErrTOTPNotConfigured` | `CategoryAuthState` | `CodeAuthMFANotConfigured` | `totp not configured` |
| `ErrTOTPUnavailable` | `CategorySystem` | `CodeSystemUnavailableMFA` | `totp unavailable` |
| `ErrMFALoginRequired` | `CategoryAuthState` | `CodeAuthMFARequired` | `mfa required` |
| `ErrMFALoginInvalid` | `CategoryAuthValidation` | `CodeAuthMFAInvalidCode` | `mfa code invalid` |
| `ErrMFALoginExpired` | `CategoryAuthState` | `CodeAuthMFAExpired` | `mfa challenge expired` |
| `ErrMFALoginAttemptsExceeded` | `CategoryAuthAbuse` | `CodeAuthMFAAttemptsExceeded` | `mfa attempts exceeded` |
| `ErrMFALoginReplay` | `CategoryAuthAbuse` | `CodeAuthMFAReplayDetected` | `mfa replay detected` |
| `ErrMFALoginUnavailable` | `CategorySystem` | `CodeSystemUnavailableMFAChallenge` | `mfa challenge unavailable` |
| `ErrBackupCodeInvalid` | `CategoryAuthValidation` | `CodeAuthMFABackupInvalid` | `backup code invalid` |
| `ErrBackupCodeRateLimited` | `CategoryAuthAbuse` | `CodeAuthMFABackupRateLimited` | `backup code attempts rate limited` |
| `ErrBackupCodeUnavailable` | `CategorySystem` | `CodeSystemUnavailableMFABackup` | `backup code unavailable` |
| `ErrBackupCodesNotConfigured` | `CategoryAuthState` | `CodeAuthMFABackupNotConfigured` | `backup codes not configured` |
| `ErrBackupCodeRegenerationRequiresTOTP` | `CategoryAuthState` | `CodeAuthMFABackupRegenRequiresTOTP` | `backup code regeneration requires totp` |
| `ErrSessionNotFound` | `CategoryAuthState` | `CodeAuthSessionExpired` | `session not found or expired` |
| `ErrTokenInvalid` | `CategoryAuthValidation` | `CodeAuthInvalidToken` | `invalid token` |
| `ErrTokenClockSkew` | `CategoryAuthValidation` | `CodeAuthInvalidTokenClockSkew` | `token clock skew exceeded` |
| `ErrInvalidRouteMode` | `CategoryAuthValidation` | `CodeAuthInvalidRouteMode` | `invalid route validation mode` |
| `ErrStrictBackendDown` | `CategorySystem` | `CodeSystemUnavailableStrictBackend` | `strict validation backend unavailable` |
| `ErrRefreshInvalid` | `CategoryAuthValidation` | `CodeAuthRefreshInvalid` | `invalid refresh token` |
| `ErrRefreshReuse` | `CategoryAuthAbuse` | `CodeAuthRefreshReuseDetected` | `refresh token reuse detected` |
| `ErrPermissionDenied` | `CategoryAuthState` | `CodeAuthPermissionDenied` | `permission denied` |
| `ErrEngineNotReady` | `CategorySystem` | `CodeSystemEngineNotReady` | `engine not initialized` |
| `ErrProviderDuplicateIdentifier` | `CategorySystem` | `CodeSystemProviderDuplicateIdentifier` | `provider duplicate identifier` |
| `ErrSystemInternal` | `CategorySystem` | `CodeSystemInternalError` | `internal error` |
| `ErrSystemUnavailable` | `CategorySystem` | `CodeSystemUnavailable` | `service unavailable` |

## Mapper Behavior (`mapToAuthError`)

The boundary mapper in `error_mapping.go` applies these rules in order:

1. `nil` stays `nil`.
2. Existing `*AuthError` values are returned unchanged.
3. Wrapped/joined errors that match any exported sentinel via `errors.Is` are re-wrapped as that sentinel.
4. Internal subsystems are mapped to public sentinels:
   - `rate.ErrRateLimited` -> `ErrLoginRateLimited`
   - limiter domain errors -> domain abuse/unavailable sentinels
   - password reset/email verification/MFA challenge store errors -> corresponding invalid/attempt/unavailable sentinels
   - refresh/session domain errors -> `ErrRefreshReuse`, `ErrRefreshInvalid`, or `ErrSessionNotFound`
5. Dependency and context failures map to availability:
   - `rate.ErrRedisUnavailable`, `session.ErrRedisUnavailable`, lockout backend errors, `context.Canceled`, `context.DeadlineExceeded` -> `ErrSystemUnavailable`
6. Any remaining unknown error maps to `ErrSystemInternal`.

## HTTP Mapping Guidance

These status mappings are recommended for API adapters wrapping goAuth.

| Condition | Suggested HTTP Status |
|-----------|------------------------|
| `AUTH_UNAUTHORIZED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_INVALID_TOKEN`, `AUTH_REFRESH_INVALID` | `401 Unauthorized` |
| `AUTH_MFA_REQUIRED`, `AUTH_TOTP_REQUIRED` | `401 Unauthorized` |
| `AUTH_PERMISSION_DENIED` | `403 Forbidden` |
| `AUTH_ACCOUNT_DISABLED`, `AUTH_ACCOUNT_LOCKED`, `AUTH_ACCOUNT_DELETED`, `AUTH_VERIFICATION_REQUIRED` | `403 Forbidden` |
| `AUTH_ACCOUNT_EXISTS` | `409 Conflict` |
| Validation failures (`AUTH_*_INVALID`, password policy, route mode) | `400 Bad Request` |
| Abuse and attempt limits (`AUTH_*_LIMITED`, `AUTH_*_ATTEMPTS_*`, `AUTH_REFRESH_REUSE_DETECTED`) | `429 Too Many Requests` |
| Unavailable dependency codes (`SYSTEM_UNAVAILABLE*`) | `503 Service Unavailable` |
| `SYSTEM_INTERNAL_ERROR` | `500 Internal Server Error` |

## Consumer Pattern

```go
access, refresh, err := engine.Login(ctx, username, password)
if err != nil {
    if errors.Is(err, goAuth.ErrInvalidCredentials) {
        // stable sentinel check
    }

    var ae *goAuth.AuthError
    if errors.As(err, &ae) {
        log.Printf("auth error category=%s code=%s", ae.Category, ae.Code)
    }
}
```
