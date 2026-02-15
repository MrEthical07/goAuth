package goAuth

import (
	"context"
	"errors"
	"time"
)

const (
	auditEventLoginSuccess               = "login_success"
	auditEventLoginFailure               = "login_failure"
	auditEventLoginRateLimited           = "login_rate_limited"
	auditEventRefreshSuccess             = "refresh_success"
	auditEventRefreshInvalid             = "refresh_invalid"
	auditEventRefreshRateLimited         = "refresh_rate_limited"
	auditEventRefreshReuseDetected       = "refresh_reuse_detected"
	auditEventPasswordChangeSuccess      = "password_change_success"
	auditEventPasswordChangeInvalidOld   = "password_change_invalid_old"
	auditEventPasswordChangeReuse        = "password_change_reuse_attempt"
	auditEventPasswordChangeFailure      = "password_change_failure"
	auditEventPasswordResetRequest       = "password_reset_request"
	auditEventPasswordResetConfirm       = "password_reset_confirm"
	auditEventPasswordResetReplay        = "password_reset_replay"
	auditEventEmailVerificationRequest   = "email_verification_request"
	auditEventEmailVerificationConfirm   = "email_verification_confirm"
	auditEventAccountCreationSuccess     = "account_creation_success"
	auditEventAccountCreationFailure     = "account_creation_failure"
	auditEventAccountCreationDuplicate   = "account_creation_duplicate"
	auditEventAccountCreationRateLimited = "account_creation_rate_limited"
	auditEventAccountStatusChange        = "account_status_change"
	auditEventLogoutSession              = "logout_session"
	auditEventLogoutAll                  = "logout_all"
	auditEventRateLimitTriggered         = "rate_limit_triggered"
	auditEventDeviceAnomalyDetected      = "device_anomaly_detected"
	auditEventDeviceBindingRejected      = "device_binding_rejected"
	auditEventTOTPSetupRequested         = "totp_setup_requested"
	auditEventTOTPEnabled                = "totp_enabled"
	auditEventTOTPDisabled               = "totp_disabled"
	auditEventTOTPFailure                = "totp_failure"
	auditEventTOTPSuccess                = "totp_success"
	auditEventMFARequired                = "mfa_required"
	auditEventMFASuccess                 = "mfa_success"
	auditEventMFAFailure                 = "mfa_failure"
	auditEventMFAAttemptsExceeded        = "mfa_attempts_exceeded"
	auditEventBackupCodesGenerated       = "backup_codes_generated"
	auditEventBackupCodeUsed             = "backup_code_used"
	auditEventBackupCodeFailed           = "backup_code_failed"
)

// AuditErrorCode defines a public type used by goAuth APIs.
//
// AuditErrorCode instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuditErrorCode string

const (
	auditErrUnauthorized          AuditErrorCode = "unauthorized"
	auditErrInvalidCredentials    AuditErrorCode = "invalid_credentials"
	auditErrRateLimited           AuditErrorCode = "rate_limited"
	auditErrRefreshReuse          AuditErrorCode = "refresh_reuse"
	auditErrInvalidToken          AuditErrorCode = "invalid_token"
	auditErrSessionNotFound       AuditErrorCode = "session_not_found"
	auditErrUserNotFound          AuditErrorCode = "user_not_found"
	auditErrAccountDisabled       AuditErrorCode = "account_disabled"
	auditErrAccountLocked         AuditErrorCode = "account_locked"
	auditErrAccountDeleted        AuditErrorCode = "account_deleted"
	auditErrAccountUnverified     AuditErrorCode = "account_unverified"
	auditErrPasswordPolicy        AuditErrorCode = "password_policy"
	auditErrPasswordReuse         AuditErrorCode = "password_reuse"
	auditErrAttemptsExceeded      AuditErrorCode = "attempts_exceeded"
	auditErrSessionCreationFailed AuditErrorCode = "session_creation_failed"
	auditErrSessionInvalidation   AuditErrorCode = "session_invalidation_failed"
	auditErrSessionLimitExceeded  AuditErrorCode = "session_limit_exceeded"
	auditErrDeviceBindingRejected AuditErrorCode = "device_binding_rejected"
	auditErrTOTPRequired          AuditErrorCode = "totp_required"
	auditErrTOTPInvalid           AuditErrorCode = "totp_invalid"
	auditErrTOTPRateLimited       AuditErrorCode = "totp_rate_limited"
	auditErrMFARequired           AuditErrorCode = "mfa_required"
	auditErrMFAInvalid            AuditErrorCode = "mfa_invalid"
	auditErrMFAAttemptsExceeded   AuditErrorCode = "mfa_attempts_exceeded"
	auditErrMFAReplay             AuditErrorCode = "mfa_replay"
	auditErrBackupCodeInvalid     AuditErrorCode = "backup_code_invalid"
	auditErrBackupCodeRateLimited AuditErrorCode = "backup_code_rate_limited"
	auditErrDuplicate             AuditErrorCode = "duplicate"
	auditErrUnavailable           AuditErrorCode = "backend_unavailable"
	auditErrInternal              AuditErrorCode = "internal_error"
)

func (e *Engine) emitAudit(
	ctx context.Context,
	eventType string,
	success bool,
	userID string,
	tenantID string,
	sessionID string,
	err error,
	metadataBuilder func() map[string]string,
) {
	if e == nil || e.audit == nil {
		return
	}
	if tenantID == "" {
		tenantID = tenantIDFromContext(ctx)
	}

	var metadata map[string]string
	if metadataBuilder != nil {
		metadata = metadataBuilder()
	}

	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		IP:        clientIPFromContext(ctx),
		Success:   success,
		Metadata:  metadata,
	}
	if code := auditErrorCode(err); code != "" {
		event.Error = string(code)
	}

	e.audit.Emit(ctx, event)
}

func (e *Engine) emitRateLimit(
	ctx context.Context,
	scope string,
	tenantID string,
	metadataBuilder func() map[string]string,
) {
	e.metricInc(MetricRateLimitHit)
	e.emitAudit(ctx, auditEventRateLimitTriggered, false, "", tenantID, "", nil, func() map[string]string {
		base := map[string]string{
			"scope": scope,
		}
		if metadataBuilder == nil {
			return base
		}
		for k, v := range metadataBuilder() {
			base[k] = v
		}
		return base
	})
}

func auditErrorCode(err error) AuditErrorCode {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrUnauthorized):
		return auditErrUnauthorized
	case errors.Is(err, ErrInvalidCredentials):
		return auditErrInvalidCredentials
	case errors.Is(err, ErrLoginRateLimited),
		errors.Is(err, ErrRefreshRateLimited),
		errors.Is(err, ErrPasswordResetRateLimited),
		errors.Is(err, ErrEmailVerificationRateLimited),
		errors.Is(err, ErrAccountCreationRateLimited):
		return auditErrRateLimited
	case errors.Is(err, ErrRefreshReuse):
		return auditErrRefreshReuse
	case errors.Is(err, ErrRefreshInvalid),
		errors.Is(err, ErrPasswordResetInvalid),
		errors.Is(err, ErrEmailVerificationInvalid),
		errors.Is(err, ErrTokenInvalid),
		errors.Is(err, ErrTokenClockSkew):
		return auditErrInvalidToken
	case errors.Is(err, ErrSessionNotFound):
		return auditErrSessionNotFound
	case errors.Is(err, ErrUserNotFound):
		return auditErrUserNotFound
	case errors.Is(err, ErrAccountDisabled):
		return auditErrAccountDisabled
	case errors.Is(err, ErrAccountLocked):
		return auditErrAccountLocked
	case errors.Is(err, ErrAccountDeleted):
		return auditErrAccountDeleted
	case errors.Is(err, ErrAccountUnverified):
		return auditErrAccountUnverified
	case errors.Is(err, ErrPasswordPolicy):
		return auditErrPasswordPolicy
	case errors.Is(err, ErrPasswordReuse):
		return auditErrPasswordReuse
	case errors.Is(err, ErrPasswordResetAttempts),
		errors.Is(err, ErrEmailVerificationAttempts):
		return auditErrAttemptsExceeded
	case errors.Is(err, ErrSessionCreationFailed):
		return auditErrSessionCreationFailed
	case errors.Is(err, ErrSessionInvalidationFailed):
		return auditErrSessionInvalidation
	case errors.Is(err, ErrSessionLimitExceeded),
		errors.Is(err, ErrTenantSessionLimitExceeded):
		return auditErrSessionLimitExceeded
	case errors.Is(err, ErrDeviceBindingRejected):
		return auditErrDeviceBindingRejected
	case errors.Is(err, ErrTOTPRequired):
		return auditErrTOTPRequired
	case errors.Is(err, ErrTOTPInvalid),
		errors.Is(err, ErrTOTPNotConfigured):
		return auditErrTOTPInvalid
	case errors.Is(err, ErrTOTPRateLimited):
		return auditErrTOTPRateLimited
	case errors.Is(err, ErrMFALoginRequired):
		return auditErrMFARequired
	case errors.Is(err, ErrMFALoginInvalid),
		errors.Is(err, ErrMFALoginExpired):
		return auditErrMFAInvalid
	case errors.Is(err, ErrMFALoginAttemptsExceeded):
		return auditErrMFAAttemptsExceeded
	case errors.Is(err, ErrMFALoginReplay):
		return auditErrMFAReplay
	case errors.Is(err, ErrBackupCodeInvalid),
		errors.Is(err, ErrBackupCodesNotConfigured),
		errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP):
		return auditErrBackupCodeInvalid
	case errors.Is(err, ErrBackupCodeRateLimited):
		return auditErrBackupCodeRateLimited
	case errors.Is(err, ErrTOTPFeatureDisabled),
		errors.Is(err, ErrTOTPUnavailable),
		errors.Is(err, ErrMFALoginUnavailable),
		errors.Is(err, ErrBackupCodeUnavailable):
		return auditErrUnavailable
	case errors.Is(err, ErrAccountExists),
		errors.Is(err, ErrProviderDuplicateIdentifier):
		return auditErrDuplicate
	case errors.Is(err, ErrPasswordResetUnavailable),
		errors.Is(err, ErrEmailVerificationUnavailable),
		errors.Is(err, ErrAccountCreationUnavailable),
		errors.Is(err, ErrTOTPUnavailable),
		errors.Is(err, ErrMFALoginUnavailable),
		errors.Is(err, ErrBackupCodeUnavailable),
		errors.Is(err, ErrStrictBackendDown):
		return auditErrUnavailable
	default:
		return auditErrInternal
	}
}
