package internaldefs

import (
	goAuth "github.com/MrEthical07/goAuth"
)

// CounterDef defines a public type used by goAuth APIs.
//
// CounterDef instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type CounterDef struct {
	ID   goAuth.MetricID
	Name string
	Help string
}

// HistogramDef defines a public type used by goAuth APIs.
//
// HistogramDef instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type HistogramDef struct {
	ID   goAuth.MetricID
	Name string
	Help string
}

// CounterDefs is an exported constant or variable used by the authentication engine.
var CounterDefs = []CounterDef{
	{ID: goAuth.MetricLoginSuccess, Name: "goauth_login_success_total", Help: "Successful login attempts."},
	{ID: goAuth.MetricLoginFailure, Name: "goauth_login_failure_total", Help: "Failed login attempts."},
	{ID: goAuth.MetricLoginRateLimited, Name: "goauth_login_rate_limited_total", Help: "Rate-limited login attempts."},
	{ID: goAuth.MetricRefreshSuccess, Name: "goauth_refresh_success_total", Help: "Successful refresh operations."},
	{ID: goAuth.MetricRefreshFailure, Name: "goauth_refresh_failure_total", Help: "Failed refresh operations."},
	{ID: goAuth.MetricRefreshReuseDetected, Name: "goauth_refresh_reuse_detected_total", Help: "Detected refresh token reuses."},
	{ID: goAuth.MetricReplayDetected, Name: "goauth_replay_detected_total", Help: "Detected replay attempts."},
	{ID: goAuth.MetricRefreshRateLimited, Name: "goauth_refresh_rate_limited_total", Help: "Rate-limited refresh attempts."},
	{ID: goAuth.MetricDeviceIPMismatch, Name: "goauth_device_ip_mismatch_total", Help: "Detected device IP mismatches."},
	{ID: goAuth.MetricDeviceUAMismatch, Name: "goauth_device_ua_mismatch_total", Help: "Detected device user-agent mismatches."},
	{ID: goAuth.MetricDeviceRejected, Name: "goauth_device_rejected_total", Help: "Requests rejected by device binding enforcement."},
	{ID: goAuth.MetricTOTPRequired, Name: "goauth_totp_required_total", Help: "Operations requiring TOTP."},
	{ID: goAuth.MetricTOTPFailure, Name: "goauth_totp_failure_total", Help: "Failed TOTP verifications."},
	{ID: goAuth.MetricTOTPSuccess, Name: "goauth_totp_success_total", Help: "Successful TOTP verifications."},
	{ID: goAuth.MetricMFALoginRequired, Name: "goauth_mfa_login_required_total", Help: "Login flows requiring MFA step-up."},
	{ID: goAuth.MetricMFALoginSuccess, Name: "goauth_mfa_login_success_total", Help: "Successful MFA login confirmations."},
	{ID: goAuth.MetricMFALoginFailure, Name: "goauth_mfa_login_failure_total", Help: "Failed MFA login confirmations."},
	{ID: goAuth.MetricMFAReplayAttempt, Name: "goauth_mfa_replay_attempt_total", Help: "Detected MFA replay attempts."},
	{ID: goAuth.MetricBackupCodeUsed, Name: "goauth_backup_code_used_total", Help: "Successful backup-code authentications."},
	{ID: goAuth.MetricBackupCodeFailed, Name: "goauth_backup_code_failed_total", Help: "Failed backup-code authentications."},
	{ID: goAuth.MetricBackupCodeRegenerated, Name: "goauth_backup_code_regenerated_total", Help: "Backup-code regeneration operations."},
	{ID: goAuth.MetricRateLimitHit, Name: "goauth_rate_limit_hit_total", Help: "Rate-limit checks that denied requests."},
	{ID: goAuth.MetricSessionCreated, Name: "goauth_session_created_total", Help: "Created sessions."},
	{ID: goAuth.MetricSessionInvalidated, Name: "goauth_session_invalidated_total", Help: "Invalidated sessions."},
	{ID: goAuth.MetricLogout, Name: "goauth_logout_total", Help: "Single-session logout operations."},
	{ID: goAuth.MetricLogoutAll, Name: "goauth_logout_all_total", Help: "Logout-all operations."},
	{ID: goAuth.MetricAccountCreationSuccess, Name: "goauth_account_creation_success_total", Help: "Successful account creations."},
	{ID: goAuth.MetricAccountCreationDuplicate, Name: "goauth_account_creation_duplicate_total", Help: "Account creation attempts rejected as duplicate."},
	{ID: goAuth.MetricAccountCreationRateLimited, Name: "goauth_account_creation_rate_limited_total", Help: "Rate-limited account creation attempts."},
	{ID: goAuth.MetricPasswordChangeSuccess, Name: "goauth_password_change_success_total", Help: "Successful password changes."},
	{ID: goAuth.MetricPasswordChangeInvalidOld, Name: "goauth_password_change_invalid_old_total", Help: "Password change attempts with invalid old password."},
	{ID: goAuth.MetricPasswordChangeReuseRejected, Name: "goauth_password_change_reuse_rejected_total", Help: "Password change attempts rejected for reuse."},
	{ID: goAuth.MetricPasswordResetRequest, Name: "goauth_password_reset_request_total", Help: "Password reset requests."},
	{ID: goAuth.MetricPasswordResetConfirmSuccess, Name: "goauth_password_reset_confirm_success_total", Help: "Successful password reset confirmations."},
	{ID: goAuth.MetricPasswordResetConfirmFailure, Name: "goauth_password_reset_confirm_failure_total", Help: "Failed password reset confirmations."},
	{ID: goAuth.MetricPasswordResetAttemptsExceeded, Name: "goauth_password_reset_attempts_exceeded_total", Help: "Password reset challenges invalidated due to attempt cap."},
	{ID: goAuth.MetricEmailVerificationRequest, Name: "goauth_email_verification_request_total", Help: "Email verification requests."},
	{ID: goAuth.MetricEmailVerificationSuccess, Name: "goauth_email_verification_success_total", Help: "Successful email verifications."},
	{ID: goAuth.MetricEmailVerificationFailure, Name: "goauth_email_verification_failure_total", Help: "Failed email verifications."},
	{ID: goAuth.MetricEmailVerificationAttemptsExceeded, Name: "goauth_email_verification_attempts_exceeded_total", Help: "Email verification challenges invalidated due to attempt cap."},
	{ID: goAuth.MetricAccountDisabled, Name: "goauth_account_disabled_total", Help: "Account disable operations."},
	{ID: goAuth.MetricAccountLocked, Name: "goauth_account_locked_total", Help: "Account lock operations."},
	{ID: goAuth.MetricAccountDeleted, Name: "goauth_account_deleted_total", Help: "Account delete operations."},
}

// HistogramDefs is an exported constant or variable used by the authentication engine.
var HistogramDefs = []HistogramDef{
	{ID: goAuth.MetricValidateLatency, Name: "goauth_validate_latency_seconds", Help: "Validate latency histogram."},
}

// HistogramBounds is an exported constant or variable used by the authentication engine.
var HistogramBounds = []string{
	"0.005",
	"0.01",
	"0.025",
	"0.05",
	"0.1",
	"0.25",
	"0.5",
	"+Inf",
}

// HistogramBoundSuffix is an exported constant or variable used by the authentication engine.
var HistogramBoundSuffix = []string{
	"0_005",
	"0_01",
	"0_025",
	"0_05",
	"0_1",
	"0_25",
	"0_5",
	"inf",
}

// NormalizeBuckets describes the normalizebuckets operation and its observable behavior.
//
// NormalizeBuckets may return an error when input validation, dependency calls, or security checks fail.
// NormalizeBuckets does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NormalizeBuckets(raw []uint64) [8]uint64 {
	var out [8]uint64
	for i := 0; i < len(out) && i < len(raw); i++ {
		out[i] = raw[i]
	}
	return out
}

// CumulativeBuckets describes the cumulativebuckets operation and its observable behavior.
//
// CumulativeBuckets may return an error when input validation, dependency calls, or security checks fail.
// CumulativeBuckets does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func CumulativeBuckets(raw [8]uint64) [8]uint64 {
	var out [8]uint64
	var running uint64
	for i := 0; i < len(raw); i++ {
		running += raw[i]
		out[i] = running
	}
	return out
}
