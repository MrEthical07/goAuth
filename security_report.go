package goAuth

import "time"

// SecurityReport defines a public type used by goAuth APIs.
//
// SecurityReport instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SecurityReport struct {
	ProductionMode               bool
	SigningAlgorithm             string
	ValidationMode               ValidationMode
	StrictMode                   bool
	AccessTTL                    time.Duration
	RefreshTTL                   time.Duration
	Argon2                       PasswordConfigReport
	TOTPEnabled                  bool
	BackupEnabled                bool
	DeviceBindingEnabled         bool
	RefreshRotationEnabled       bool
	RefreshReuseDetectionEnabled bool
	SessionCapsActive            bool
	RateLimitingActive           bool
	EmailVerificationActive      bool
	PasswordResetActive          bool
}

// PasswordConfigReport defines a public type used by goAuth APIs.
//
// PasswordConfigReport instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type PasswordConfigReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// SecurityReport describes the securityreport operation and its observable behavior.
//
// SecurityReport may return an error when input validation, dependency calls, or security checks fail.
// SecurityReport does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) SecurityReport() SecurityReport {
	if e == nil {
		return SecurityReport{}
	}

	sessionCaps := e.config.SessionHardening.MaxSessionsPerUser > 0 ||
		e.config.SessionHardening.MaxSessionsPerTenant > 0 ||
		e.config.SessionHardening.EnforceSingleSession ||
		e.config.SessionHardening.ConcurrentLoginLimit > 0

	rateLimiting := e.config.Security.MaxLoginAttempts > 0 &&
		e.config.Security.LoginCooldownDuration > 0

	return SecurityReport{
		ProductionMode:   e.config.Security.ProductionMode,
		SigningAlgorithm: e.config.JWT.SigningMethod,
		ValidationMode:   e.config.ValidationMode,
		StrictMode:       e.config.ValidationMode == ModeStrict || e.config.Security.StrictMode,
		AccessTTL:        e.config.JWT.AccessTTL,
		RefreshTTL:       e.config.JWT.RefreshTTL,
		Argon2: PasswordConfigReport{
			Memory:      e.config.Password.Memory,
			Time:        e.config.Password.Time,
			Parallelism: e.config.Password.Parallelism,
			SaltLength:  e.config.Password.SaltLength,
			KeyLength:   e.config.Password.KeyLength,
		},
		TOTPEnabled:                  e.config.TOTP.Enabled,
		BackupEnabled:                e.config.TOTP.Enabled && e.config.TOTP.BackupCodeCount > 0,
		DeviceBindingEnabled:         e.config.DeviceBinding.Enabled,
		RefreshRotationEnabled:       e.config.Security.EnforceRefreshRotation,
		RefreshReuseDetectionEnabled: e.config.Security.EnforceRefreshReuseDetection,
		SessionCapsActive:            sessionCaps,
		RateLimitingActive:           rateLimiting || e.config.Security.EnableRefreshThrottle,
		EmailVerificationActive:      e.config.EmailVerification.Enabled,
		PasswordResetActive:          e.config.PasswordReset.Enabled,
	}
}
