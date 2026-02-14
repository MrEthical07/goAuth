package goAuth

import "time"

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

type PasswordConfigReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

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
