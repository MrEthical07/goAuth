package security

import "time"

type PasswordReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type Report struct {
	ProductionMode               bool
	SigningAlgorithm             string
	ValidationMode               int
	StrictMode                   bool
	AccessTTL                    time.Duration
	RefreshTTL                   time.Duration
	Argon2                       PasswordReport
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

type ReportInput struct {
	ProductionMode               bool
	SigningAlgorithm             string
	ValidationMode               int
	StrictMode                   bool
	AccessTTL                    time.Duration
	RefreshTTL                   time.Duration
	Password                     PasswordReport
	TOTPEnabled                  bool
	BackupCodeCount              int
	DeviceBindingEnabled         bool
	RefreshRotationEnabled       bool
	RefreshReuseDetectionEnabled bool
	EnableRefreshThrottle        bool
	EmailVerificationEnabled     bool
	PasswordResetEnabled         bool
	MaxSessionsPerUser           int
	MaxSessionsPerTenant         int
	EnforceSingleSession         bool
	ConcurrentLoginLimit         int
	MaxLoginAttempts             int
	LoginCooldownDuration        time.Duration
}

func BuildReport(input ReportInput) Report {
	sessionCaps := input.MaxSessionsPerUser > 0 ||
		input.MaxSessionsPerTenant > 0 ||
		input.EnforceSingleSession ||
		input.ConcurrentLoginLimit > 0

	rateLimiting := input.MaxLoginAttempts > 0 &&
		input.LoginCooldownDuration > 0

	return Report{
		ProductionMode:               input.ProductionMode,
		SigningAlgorithm:             input.SigningAlgorithm,
		ValidationMode:               input.ValidationMode,
		StrictMode:                   input.StrictMode,
		AccessTTL:                    input.AccessTTL,
		RefreshTTL:                   input.RefreshTTL,
		Argon2:                       input.Password,
		TOTPEnabled:                  input.TOTPEnabled,
		BackupEnabled:                input.TOTPEnabled && input.BackupCodeCount > 0,
		DeviceBindingEnabled:         input.DeviceBindingEnabled,
		RefreshRotationEnabled:       input.RefreshRotationEnabled,
		RefreshReuseDetectionEnabled: input.RefreshReuseDetectionEnabled,
		SessionCapsActive:            sessionCaps,
		RateLimitingActive:           rateLimiting || input.EnableRefreshThrottle,
		EmailVerificationActive:      input.EmailVerificationEnabled,
		PasswordResetActive:          input.PasswordResetEnabled,
	}
}
