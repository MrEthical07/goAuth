package goAuth

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"time"
)

// Config defines a public type used by goAuth APIs.
//
// Config instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Config struct {
	JWT               JWTConfig
	Session           SessionConfig
	SessionHardening  SessionHardeningConfig
	DeviceBinding     DeviceBindingConfig
	TOTP              TOTPConfig
	Password          PasswordConfig
	PasswordReset     PasswordResetConfig
	EmailVerification EmailVerificationConfig
	Account           AccountConfig
	Audit             AuditConfig
	Metrics           MetricsConfig
	Security          SecurityConfig
	MultiTenant       MultiTenantConfig
	Database          DatabaseConfig
	Permission        PermissionConfig
	Cache             CacheConfig
	Result            ResultConfig
	ValidationMode    ValidationMode
}

/*
====================================
JWT CONFIG
====================================
*/

// JWTConfig defines a public type used by goAuth APIs.
//
// JWTConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type JWTConfig struct {
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	SigningMethod string // "ed25519" (default), "hs256" optional
	PrivateKey    []byte
	PublicKey     []byte
}

/*
====================================
SESSION CONFIG
====================================
*/

// SessionConfig defines a public type used by goAuth APIs.
//
// SessionConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SessionConfig struct {
	RedisPrefix             string
	SlidingExpiration       bool
	AbsoluteSessionLifetime time.Duration
	JitterEnabled           bool
	JitterRange             time.Duration
	MaxSessionSize          int
	SessionEncoding         string // "binary" (default) or "msgpack"
}

/*
====================================
PASSWORD CONFIG
====================================
*/

// PasswordConfig defines a public type used by goAuth APIs.
//
// PasswordConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type PasswordConfig struct {
	Memory         uint32 // in KB
	Time           uint32
	Parallelism    uint8
	SaltLength     uint32
	KeyLength      uint32
	UpgradeOnLogin bool
}

// ResetStrategyType defines a public type used by goAuth APIs.
//
// ResetStrategyType instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type ResetStrategyType int

const (
	// ResetToken is an exported constant or variable used by the authentication engine.
	ResetToken ResetStrategyType = iota
	// ResetOTP is an exported constant or variable used by the authentication engine.
	ResetOTP
	// ResetUUID is an exported constant or variable used by the authentication engine.
	ResetUUID
)

// PasswordResetConfig defines a public type used by goAuth APIs.
//
// PasswordResetConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type PasswordResetConfig struct {
	Enabled                  bool
	Strategy                 ResetStrategyType
	ResetTTL                 time.Duration
	MaxAttempts              int
	EnableIPThrottle         bool
	EnableIdentifierThrottle bool
	OTPDigits                int
}

// VerificationStrategyType defines a public type used by goAuth APIs.
//
// VerificationStrategyType instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type VerificationStrategyType int

const (
	// VerificationToken is an exported constant or variable used by the authentication engine.
	VerificationToken VerificationStrategyType = iota
	// VerificationOTP is an exported constant or variable used by the authentication engine.
	VerificationOTP
	// VerificationUUID is an exported constant or variable used by the authentication engine.
	VerificationUUID
)

// EmailVerificationConfig defines a public type used by goAuth APIs.
//
// EmailVerificationConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type EmailVerificationConfig struct {
	Enabled                  bool
	Strategy                 VerificationStrategyType
	VerificationTTL          time.Duration
	MaxAttempts              int
	RequireForLogin          bool
	EnableIPThrottle         bool
	EnableIdentifierThrottle bool
	OTPDigits                int
}

// AccountConfig defines a public type used by goAuth APIs.
//
// AccountConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AccountConfig struct {
	Enabled                               bool
	AutoLogin                             bool
	EnableIPThrottle                      bool
	EnableIdentifierThrottle              bool
	AccountCreationMaxAttempts            int
	AccountCreationCooldown               time.Duration
	DefaultRole                           string
	AllowDuplicateIdentifierAcrossTenants bool
}

// AuditConfig defines a public type used by goAuth APIs.
//
// AuditConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuditConfig struct {
	Enabled    bool
	BufferSize int
	DropIfFull bool
}

// MetricsConfig defines a public type used by goAuth APIs.
//
// MetricsConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type MetricsConfig struct {
	Enabled                 bool
	EnableLatencyHistograms bool
}

/*
====================================
SECURITY CONFIG
====================================
*/

// SecurityConfig defines a public type used by goAuth APIs.
//
// SecurityConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SecurityConfig struct {
	ProductionMode               bool
	EnableIPBinding              bool
	EnableUserAgentBinding       bool
	EnableIPThrottle             bool
	EnableRefreshThrottle        bool
	EnforceRefreshRotation       bool
	EnforceRefreshReuseDetection bool
	MaxLoginAttempts             int
	LoginCooldownDuration        time.Duration
	MaxRefreshAttempts           int
	RefreshCooldownDuration      time.Duration
	StrictMode                   bool
	RequireSecureCookies         bool
	SameSitePolicy               http.SameSite
	CSRFProtection               bool
	EnablePermissionVersionCheck bool
	EnableRoleVersionCheck       bool
	EnableAccountVersionCheck    bool
}

// SessionHardeningConfig defines a public type used by goAuth APIs.
//
// SessionHardeningConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SessionHardeningConfig struct {
	MaxSessionsPerUser   int
	MaxSessionsPerTenant int
	EnforceSingleSession bool
	ConcurrentLoginLimit int
	EnableReplayTracking bool
	MaxClockSkew         time.Duration
}

// DeviceBindingConfig defines a public type used by goAuth APIs.
//
// DeviceBindingConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type DeviceBindingConfig struct {
	Enabled                 bool
	EnforceIPBinding        bool
	EnforceUserAgentBinding bool
	DetectIPChange          bool
	DetectUserAgentChange   bool
}

// TOTPConfig defines a public type used by goAuth APIs.
//
// TOTPConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type TOTPConfig struct {
	Enabled                     bool
	Issuer                      string
	Digits                      int
	Period                      int
	Algorithm                   string
	Skew                        int
	EnforceReplayProtection     bool
	MFALoginChallengeTTL        time.Duration
	MFALoginMaxAttempts         int
	BackupCodeCount             int
	BackupCodeLength            int
	BackupCodeMaxAttempts       int
	BackupCodeCooldown          time.Duration
	RequireForLogin             bool
	RequireBackupForLogin       bool
	RequireForSensitive         bool
	RequireForPasswordReset     bool
	RequireTOTPForPasswordReset bool
}

/*
====================================
MULTI TENANT CONFIG
====================================
*/

// MultiTenantConfig defines a public type used by goAuth APIs.
//
// MultiTenantConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type MultiTenantConfig struct {
	Enabled          bool
	TenantHeader     string
	EnforceIsolation bool
}

/*
====================================
DATABASE CONFIG
====================================
*/

// DatabaseConfig defines a public type used by goAuth APIs.
//
// DatabaseConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type DatabaseConfig struct {
	Address                   string
	Password                  string
	MaxConnections            int
	MinConnections            int
	ConnMaxLifetime           time.Duration
	PreparedStatementsEnabled bool
}

/*
====================================
PERMISSION CONFIG
====================================
*/

// PermissionConfig defines a public type used by goAuth APIs.
//
// PermissionConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type PermissionConfig struct {
	MaxBits         int  // 64, 128, 256, 512 (hard cap)
	RootBitReserved bool // if true, highest bit is root/super admin
}

/*
====================================
CACHE CONFIG
====================================
*/

// CacheConfig defines a public type used by goAuth APIs.
//
// CacheConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type CacheConfig struct {
	LRUEnabled bool
	Size       int
}

// ResultConfig defines a public type used by goAuth APIs.
//
// ResultConfig instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type ResultConfig struct {
	IncludeRole        bool
	IncludePermissions bool
}

// ValidationMode defines a public type used by goAuth APIs.
//
// ValidationMode instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type ValidationMode int

const (
	// ModeInherit is an exported constant or variable used by the authentication engine.
	ModeInherit ValidationMode = -1

	// ModeJWTOnly is an exported constant or variable used by the authentication engine.
	ModeJWTOnly ValidationMode = iota
	// ModeHybrid is an exported constant or variable used by the authentication engine.
	ModeHybrid
	// ModeStrict is an exported constant or variable used by the authentication engine.
	ModeStrict
)

// RouteMode is the per-route override mode for Engine.Validate.
// It intentionally reuses the same constants (ModeInherit/ModeStrict/ModeJWTOnly).
type RouteMode = ValidationMode

/*
====================================
DEFAULT CONFIG
====================================
*/

func defaultConfig() Config {
	return Config{
		JWT: JWTConfig{
			AccessTTL:     5 * time.Minute,
			RefreshTTL:    7 * 24 * time.Hour,
			SigningMethod: "ed25519",
		},
		Session: SessionConfig{
			RedisPrefix:             "as",
			SlidingExpiration:       true,
			AbsoluteSessionLifetime: 7 * 24 * time.Hour,
			JitterEnabled:           true,
			JitterRange:             30 * time.Second,
			MaxSessionSize:          512,
			SessionEncoding:         "binary",
		},
		Password: PasswordConfig{
			Memory:         65536,
			Time:           3,
			Parallelism:    2,
			SaltLength:     16,
			KeyLength:      32,
			UpgradeOnLogin: true,
		},
		PasswordReset: PasswordResetConfig{
			Enabled:                  false,
			Strategy:                 ResetToken,
			ResetTTL:                 15 * time.Minute,
			MaxAttempts:              5,
			EnableIPThrottle:         true,
			EnableIdentifierThrottle: true,
			OTPDigits:                6,
		},
		EmailVerification: EmailVerificationConfig{
			Enabled:                  false,
			Strategy:                 VerificationToken,
			VerificationTTL:          15 * time.Minute,
			MaxAttempts:              5,
			RequireForLogin:          false,
			EnableIPThrottle:         true,
			EnableIdentifierThrottle: true,
			OTPDigits:                6,
		},
		Account: AccountConfig{
			Enabled:                               true,
			AutoLogin:                             false,
			EnableIPThrottle:                      true,
			EnableIdentifierThrottle:              true,
			AccountCreationMaxAttempts:            5,
			AccountCreationCooldown:               15 * time.Minute,
			DefaultRole:                           "",
			AllowDuplicateIdentifierAcrossTenants: false,
		},
		Audit: AuditConfig{
			Enabled:    false,
			BufferSize: 1024,
			DropIfFull: true,
		},
		Metrics: MetricsConfig{
			Enabled:                 false,
			EnableLatencyHistograms: false,
		},
		Security: SecurityConfig{
			ProductionMode:               false,
			EnableIPBinding:              false,
			EnableUserAgentBinding:       true,
			EnableIPThrottle:             false,
			EnableRefreshThrottle:        true,
			EnforceRefreshRotation:       true,
			EnforceRefreshReuseDetection: true,
			MaxLoginAttempts:             5,
			LoginCooldownDuration:        15 * time.Minute,
			MaxRefreshAttempts:           20,
			RefreshCooldownDuration:      1 * time.Minute,
			StrictMode:                   false,
			RequireSecureCookies:         true,
			SameSitePolicy:               http.SameSiteStrictMode,
			CSRFProtection:               true,
			EnablePermissionVersionCheck: true,
			EnableRoleVersionCheck:       true,
			EnableAccountVersionCheck:    true,
		},
		SessionHardening: SessionHardeningConfig{
			MaxSessionsPerUser:   0,
			MaxSessionsPerTenant: 0,
			EnforceSingleSession: false,
			ConcurrentLoginLimit: 0,
			EnableReplayTracking: true,
			MaxClockSkew:         30 * time.Second,
		},
		DeviceBinding: DeviceBindingConfig{
			Enabled:                 false,
			EnforceIPBinding:        false,
			EnforceUserAgentBinding: false,
			DetectIPChange:          false,
			DetectUserAgentChange:   false,
		},
		TOTP: TOTPConfig{
			Enabled:                     false,
			Issuer:                      "",
			Digits:                      6,
			Period:                      30,
			Algorithm:                   "SHA1",
			Skew:                        1,
			EnforceReplayProtection:     true,
			MFALoginChallengeTTL:        3 * time.Minute,
			MFALoginMaxAttempts:         5,
			BackupCodeCount:             10,
			BackupCodeLength:            10,
			BackupCodeMaxAttempts:       5,
			BackupCodeCooldown:          10 * time.Minute,
			RequireForLogin:             false,
			RequireBackupForLogin:       false,
			RequireForSensitive:         false,
			RequireForPasswordReset:     false,
			RequireTOTPForPasswordReset: false,
		},
		MultiTenant: MultiTenantConfig{
			Enabled:          false,
			TenantHeader:     "X-Tenant-ID",
			EnforceIsolation: true,
		},
		Database: DatabaseConfig{
			MaxConnections:            25,
			MinConnections:            5,
			ConnMaxLifetime:           30 * time.Minute,
			PreparedStatementsEnabled: true,
		},
		Permission: PermissionConfig{
			MaxBits:         64,
			RootBitReserved: true,
		},
		Cache: CacheConfig{
			LRUEnabled: false,
			Size:       10000,
		},
		Result: ResultConfig{
			IncludeRole:        true,
			IncludePermissions: false,
		},
		ValidationMode: ModeHybrid,
	}
}

func cloneConfig(cfg Config) Config {
	out := cfg
	out.JWT.PrivateKey = cloneBytes(cfg.JWT.PrivateKey)
	out.JWT.PublicKey = cloneBytes(cfg.JWT.PublicKey)
	return out
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

/*
====================================
VALIDATION
====================================
*/

// Validate describes the validate operation and its observable behavior.
//
// Validate may return an error when input validation, dependency calls, or security checks fail.
// Validate does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (c *Config) Validate() error {
	// JWT
	if c.JWT.AccessTTL <= 0 {
		return errors.New("JWT AccessTTL must be > 0")
	}
	if c.JWT.RefreshTTL <= 0 {
		return errors.New("JWT RefreshTTL must be > 0")
	}

	if c.JWT.SigningMethod != "ed25519" && c.JWT.SigningMethod != "hs256" {
		return errors.New("unsupported JWT signing method")
	}

	if c.JWT.SigningMethod == "ed25519" && len(c.JWT.PrivateKey) == 0 {
		return errors.New("ed25519 requires PrivateKey")
	}
	if c.JWT.SigningMethod == "ed25519" && len(c.JWT.PublicKey) == 0 {
		return errors.New("ed25519 requires PublicKey")
	}
	if c.JWT.SigningMethod == "hs256" && len(c.JWT.PrivateKey) == 0 {
		return errors.New("hs256 requires PrivateKey")
	}

	// Session
	if c.Session.MaxSessionSize <= 0 {
		return errors.New("Session MaxSessionSize must be > 0")
	}

	if c.Session.AbsoluteSessionLifetime <= 0 {
		return errors.New("Session AbsoluteSessionLifetime must be > 0")
	}

	if c.Session.JitterRange < 0 {
		return errors.New("Session JitterRange must be >= 0")
	}
	if c.Session.JitterRange > time.Duration((math.MaxInt64-1)/2) {
		return errors.New("Session JitterRange is too large")
	}
	if c.Session.JitterEnabled && c.Session.JitterRange <= 0 {
		return errors.New("Session JitterRange must be > 0 when JitterEnabled is true")
	}

	if c.Session.SessionEncoding != "binary" && c.Session.SessionEncoding != "msgpack" {
		return errors.New("SessionEncoding must be 'binary' or 'msgpack'")
	}

	// Password
	if c.Password.Memory < 8*1024 {
		return errors.New("Password Memory must be >= 8192 KB")
	}
	if c.Password.Time < 1 {
		return errors.New("Password Time must be >= 1")
	}
	if c.Password.Parallelism < 1 {
		return errors.New("Password Parallelism must be >= 1")
	}
	if c.Password.SaltLength < 16 {
		return errors.New("Password SaltLength must be >= 16")
	}
	if c.Password.KeyLength < 16 {
		return errors.New("Password KeyLength must be >= 16")
	}

	// Password Reset
	if c.PasswordReset.Enabled {
		switch c.PasswordReset.Strategy {
		case ResetToken, ResetOTP, ResetUUID:
			// valid
		default:
			return errors.New("PasswordReset Strategy is invalid")
		}

		if c.PasswordReset.ResetTTL <= 0 {
			return errors.New("PasswordReset ResetTTL must be > 0")
		}
		if c.PasswordReset.MaxAttempts <= 0 {
			return errors.New("PasswordReset MaxAttempts must be > 0")
		}

		if c.PasswordReset.Strategy == ResetOTP {
			if c.PasswordReset.OTPDigits < 6 || c.PasswordReset.OTPDigits > 10 {
				return errors.New("PasswordReset OTPDigits must be between 6 and 10 in OTP mode")
			}
			if c.PasswordReset.MaxAttempts > 5 {
				return errors.New("PasswordReset MaxAttempts must be <= 5 in OTP mode")
			}
			if c.PasswordReset.ResetTTL > 15*time.Minute {
				return errors.New("PasswordReset ResetTTL must be <= 15m in OTP mode")
			}
			if !c.PasswordReset.EnableIPThrottle {
				return errors.New("PasswordReset EnableIPThrottle must be true in OTP mode")
			}
			if !c.PasswordReset.EnableIdentifierThrottle {
				return errors.New("PasswordReset EnableIdentifierThrottle must be true in OTP mode")
			}
		}
	}

	// Email Verification
	if c.EmailVerification.Enabled {
		switch c.EmailVerification.Strategy {
		case VerificationToken, VerificationOTP, VerificationUUID:
			// valid
		default:
			return errors.New("EmailVerification Strategy is invalid")
		}

		if c.EmailVerification.VerificationTTL <= 0 {
			return errors.New("EmailVerification VerificationTTL must be > 0")
		}
		if c.EmailVerification.MaxAttempts <= 0 {
			return errors.New("EmailVerification MaxAttempts must be > 0")
		}
		if c.EmailVerification.Strategy == VerificationOTP {
			if c.EmailVerification.OTPDigits < 6 || c.EmailVerification.OTPDigits > 10 {
				return errors.New("EmailVerification OTPDigits must be between 6 and 10 in OTP mode")
			}
			if c.EmailVerification.MaxAttempts > 5 {
				return errors.New("EmailVerification MaxAttempts must be <= 5 in OTP mode")
			}
			if c.EmailVerification.VerificationTTL > 15*time.Minute {
				return errors.New("EmailVerification VerificationTTL must be <= 15m in OTP mode")
			}
			if !c.EmailVerification.EnableIPThrottle {
				return errors.New("EmailVerification EnableIPThrottle must be true in OTP mode")
			}
			if !c.EmailVerification.EnableIdentifierThrottle {
				return errors.New("EmailVerification EnableIdentifierThrottle must be true in OTP mode")
			}
		}
	}
	if c.EmailVerification.RequireForLogin && !c.EmailVerification.Enabled {
		return errors.New("EmailVerification RequireForLogin requires EmailVerification Enabled")
	}

	// Audit
	if c.Audit.Enabled {
		if c.Audit.BufferSize <= 0 {
			return errors.New("Audit BufferSize must be > 0 when audit is enabled")
		}
	}

	// Account Creation
	if c.Account.Enabled {
		if c.Account.DefaultRole == "" {
			return errors.New("Account DefaultRole is required when account creation is enabled")
		}
		if !c.Account.EnableIPThrottle || !c.Account.EnableIdentifierThrottle {
			return errors.New("Account throttles must be enabled")
		}
		if c.Account.AccountCreationMaxAttempts <= 0 {
			return errors.New("Account AccountCreationMaxAttempts must be > 0")
		}
		if c.Account.AccountCreationCooldown <= 0 {
			return errors.New("Account AccountCreationCooldown must be > 0")
		}
		if c.Account.AutoLogin && c.JWT.RefreshTTL <= 0 {
			return errors.New("Account AutoLogin requires refresh system to be enabled")
		}
	}

	// Security
	if c.Security.MaxLoginAttempts <= 0 {
		return errors.New("MaxLoginAttempts must be > 0")
	}

	if c.Security.LoginCooldownDuration <= 0 {
		return errors.New("LoginCooldownDuration must be > 0")
	}
	if !c.Security.EnforceRefreshRotation {
		return errors.New("EnforceRefreshRotation must be true")
	}
	if !c.Security.EnforceRefreshReuseDetection {
		return errors.New("EnforceRefreshReuseDetection must be true")
	}
	if c.Security.EnableRefreshThrottle {
		if c.Security.MaxRefreshAttempts <= 0 {
			return errors.New("MaxRefreshAttempts must be > 0 when refresh throttle is enabled")
		}
		if c.Security.RefreshCooldownDuration <= 0 {
			return errors.New("RefreshCooldownDuration must be > 0 when refresh throttle is enabled")
		}
	}
	if c.SessionHardening.MaxSessionsPerUser < 0 {
		return errors.New("SessionHardening MaxSessionsPerUser must be >= 0")
	}
	if c.SessionHardening.MaxSessionsPerTenant < 0 {
		return errors.New("SessionHardening MaxSessionsPerTenant must be >= 0")
	}
	if c.SessionHardening.ConcurrentLoginLimit < 0 {
		return errors.New("SessionHardening ConcurrentLoginLimit must be >= 0")
	}
	if c.SessionHardening.MaxClockSkew < 0 {
		return errors.New("SessionHardening MaxClockSkew must be >= 0")
	}
	if !c.DeviceBinding.Enabled {
		// disabled mode is valid regardless of per-signal toggles
	} else if !c.DeviceBinding.EnforceIPBinding &&
		!c.DeviceBinding.EnforceUserAgentBinding &&
		!c.DeviceBinding.DetectIPChange &&
		!c.DeviceBinding.DetectUserAgentChange {
		return errors.New("DeviceBinding must enable at least one enforce or detect option when enabled")
	}
	if c.DeviceBinding.Enabled &&
		(c.DeviceBinding.EnforceIPBinding || c.DeviceBinding.EnforceUserAgentBinding) &&
		!c.DeviceBinding.DetectIPChange &&
		!c.DeviceBinding.DetectUserAgentChange {
		return errors.New("DeviceBinding enforce mode requires at least one detect option")
	}
	if c.TOTP.Enabled {
		if c.TOTP.Issuer == "" {
			return errors.New("TOTP Issuer is required when TOTP is enabled")
		}
		if c.TOTP.Digits != 6 && c.TOTP.Digits != 8 {
			return errors.New("TOTP Digits must be 6 or 8")
		}
		if c.TOTP.Period < 15 {
			return errors.New("TOTP Period must be >= 15 seconds")
		}
		if c.TOTP.Skew < 0 {
			return errors.New("TOTP Skew must be >= 0")
		}
		if c.TOTP.MFALoginChallengeTTL <= 0 {
			return errors.New("TOTP MFALoginChallengeTTL must be > 0")
		}
		if c.TOTP.MFALoginMaxAttempts <= 0 {
			return errors.New("TOTP MFALoginMaxAttempts must be > 0")
		}
		if c.TOTP.BackupCodeCount <= 0 {
			return errors.New("TOTP BackupCodeCount must be > 0")
		}
		if c.TOTP.BackupCodeLength <= 0 {
			return errors.New("TOTP BackupCodeLength must be > 0")
		}
		if c.TOTP.BackupCodeMaxAttempts <= 0 {
			return errors.New("TOTP BackupCodeMaxAttempts must be > 0")
		}
		if c.TOTP.BackupCodeCooldown <= 0 {
			return errors.New("TOTP BackupCodeCooldown must be > 0")
		}
		switch strings.ToUpper(c.TOTP.Algorithm) {
		case "", "SHA1", "SHA256", "SHA512":
			// valid (empty treated as SHA1)
		default:
			return errors.New("TOTP Algorithm must be SHA1, SHA256, or SHA512")
		}
	}
	if c.TOTP.RequireForLogin && !c.TOTP.Enabled {
		return errors.New("TOTP RequireForLogin requires TOTP Enabled")
	}
	if c.TOTP.RequireBackupForLogin && !c.TOTP.Enabled {
		return errors.New("TOTP RequireBackupForLogin requires TOTP Enabled")
	}

	switch c.ValidationMode {
	case ModeJWTOnly, ModeHybrid, ModeStrict:
		// valid
	default:
		return errors.New("invalid ValidationMode")
	}
	if c.ValidationMode == ModeJWTOnly {
		if c.DeviceBinding.EnforceIPBinding || c.DeviceBinding.EnforceUserAgentBinding {
			return errors.New("JWTOnly mode cannot enforce device binding")
		}
		if c.Security.EnableAccountVersionCheck {
			return errors.New("JWTOnly mode cannot enforce AccountVersion checks")
		}
	}

	if c.Security.ProductionMode {
		if c.JWT.AccessTTL > 15*time.Minute {
			return errors.New("ProductionMode requires JWT AccessTTL <= 15m")
		}
		if c.JWT.RefreshTTL > 30*24*time.Hour {
			return errors.New("ProductionMode requires JWT RefreshTTL <= 30d")
		}
		if c.JWT.SigningMethod == "hs256" && len(c.JWT.PrivateKey) < 32 {
			return errors.New("ProductionMode requires hs256 key length >= 256 bits")
		}
		if c.Password.Memory < 64*1024 {
			return errors.New("ProductionMode requires Password Memory >= 65536 KB")
		}
		if c.Password.Time < 2 {
			return errors.New("ProductionMode requires Password Time >= 2")
		}
		if c.Password.Parallelism < 1 {
			return errors.New("ProductionMode requires Password Parallelism >= 1")
		}
		if c.Password.KeyLength < 32 {
			return errors.New("ProductionMode requires Password KeyLength >= 32")
		}
		if c.Password.SaltLength < 16 {
			return errors.New("ProductionMode requires Password SaltLength >= 16")
		}
		if c.TOTP.Enabled {
			if c.TOTP.Digits < 6 {
				return errors.New("ProductionMode requires TOTP Digits >= 6")
			}
			if c.TOTP.Period > 60 {
				return errors.New("ProductionMode requires TOTP Period <= 60")
			}
			if c.TOTP.Skew > 2 {
				return errors.New("ProductionMode requires TOTP Skew <= 2")
			}
			if !c.TOTP.EnforceReplayProtection {
				return errors.New("ProductionMode requires TOTP EnforceReplayProtection")
			}
			if c.TOTP.BackupCodeCount < 8 {
				return errors.New("ProductionMode requires TOTP BackupCodeCount >= 8")
			}
			if c.TOTP.BackupCodeLength < 8 {
				return errors.New("ProductionMode requires TOTP BackupCodeLength >= 8")
			}
			if c.TOTP.BackupCodeMaxAttempts <= 0 || c.TOTP.BackupCodeCooldown <= 0 {
				return errors.New("ProductionMode requires backup code limiter configuration")
			}
		}
		if c.PasswordReset.Enabled && c.PasswordReset.Strategy == ResetOTP {
			if c.PasswordReset.ResetTTL > 15*time.Minute {
				return errors.New("ProductionMode requires PasswordReset ResetTTL <= 15m in OTP mode")
			}
			if c.PasswordReset.MaxAttempts > 5 {
				return errors.New("ProductionMode requires PasswordReset MaxAttempts <= 5 in OTP mode")
			}
			if !c.PasswordReset.EnableIPThrottle || !c.PasswordReset.EnableIdentifierThrottle {
				return errors.New("ProductionMode requires PasswordReset throttles in OTP mode")
			}
		}
		if c.EmailVerification.Enabled && c.EmailVerification.Strategy == VerificationOTP {
			if c.EmailVerification.VerificationTTL > 15*time.Minute {
				return errors.New("ProductionMode requires EmailVerification VerificationTTL <= 15m in OTP mode")
			}
			if c.EmailVerification.MaxAttempts > 5 {
				return errors.New("ProductionMode requires EmailVerification MaxAttempts <= 5 in OTP mode")
			}
			if !c.EmailVerification.EnableIPThrottle || !c.EmailVerification.EnableIdentifierThrottle {
				return errors.New("ProductionMode requires EmailVerification throttles in OTP mode")
			}
		}
	}

	// Permission
	switch c.Permission.MaxBits {
	case 64, 128, 256, 512:
		// valid
	default:
		return errors.New("Permission MaxBits must be 64, 128, 256, or 512")
	}

	// Cache
	if c.Cache.LRUEnabled && c.Cache.Size <= 0 {
		return errors.New("Cache Size must be > 0 when LRUEnabled is true")
	}

	return nil
}
