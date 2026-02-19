package goAuth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"
)

// Config is the top-level configuration struct for the goAuth [Engine].
// It embeds sub-configs for JWT, sessions, passwords, MFA, rate limiting,
// audit, metrics, and more. Obtain defaults via [DefaultConfig].
//
//	Docs: docs/config.md
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
	Logger            *slog.Logger
	ValidationMode    ValidationMode
}

/*
====================================
JWT CONFIG
====================================
*/

// JWTConfig controls JWT access token signing and validation parameters.
//
//	Docs: docs/jwt.md, docs/config.md
type JWTConfig struct {
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	SigningMethod string // "ed25519" (default), "hs256" optional
	PrivateKey    []byte
	PublicKey     []byte
	Issuer        string
	Audience      string
	Leeway        time.Duration
	RequireIAT    bool
	MaxFutureIAT  time.Duration
	KeyID         string
}

/*
====================================
SESSION CONFIG
====================================
*/

// SessionConfig controls Redis session storage, sliding expiration, and jitter.
//
//	Docs: docs/session.md, docs/config.md
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

// PasswordConfig holds Argon2id hashing parameters.
//
//	Docs: docs/password.md, docs/config.md
type PasswordConfig struct {
	Memory         uint32 // in KB
	Time           uint32
	Parallelism    uint8
	SaltLength     uint32
	KeyLength      uint32
	UpgradeOnLogin bool
}

// ResetStrategyType selects the password-reset challenge delivery strategy
// (link-based or OTP-based).
//
//	Docs: docs/password_reset.md
type ResetStrategyType int

const (
	// ResetToken is an exported constant or variable used by the authentication engine.
	ResetToken ResetStrategyType = iota
	// ResetOTP is an exported constant or variable used by the authentication engine.
	ResetOTP
	// ResetUUID is an exported constant or variable used by the authentication engine.
	ResetUUID
)

// PasswordResetConfig controls the password-reset flow: strategy, TTLs,
// rate limits, and attempt caps.
//
//	Docs: docs/password_reset.md, docs/config.md
type PasswordResetConfig struct {
	Enabled                  bool
	Strategy                 ResetStrategyType
	ResetTTL                 time.Duration
	MaxAttempts              int
	EnableIPThrottle         bool
	EnableIdentifierThrottle bool
	OTPDigits                int
}

// VerificationStrategyType selects the email verification challenge strategy
// (link-based or OTP-based).
//
//	Docs: docs/email_verification.md
type VerificationStrategyType int

const (
	// VerificationToken is an exported constant or variable used by the authentication engine.
	VerificationToken VerificationStrategyType = iota
	// VerificationOTP is an exported constant or variable used by the authentication engine.
	VerificationOTP
	// VerificationUUID is an exported constant or variable used by the authentication engine.
	VerificationUUID
)

// EmailVerificationConfig controls the email verification flow.
//
//	Docs: docs/email_verification.md, docs/config.md
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

// AccountConfig controls account creation, auto-login, default role, and
// rate limiting.
//
//	Docs: docs/config.md
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

// AuditConfig controls the audit event dispatcher: enable/disable,
// buffer size, and overflow policy.
//
//	Docs: docs/audit.md, docs/config.md
type AuditConfig struct {
	Enabled    bool
	BufferSize int
	DropIfFull bool
}

// MetricsConfig controls in-process metrics: counters and optional latency
// histograms.
//
//	Docs: docs/metrics.md, docs/config.md
type MetricsConfig struct {
	Enabled                 bool
	EnableLatencyHistograms bool
}

/*
====================================
SECURITY CONFIG
====================================
*/

// SecurityConfig holds security-related settings: rate limits, lockout,
// refresh rotation, version checking, and production mode flags.
//
//	Docs: docs/security.md, docs/config.md
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
	AutoLockoutEnabled           bool
	AutoLockoutThreshold         int
	AutoLockoutDuration          time.Duration // 0 = manual unlock only
}

// SessionHardeningConfig controls session limits: max per user/tenant,
// single-session enforcement, concurrent login caps, replay tracking,
// and clock-skew tolerance.
//
//	Docs: docs/session.md, docs/config.md
type SessionHardeningConfig struct {
	MaxSessionsPerUser   int
	MaxSessionsPerTenant int
	EnforceSingleSession bool
	ConcurrentLoginLimit int
	EnableReplayTracking bool
	MaxClockSkew         time.Duration
}

// DeviceBindingConfig controls IP and User-Agent binding checks on
// session validation.
//
//	Docs: docs/device_binding.md, docs/config.md
type DeviceBindingConfig struct {
	Enabled                 bool
	EnforceIPBinding        bool
	EnforceUserAgentBinding bool
	DetectIPChange          bool
	DetectUserAgentChange   bool
}

// TOTPConfig controls TOTP-based two-factor authentication: issuer,
// period, digits, algorithm, skew, backup codes, and enforcement flags.
//
//	Docs: docs/mfa.md, docs/config.md
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

	// MaxVerifyAttempts is the maximum number of TOTP verification
	// attempts before rate limiting kicks in. Default: 5.
	MaxVerifyAttempts int

	// VerifyAttemptCooldown is the window after the first failed attempt
	// in which MaxVerifyAttempts are counted. Default: 1m.
	VerifyAttemptCooldown time.Duration
}

/*
====================================
MULTI TENANT CONFIG
====================================
*/

// MultiTenantConfig enables tenant-scoped session isolation.
//
//	Docs: docs/config.md
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

// DatabaseConfig holds Redis connection parameters (currently unused;
// prefer [Builder.WithRedis]).
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

// PermissionConfig controls the bitmask RBAC system: max bits, root-bit
// reservation, and versioning.
//
//	Docs: docs/permission.md, docs/config.md
type PermissionConfig struct {
	MaxBits         int  // 64, 128, 256, 512 (hard cap)
	RootBitReserved bool // if true, highest bit is root/super admin
}

/*
====================================
CACHE CONFIG
====================================
*/

// CacheConfig controls optional in-memory caching of session data.
type CacheConfig struct {
	LRUEnabled bool
	Size       int
}

// ResultConfig controls what data is included in [AuthResult] returned
// by [Engine.Validate].
type ResultConfig struct {
	IncludeRole        bool
	IncludePermissions bool
}

// ValidationMode determines how access tokens are validated: JWTOnly
// (0 Redis), Hybrid, or Strict (1 Redis GET).
//
//	Docs: docs/jwt.md, docs/engine.md
type ValidationMode int

const (
	// ModeInherit is an exported constant or variable used by the authentication engine.
	ModeInherit ValidationMode = -1

	// ModeJWTOnly validates access tokens using JWT claims only (no Redis access in validation path).
	ModeJWTOnly ValidationMode = iota
	// ModeHybrid validates by JWT by default; strict routes can still force Redis-backed checks.
	ModeHybrid
	// ModeStrict validates every request against Redis and fails closed on Redis/session errors.
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
			Leeway:        30 * time.Second,
			RequireIAT:    false,
			MaxFutureIAT:  10 * time.Minute,
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
			AutoLockoutEnabled:           false,
			AutoLockoutThreshold:         10,
			AutoLockoutDuration:          30 * time.Minute,
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
			MaxVerifyAttempts:           5,
			VerifyAttemptCooldown:       time.Minute,
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
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		ValidationMode: ModeHybrid,
	}
}

// DefaultConfig returns a production-safe baseline preset.
//
// The preset keeps hybrid validation, refresh rotation/reuse enforcement, and
// Ed25519 signing. It also generates an ephemeral signing keypair so the result
// validates without additional key wiring.
func DefaultConfig() Config {
	cfg := defaultConfig()
	applyPresetBase(&cfg)
	return cfg
}

// HighSecurityConfig returns a strict preset for security-critical deployments.
//
// This preset enables strict validation mode and tighter token/rate-limiter
// windows, and enforces iat presence.
func HighSecurityConfig() Config {
	cfg := DefaultConfig()

	cfg.Security.ProductionMode = true
	cfg.ValidationMode = ModeStrict
	cfg.Security.StrictMode = true

	cfg.JWT.RequireIAT = true
	cfg.JWT.AccessTTL = 5 * time.Minute
	cfg.JWT.RefreshTTL = 24 * time.Hour
	cfg.Session.AbsoluteSessionLifetime = 24 * time.Hour

	cfg.Security.EnableIPThrottle = true
	cfg.Security.MaxLoginAttempts = 3
	cfg.Security.LoginCooldownDuration = 15 * time.Minute
	cfg.Security.MaxRefreshAttempts = 10
	cfg.Security.RefreshCooldownDuration = 2 * time.Minute

	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.DeviceBinding.DetectUserAgentChange = true
	cfg.DeviceBinding.EnforceUserAgentBinding = true

	return cfg
}

// HighThroughputConfig returns a preset optimized for higher sustained request
// volume while keeping security defaults intact.
//
// It keeps Hybrid validation as the global mode; callers can use per-route
// `ModeJWTOnly` where immediate revocation is not required.
func HighThroughputConfig() Config {
	cfg := DefaultConfig()

	cfg.Security.ProductionMode = true
	cfg.ValidationMode = ModeHybrid

	cfg.JWT.AccessTTL = 15 * time.Minute
	cfg.JWT.RefreshTTL = 14 * 24 * time.Hour
	cfg.Session.AbsoluteSessionLifetime = 14 * 24 * time.Hour

	cfg.Security.EnableIPThrottle = false
	cfg.Security.MaxRefreshAttempts = 60
	cfg.Security.RefreshCooldownDuration = 1 * time.Minute

	return cfg
}

func applyPresetBase(cfg *Config) {
	cfg.Account.Enabled = false
	cfg.Account.DefaultRole = ""
	ensureEd25519Keys(cfg)
}

func ensureEd25519Keys(cfg *Config) {
	if cfg.JWT.SigningMethod != "ed25519" {
		return
	}
	if len(cfg.JWT.PrivateKey) > 0 && len(cfg.JWT.PublicKey) > 0 {
		return
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	cfg.JWT.PrivateKey = cloneBytes(privateKey)
	cfg.JWT.PublicKey = cloneBytes(publicKey)
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

// Validate checks the Config for invalid or contradictory settings.
// It is called automatically by [Builder.Build].
//
//	Docs: docs/config.md
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
	if c.JWT.Leeway < 0 {
		return errors.New("JWT Leeway must be >= 0")
	}
	if c.JWT.Leeway > 2*time.Minute {
		return errors.New("JWT Leeway must be <= 2m")
	}
	if c.JWT.MaxFutureIAT < 0 {
		return errors.New("JWT MaxFutureIAT must be >= 0")
	}
	if c.JWT.MaxFutureIAT > 24*time.Hour {
		return errors.New("JWT MaxFutureIAT must be <= 24h")
	}
	if c.JWT.Audience != "" && strings.TrimSpace(c.JWT.Audience) == "" {
		return errors.New("JWT Audience must not be empty when configured")
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
	if c.Security.AutoLockoutEnabled {
		if c.Security.AutoLockoutThreshold <= 0 {
			return errors.New("AutoLockoutThreshold must be > 0 when AutoLockoutEnabled")
		}
		if c.Security.AutoLockoutDuration < 0 {
			return errors.New("AutoLockoutDuration must be >= 0")
		}
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

// LintSeverity classifies the importance of a lint warning.
type LintSeverity int

const (
	// LintInfo is advisory only — no action required.
	LintInfo LintSeverity = iota
	// LintWarn indicates a configuration that may be sub-optimal in production.
	LintWarn
	// LintHigh indicates a configuration that is dangerous or contradictory.
	LintHigh
)

// String returns a human-readable severity tag.
func (s LintSeverity) String() string {
	switch s {
	case LintInfo:
		return "INFO"
	case LintWarn:
		return "WARN"
	case LintHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// LintWarning represents a single advisory warning from Config.Lint().
// It contains a short code for programmatic matching, a severity level,
// and a human-readable message.
type LintWarning struct {
	Code     string       // e.g., "leeway_large", "access_ttl_long"
	Severity LintSeverity // INFO, WARN, or HIGH
	Message  string
}

// LintResult wraps a slice of LintWarning with helper methods for filtering
// and promotion to errors.
type LintResult []LintWarning

// AsError returns an error if any warning meets or exceeds minSeverity.
// Returns nil if no warnings meet the threshold. Useful for teams that want
// to fail startup on high-severity configuration issues:
//
//	if err := cfg.Lint().AsError(goAuth.LintHigh); err != nil {
//	    log.Fatalf("config lint: %v", err)
//	}
func (lr LintResult) AsError(minSeverity LintSeverity) error {
	var msgs []string
	for _, w := range lr {
		if w.Severity >= minSeverity {
			msgs = append(msgs, "["+w.Severity.String()+"] "+w.Code+": "+w.Message)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New("config lint failures:\n" + strings.Join(msgs, "\n"))
}

// BySeverity returns only warnings at or above the given severity.
func (lr LintResult) BySeverity(minSeverity LintSeverity) LintResult {
	var filtered LintResult
	for _, w := range lr {
		if w.Severity >= minSeverity {
			filtered = append(filtered, w)
		}
	}
	return filtered
}

// Codes returns the warning codes as a string slice (for test assertions).
func (lr LintResult) Codes() []string {
	codes := make([]string, len(lr))
	for i, w := range lr {
		codes[i] = w.Code
	}
	return codes
}

// Lint returns advisory warnings for configurations that are technically valid
// but potentially dangerous in production. Unlike Validate(), Lint() never
// rejects a config — it only surfaces things worth reviewing.
//
// Each warning has a stable code and a severity level (INFO/WARN/HIGH).
// Use the returned LintResult helpers to filter or promote to errors:
//
//	for _, w := range cfg.Lint() {
//	    slog.Warn("config lint", "code", w.Code, "severity", w.Severity.String(), "msg", w.Message)
//	}
//
//	// Fail startup on HIGH severity:
//	if err := cfg.Lint().AsError(goAuth.LintHigh); err != nil {
//	    log.Fatalf("config lint: %v", err)
//	}
func (c *Config) Lint() LintResult {
	var ws LintResult
	warn := func(sev LintSeverity, code, msg string) {
		ws = append(ws, LintWarning{Code: code, Severity: sev, Message: msg})
	}

	// --- JWT ---
	if c.JWT.Leeway > 1*time.Minute {
		warn(LintWarn, "leeway_large",
			"JWT Leeway > 1m widens the token acceptance window; consider ≤ 30s")
	}

	if c.JWT.AccessTTL > 10*time.Minute {
		warn(LintWarn, "access_ttl_long",
			"JWT AccessTTL > 10m increases the exposure window for stolen tokens")
	}

	if c.JWT.RefreshTTL > 14*24*time.Hour {
		warn(LintInfo, "refresh_ttl_long",
			"JWT RefreshTTL > 14d means long-lived sessions; consider ≤ 7–14d")
	}

	if !c.JWT.RequireIAT {
		warn(LintInfo, "iat_not_required",
			"JWT RequireIAT is false; pre-dated tokens will be accepted")
	}

	if c.JWT.SigningMethod == "hs256" {
		warn(LintWarn, "signing_hs256",
			"HS256 signing is supported but Ed25519 provides better security properties")
	}

	// --- Validation mode contradictions ---
	if c.ValidationMode == ModeJWTOnly && c.DeviceBinding.Enabled {
		warn(LintHigh, "jwtonly_device_binding",
			"ValidationMode is JWTOnly but DeviceBinding is enabled; device checks require Redis session access and will not execute in JWTOnly mode")
	}

	if c.ValidationMode == ModeJWTOnly && c.SessionHardening.EnforceSingleSession {
		warn(LintHigh, "jwtonly_single_session",
			"ValidationMode is JWTOnly but EnforceSingleSession is enabled; session limits require Redis")
	}

	if c.ValidationMode == ModeJWTOnly && c.Security.EnablePermissionVersionCheck {
		warn(LintWarn, "jwtonly_perm_version",
			"ValidationMode is JWTOnly with PermissionVersionCheck; version checks use embedded claim values only and won't catch real-time revocations")
	}

	// --- Rate limiting ---
	if !c.Security.EnableIPThrottle && !c.Security.EnableRefreshThrottle {
		warn(LintHigh, "rate_limits_disabled",
			"Both IP throttle and refresh throttle are disabled; public endpoints are unprotected from brute-force")
	}

	if !c.Security.EnableIPThrottle {
		warn(LintWarn, "ip_throttle_disabled",
			"IP throttle is disabled; login endpoints are vulnerable to distributed brute-force")
	}

	// --- Session ---
	if c.Session.AbsoluteSessionLifetime > 30*24*time.Hour {
		warn(LintWarn, "session_lifetime_long",
			"AbsoluteSessionLifetime > 30d is unusually long; consider shorter sessions")
	}

	if c.Session.AbsoluteSessionLifetime < c.JWT.RefreshTTL {
		warn(LintHigh, "session_shorter_than_refresh",
			"AbsoluteSessionLifetime < RefreshTTL; sessions will expire before refresh tokens, causing unexpected refresh failures")
	}

	// --- Production readiness ---
	if !c.Security.ProductionMode {
		warn(LintInfo, "not_production_mode",
			"ProductionMode is false; some security constraints are relaxed")
	}

	if !c.Audit.Enabled {
		warn(LintWarn, "audit_disabled",
			"Audit is disabled; security events will not be recorded")
	}

	// --- TOTP ---
	if c.TOTP.Enabled && c.TOTP.Skew > 1 {
		warn(LintWarn, "totp_skew_wide",
			"TOTP Skew > 1 accepts codes from a wider time window; consider Skew=1 for tighter security")
	}

	// --- Password ---
	if c.Password.Memory < 64*1024 {
		warn(LintWarn, "argon2_memory_low",
			"Argon2 Memory < 64 MB is below OWASP recommended minimum")
	}

	return ws
}
