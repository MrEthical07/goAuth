package goAuth

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/rate"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/MrEthical07/goAuth/jwt"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// Builder constructs an [Engine] through a fluent API. Call [New] to start,
// chain With* methods, then call [Builder.Build] to validate configuration
// and produce an immutable Engine. A Builder can only be built once.
//
//	Docs: docs/engine.md, docs/usage.md
type Builder struct {
	config Config
	redis  redis.UniversalClient

	permissions []string
	roles       map[string][]string

	userProvider UserProvider
	auditSink    AuditSink

	built bool
}

// New creates a fresh [Builder] initialized with [DefaultConfig].
//
//	Docs: docs/engine.md, docs/usage.md
func New() *Builder {
	return &Builder{
		config: defaultConfig(),
	}
}

// WithConfig replaces the builder’s configuration. The provided Config is
// deep-copied; later mutations to the caller’s copy have no effect.
//
//	Docs: docs/config.md
func (b *Builder) WithConfig(cfg Config) *Builder {
	b.config = cloneConfig(cfg)
	return b
}

// WithRedis sets the Redis client used for sessions, rate limiting, and
// all Redis-backed stores. Required for all validation modes.
//
//	Docs: docs/config.md, docs/session.md
func (b *Builder) WithRedis(client redis.UniversalClient) *Builder {
	b.redis = client
	return b
}

// WithPermissions registers the permission names that will be mapped to
// bitmask bits. Order determines bit assignment.
//
//	Docs: docs/permission.md
func (b *Builder) WithPermissions(perms []string) *Builder {
	b.permissions = perms
	return b
}

// WithRoles registers role names and their associated permission lists.
// Each role gets a pre-computed bitmask at build time.
//
//	Docs: docs/permission.md
func (b *Builder) WithRoles(r map[string][]string) *Builder {
	b.roles = r
	return b
}

// WithUserProvider sets the [UserProvider] implementation that the engine
// uses for credential lookup, account creation, TOTP storage, etc.
//
//	Docs: docs/engine.md
func (b *Builder) WithUserProvider(up UserProvider) *Builder {
	b.userProvider = up
	return b
}

// WithAuditSink sets the [AuditSink] that receives structured audit events.
// Pass nil only when audit is disabled in config.
//
//	Docs: docs/audit.md
func (b *Builder) WithAuditSink(sink AuditSink) *Builder {
	b.auditSink = sink
	return b
}

// WithMetricsEnabled enables or disables the in-process metrics counters.
// When disabled, MetricsSnapshot returns zero values.
//
//	Docs: docs/metrics.md
func (b *Builder) WithMetricsEnabled(enabled bool) *Builder {
	b.config.Metrics.Enabled = enabled
	return b
}

// WithLatencyHistograms enables per-operation latency histograms inside
// the metrics subsystem. Adds a small allocation overhead per tracked op.
//
//	Docs: docs/metrics.md
func (b *Builder) WithLatencyHistograms(enabled bool) *Builder {
	b.config.Metrics.EnableLatencyHistograms = enabled
	return b
}

// Build validates the accumulated configuration, initializes every
// subsystem (JWT manager, session store, rate limiters, TOTP manager,
// password hasher, audit dispatcher, permission registry, role manager),
// and returns an immutable [Engine] ready for concurrent use.
//
// Build may only be called once per Builder instance.
//
//	Docs: docs/engine.md, docs/config.md, docs/usage.md
func (b *Builder) Build() (*Engine, error) {
	if b.built {
		return nil, errors.New("builder already used")
	}

	cfg := cloneConfig(b.config)

	if b.redis == nil {
		if cfg.ValidationMode == ModeStrict {
			return nil, errors.New("Strict mode requires redis client")
		}
		if cfg.SessionHardening.MaxSessionsPerUser > 0 ||
			cfg.SessionHardening.MaxSessionsPerTenant > 0 ||
			cfg.SessionHardening.EnforceSingleSession ||
			cfg.SessionHardening.ConcurrentLoginLimit > 0 {
			return nil, errors.New("SessionHardening requires redis client")
		}
		return nil, errors.New("redis client required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Freeze the effective session ceiling: an unset MaxSessionDuration
	// resolves to its per-mode default here so runtime paths never see zero.
	cfg.Session.MaxSessionDuration = cfg.resolvedMaxSessionDuration()

	if len(b.permissions) == 0 {
		return nil, errors.New("permissions must be provided")
	}

	if len(b.roles) == 0 {
		return nil, errors.New("roles must be provided")
	}

	if b.userProvider == nil {
		return nil, errors.New("user provider required")
	}
	if cfg.Audit.Enabled && b.auditSink == nil {
		return nil, errors.New("audit sink required when audit is enabled")
	}

	// -------- PERMISSION REGISTRY --------
	registry, err := permission.NewRegistry(
		cfg.Permission.MaxBits,
		cfg.Permission.RootBitReserved,
	)
	if err != nil {
		return nil, err
	}

	for _, p := range b.permissions {
		if _, err := registry.Register(p); err != nil {
			return nil, err
		}
	}

	registry.Freeze()

	// -------- ROLE MANAGER --------
	roleManager := permission.NewRoleManager(registry)

	for roleName, permList := range b.roles {
		if err := roleManager.RegisterRole(
			roleName,
			permList,
			cfg.Permission.MaxBits,
			cfg.Permission.RootBitReserved,
		); err != nil {
			return nil, err
		}
	}

	roleManager.Freeze()

	if cfg.Account.Enabled {
		if _, ok := roleManager.GetMask(cfg.Account.DefaultRole); !ok {
			return nil, errors.New("Account DefaultRole does not exist in role manager")
		}
		if cfg.Account.AutoLogin && cfg.JWT.RefreshTTL <= 0 {
			return nil, errors.New("Account AutoLogin requires refresh system to be enabled")
		}
	}

	// -------- SESSION STORE --------
	store := session.NewStore(
		b.redis,
		cfg.Session.RedisPrefix,
		cfg.Session.SlidingExpiration,
		cfg.Session.JitterEnabled,
		cfg.Session.JitterRange,
	)

	engine := &Engine{
		config:       cloneConfig(cfg),
		registry:     registry,
		roleManager:  roleManager,
		sessionStore: store,
	}

	windowMode := window.Fixed
	if cfg.Security.LimiterWindowMode == "sliding" {
		windowMode = window.Sliding
	}

	engine.userProvider = b.userProvider
	engine.rateLimiter = rate.New(b.redis, rate.Config{
		EnableLoginFailureLimiter: cfg.Security.EnableLoginFailureLimiter,
		MaxLoginAttempts:          cfg.Security.MaxLoginAttempts,
		LoginCooldownDuration:     cfg.Security.LoginCooldownDuration,
		WindowMode:                windowMode,
	})
	engine.resetStore = stores.NewPasswordResetStore(b.redis, "apr")
	engine.resetLimiter = limiters.NewPasswordResetLimiter(b.redis, limiters.PasswordResetConfig{
		EnableRequestLimiter:        cfg.PasswordReset.EnableRequestLimiter,
		EnableConfirmFailureLimiter: cfg.PasswordReset.EnableConfirmFailureLimiter,
		ResetTTL:                    cfg.PasswordReset.ResetTTL,
		MaxAttempts:                 cfg.PasswordReset.MaxAttempts,
		WindowMode:                  windowMode,
	})
	engine.verificationStore = stores.NewEmailVerificationStore(b.redis, "apv")
	engine.verificationLimiter = limiters.NewEmailVerificationLimiter(b.redis, limiters.EmailVerificationConfig{
		EnableRequestLimiter:        cfg.EmailVerification.EnableRequestLimiter,
		EnableConfirmFailureLimiter: cfg.EmailVerification.EnableConfirmFailureLimiter,
		VerificationTTL:             cfg.EmailVerification.VerificationTTL,
		MaxAttempts:                 cfg.EmailVerification.MaxAttempts,
		WindowMode:                  windowMode,
	})
	engine.accountLimiter = limiters.NewAccountCreationLimiter(b.redis, limiters.AccountConfig{
		EnableLimiter: cfg.Account.EnableCreationLimiter,
		MaxAttempts:   cfg.Account.AccountCreationMaxAttempts,
		Cooldown:      cfg.Account.AccountCreationCooldown,
		WindowMode:    windowMode,
	})
	engine.totpLimiter = limiters.NewTOTPLimiter(b.redis, limiters.TOTPLimiterConfig{
		// Direct TOTP verification paths share the MFA attempt budget.
		MaxAttempts: cfg.TOTP.MFALoginMaxAttempts,
		Cooldown:    cfg.TOTP.VerifyAttemptCooldown,
		WindowMode:  windowMode,
	})
	engine.backupLimiter = limiters.NewBackupCodeLimiter(b.redis, limiters.BackupCodeConfig{
		MaxAttempts: cfg.TOTP.BackupCodeMaxAttempts,
		Cooldown:    cfg.TOTP.BackupCodeCooldown,
		WindowMode:  windowMode,
	})
	engine.lockoutLimiter = limiters.NewLockoutLimiter(b.redis, limiters.LockoutConfig{
		Enabled:    cfg.Security.AutoLockoutEnabled,
		Threshold:  cfg.Security.AutoLockoutThreshold,
		Duration:   cfg.Security.AutoLockoutDuration,
		WindowMode: windowMode,
	})
	engine.mfaLoginStore = stores.NewMFALoginChallengeStore(b.redis, "amc")
	if cfg.WebAuthn.Enabled {
		provider, ok := b.userProvider.(WebAuthnCredentialProvider)
		if !ok {
			return nil, errors.New("WebAuthn is enabled but the user provider does not implement WebAuthnCredentialProvider")
		}
		rp, err := newWebAuthnRP(cfg.WebAuthn)
		if err != nil {
			return nil, fmt.Errorf("invalid WebAuthn configuration: %w", err)
		}
		engine.webauthnRP = rp
		engine.webauthnProvider = provider
		engine.webauthnSessions = stores.NewWebAuthnSessionStore(b.redis, "awn")
	}
	engine.audit = newAuditDispatcher(cfg.Audit, b.auditSink)
	engine.metrics = NewMetrics(cfg.Metrics)
	engine.totp = newTOTPManager(cfg.TOTP)
	engine.logger = cfg.Logger

	ph, err := password.NewArgon2(password.Config{
		Memory:      cfg.Password.Memory,
		Time:        cfg.Password.Time,
		Parallelism: cfg.Password.Parallelism,
		SaltLength:  cfg.Password.SaltLength,
		KeyLength:   cfg.Password.KeyLength,
	})
	if err != nil {
		return nil, err
	}
	engine.passwordHash = ph

	jm, err := jwt.NewManager(jwt.Config{
		AccessTTL:     cfg.JWT.AccessTTL,
		SigningMethod: jwt.SigningMethod(cfg.JWT.SigningMethod),
		PrivateKey:    cloneBytes(cfg.JWT.PrivateKey),
		PublicKey:     cloneBytes(cfg.JWT.PublicKey),
		Issuer:        cfg.JWT.Issuer,
		Audience:      cfg.JWT.Audience,
		Leeway:        cfg.JWT.Leeway,
		RequireIAT:    cfg.JWT.RequireIAT,
		MaxFutureIAT:  cfg.JWT.MaxFutureIAT,
		KeyID:         cfg.JWT.KeyID,
		VerifyKeys:    cloneVerifyKeys(cfg.JWT.VerifyKeys),
	})
	if err != nil {
		return nil, err
	}
	engine.jwtManager = jm
	engine.initFlowDeps()

	b.built = true

	return engine, nil
}

// newWebAuthnRP builds the relying-party handle from the frozen config.
// Validation of enum values happened in Config.Validate; empty strings fall
// back to the documented defaults here.
func newWebAuthnRP(cfg WebAuthnConfig) (*webauthn.WebAuthn, error) {
	attestation := cfg.AttestationPreference
	if attestation == "" {
		attestation = "none"
	}
	userVerification := cfg.UserVerification
	if userVerification == "" {
		userVerification = "preferred"
	}
	ceremonyTTL := cfg.CeremonyTTL
	if ceremonyTTL <= 0 {
		ceremonyTTL = 2 * time.Minute
	}
	timeout := webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    ceremonyTTL,
		TimeoutUVD: ceremonyTTL,
	}
	return webauthn.New(&webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cloneStrings(cfg.RPOrigins),
		AttestationPreference: protocol.ConveyancePreference(attestation),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.UserVerificationRequirement(userVerification),
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        timeout,
			Registration: timeout,
		},
	})
}
