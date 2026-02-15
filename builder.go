package goAuth

import (
	"errors"

	"github.com/MrEthical07/goAuth/internal/rate"
	"github.com/MrEthical07/goAuth/jwt"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// Builder defines a public type used by goAuth APIs.
//
// Builder instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Builder struct {
	config Config
	redis  *redis.Client

	permissions []string
	roles       map[string][]string

	userProvider UserProvider
	auditSink    AuditSink

	built bool
}

// New describes the new operation and its observable behavior.
//
// New may return an error when input validation, dependency calls, or security checks fail.
// New does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func New() *Builder {
	return &Builder{
		config: defaultConfig(),
	}
}

// WithConfig describes the withconfig operation and its observable behavior.
//
// WithConfig may return an error when input validation, dependency calls, or security checks fail.
// WithConfig does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithConfig(cfg Config) *Builder {
	b.config = cloneConfig(cfg)
	return b
}

// WithRedis describes the withredis operation and its observable behavior.
//
// WithRedis may return an error when input validation, dependency calls, or security checks fail.
// WithRedis does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithRedis(client *redis.Client) *Builder {
	b.redis = client
	return b
}

// WithPermissions describes the withpermissions operation and its observable behavior.
//
// WithPermissions may return an error when input validation, dependency calls, or security checks fail.
// WithPermissions does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithPermissions(perms []string) *Builder {
	b.permissions = perms
	return b
}

// WithRoles describes the withroles operation and its observable behavior.
//
// WithRoles may return an error when input validation, dependency calls, or security checks fail.
// WithRoles does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithRoles(r map[string][]string) *Builder {
	b.roles = r
	return b
}

// WithUserProvider describes the withuserprovider operation and its observable behavior.
//
// WithUserProvider may return an error when input validation, dependency calls, or security checks fail.
// WithUserProvider does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithUserProvider(up UserProvider) *Builder {
	b.userProvider = up
	return b
}

// WithAuditSink describes the withauditsink operation and its observable behavior.
//
// WithAuditSink may return an error when input validation, dependency calls, or security checks fail.
// WithAuditSink does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithAuditSink(sink AuditSink) *Builder {
	b.auditSink = sink
	return b
}

// WithMetricsEnabled describes the withmetricsenabled operation and its observable behavior.
//
// WithMetricsEnabled may return an error when input validation, dependency calls, or security checks fail.
// WithMetricsEnabled does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithMetricsEnabled(enabled bool) *Builder {
	b.config.Metrics.Enabled = enabled
	return b
}

// WithLatencyHistograms describes the withlatencyhistograms operation and its observable behavior.
//
// WithLatencyHistograms may return an error when input validation, dependency calls, or security checks fail.
// WithLatencyHistograms does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (b *Builder) WithLatencyHistograms(enabled bool) *Builder {
	b.config.Metrics.EnableLatencyHistograms = enabled
	return b
}

// Build describes the build operation and its observable behavior.
//
// Build may return an error when input validation, dependency calls, or security checks fail.
// Build does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

	if len(b.permissions) == 0 {
		return nil, errors.New("permissions must be provided")
	}

	if len(b.roles) == 0 {
		return nil, errors.New("roles must be provided")
	}

	if b.userProvider == nil {
		return nil, errors.New("user provider required")
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

	engine.userProvider = b.userProvider
	engine.rateLimiter = rate.New(b.redis, rate.Config{
		EnableIPThrottle:        cfg.Security.EnableIPThrottle,
		EnableRefreshThrottle:   cfg.Security.EnableRefreshThrottle,
		MaxLoginAttempts:        cfg.Security.MaxLoginAttempts,
		LoginCooldownDuration:   cfg.Security.LoginCooldownDuration,
		MaxRefreshAttempts:      cfg.Security.MaxRefreshAttempts,
		RefreshCooldownDuration: cfg.Security.RefreshCooldownDuration,
	})
	engine.resetStore = newPasswordResetStore(b.redis)
	engine.resetLimiter = newPasswordResetLimiter(b.redis, cfg.PasswordReset)
	engine.verificationStore = newEmailVerificationStore(b.redis)
	engine.verificationLimiter = newEmailVerificationLimiter(b.redis, cfg.EmailVerification)
	engine.accountLimiter = newAccountCreationLimiter(b.redis, cfg.Account)
	engine.totpLimiter = newTOTPLimiter(b.redis)
	engine.backupLimiter = newBackupCodeLimiter(b.redis, cfg.TOTP)
	engine.mfaLoginStore = newMFALoginChallengeStore(b.redis)
	engine.audit = newAuditDispatcher(cfg.Audit, b.auditSink)
	engine.metrics = NewMetrics(cfg.Metrics)
	engine.totp = newTOTPManager(cfg.TOTP)

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
	})
	if err != nil {
		return nil, err
	}
	engine.jwtManager = jm

	b.built = true

	return engine, nil
}
