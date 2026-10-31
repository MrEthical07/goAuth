package goAuth

import (
	"errors"
	"fmt"
	"net/http"
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

// Clock is a source of the current time. The engine's own clock is the system
// clock; [Builder.WithClock] replaces it, for tests that need to move time.
//
//	Docs: docs/testing.md, docs/config.md
type Clock interface {
	Now() time.Time
}

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
	httpClient   *http.Client
	clock        Clock

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

// WithHTTPClient sets the HTTP client used to fetch external identity
// providers' signing keys (see Config.ExternalAuth). When unset, a client with
// a 5-second timeout is used. Only https key URLs are ever requested, and
// redirects to anything else are refused whatever the client's own policy.
// Nothing is fetched at [Builder.Build]; keys are fetched on first use or by
// [Engine.WarmExternalKeys].
//
//	Docs: docs/external_identity.md
func (b *Builder) WithHTTPClient(client *http.Client) *Builder {
	b.httpClient = client
	return b
}

// WithClock makes the engine read the current time from c instead of the
// system clock; nil (the default) is the system clock. The clock is per engine:
// two engines in one process with different clocks do not affect each other.
//
// It governs every time the engine decides on: session creation and expiry,
// idle windows and profile ceilings, JWT issue and validation (iat, exp, nbf),
// the expiry of password-reset, email-verification, email-change, MFA and
// sign-up challenges, external ID-token exp/iat/nbf checks and replay TTLs,
// the sliding-window limiters' buckets, credential and audit timestamps, and
// the "now" passed to the Redis scripts. It does NOT move Redis: key lifetimes
// are Redis's own time, so with miniredis advance the clock and call
// FastForward by the same amount (real Redis cannot be time-travelled). Latency
// measurements and the anti-enumeration response floor stay on the wall clock.
//
// WithClock is meant for tests. It is safe in production only with a clock
// that is monotonic and tracks real time.
//
//	Docs: docs/testing.md, docs/config.md
func (b *Builder) WithClock(c Clock) *Builder {
	b.clock = c
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

	for role := range cfg.RoleSwitch.StepUp {
		if _, ok := roleManager.GetMask(role); !ok {
			return nil, fmt.Errorf("RoleSwitch StepUp role %q is not a registered role", role)
		}
	}

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
	if b.clock != nil {
		store.WithClock(b.clock)
	}
	if policies := sessionProfilePolicies(cfg.SessionProfiles.Profiles); policies != nil {
		store.WithProfiles(policies)
	}
	// An MFA challenge pins the revocation epoch of its password step for its
	// whole life, so the epoch has to outlive the longest challenge.
	store.WithRevocationEpochTTL(cfg.TOTP.MFALoginChallengeTTL + time.Hour)

	engine := &Engine{
		config:       cloneConfig(cfg),
		registry:     registry,
		roleManager:  roleManager,
		sessionStore: store,
		clk:          b.clock,
	}
	now := engine.now
	sessionNow := engine.sessionNow

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
		Now:                       now,
		IPLimiterEnabled:          cfg.Security.LoginIPLimiter.Enabled,
		IPMaxAttempts:             cfg.Security.LoginIPLimiter.MaxAttempts,
		IPCooldown:                cfg.Security.LoginIPLimiter.Cooldown,
	})
	engine.resetStore = stores.NewPasswordResetStore(b.redis, "apr").WithClock(now)
	engine.resetLimiter = limiters.NewPasswordResetLimiter(b.redis, limiters.PasswordResetConfig{
		EnableRequestLimiter:        cfg.PasswordReset.EnableRequestLimiter,
		EnableConfirmFailureLimiter: cfg.PasswordReset.EnableConfirmFailureLimiter,
		ResetTTL:                    cfg.PasswordReset.ResetTTL,
		MaxAttempts:                 cfg.PasswordReset.MaxAttempts,
		WindowMode:                  windowMode,
		Now:                         now,
	})
	engine.verificationStore = stores.NewEmailVerificationStore(b.redis, "apv").WithClock(now)
	engine.verificationLimiter = limiters.NewEmailVerificationLimiter(b.redis, limiters.EmailVerificationConfig{
		EnableRequestLimiter:        cfg.EmailVerification.EnableRequestLimiter,
		EnableConfirmFailureLimiter: cfg.EmailVerification.EnableConfirmFailureLimiter,
		VerificationTTL:             cfg.EmailVerification.VerificationTTL,
		MaxAttempts:                 cfg.EmailVerification.MaxAttempts,
		WindowMode:                  windowMode,
		Now:                         now,
	})
	engine.accountLimiter = limiters.NewAccountCreationLimiter(b.redis, limiters.AccountConfig{
		EnableLimiter: cfg.Account.EnableCreationLimiter,
		MaxAttempts:   cfg.Account.AccountCreationMaxAttempts,
		Cooldown:      cfg.Account.AccountCreationCooldown,
		WindowMode:    windowMode,
		Now:           now,
	})
	engine.totpLimiter = limiters.NewTOTPLimiter(b.redis, limiters.TOTPLimiterConfig{
		// Direct TOTP verification paths share the MFA attempt budget.
		MaxAttempts: cfg.TOTP.MFALoginMaxAttempts,
		Cooldown:    cfg.TOTP.VerifyAttemptCooldown,
		WindowMode:  windowMode,
		Now:         now,
	})
	engine.backupLimiter = limiters.NewBackupCodeLimiter(b.redis, limiters.BackupCodeConfig{
		MaxAttempts: cfg.TOTP.BackupCodeMaxAttempts,
		Cooldown:    cfg.TOTP.BackupCodeCooldown,
		WindowMode:  windowMode,
		Now:         now,
	})
	engine.lockoutLimiter = limiters.NewLockoutLimiter(b.redis, limiters.LockoutConfig{
		Enabled:    cfg.Security.AutoLockoutEnabled,
		Threshold:  cfg.Security.AutoLockoutThreshold,
		Duration:   cfg.Security.AutoLockoutDuration,
		WindowMode: windowMode,
		Now:        now,
	})
	// Shares ChangePassword/VerifyPassword's own attempt budget with the
	// login failure limiter's configured thresholds, in its own rl:pwdverify:*
	// namespace, independent of auto-lockout: a stolen access token must not
	// be able to lock the real owner out of login by exhausting this limiter.
	engine.passwordVerifyLimiter = limiters.NewPasswordVerifyLimiter(b.redis, limiters.PasswordVerifyConfig{
		MaxAttempts: cfg.Security.MaxLoginAttempts,
		Cooldown:    cfg.Security.LoginCooldownDuration,
		WindowMode:  windowMode,
		Now:         now,
	})
	engine.mfaLoginStore = stores.NewMFALoginChallengeStore(b.redis, "amc").WithClock(now)
	engine.backupGrants = stores.NewBackupGrantStore(b.redis, "abg")
	// Optional: only a provider that can compare-and-swap a password hash opts
	// in; without it the upgrade re-reads the user before it writes.
	if cas, ok := b.userProvider.(PasswordHashCASUpdater); ok {
		engine.passwordCAS = cas
	}
	// Optional: only a provider that can compare-and-set the status opts in;
	// without it email verification re-reads the account before it writes.
	if cas, ok := b.userProvider.(AccountStatusCASUpdater); ok {
		engine.statusCAS = cas
	}
	if cfg.MultiTenant.Enabled {
		// Without a tenant-scoped lookup the engine would resolve
		// identifiers across every tenant, so credentials from one tenant
		// would authenticate under another. Falling back silently to the
		// tenant-blind lookup in a multi-tenant deployment must be
		// impossible to configure.
		provider, ok := b.userProvider.(TenantAwareUserProvider)
		if !ok {
			return nil, errors.New("MultiTenant is enabled but the user provider does not implement TenantAwareUserProvider")
		}
		engine.tenantProvider = provider
		// Optional: only a provider that can scope password writes to a
		// tenant opts in. Without it the legacy by-ID write is unchanged.
		if updater, ok := b.userProvider.(TenantAwarePasswordUpdater); ok {
			engine.passwordUpdater = updater
		}
	}
	if cfg.RoleSwitch.Enabled {
		provider, ok := b.userProvider.(RoleSwitchProvider)
		if !ok {
			return nil, errors.New("RoleSwitch is enabled but the user provider does not implement RoleSwitchProvider")
		}
		engine.roleSwitchProvider = provider
		engine.roleSwitchLimiter = limiters.NewRoleSwitchLimiter(b.redis, limiters.RoleSwitchConfig{
			MaxAttempts: cfg.RoleSwitch.MaxAttempts,
			Cooldown:    cfg.RoleSwitch.Cooldown,
			WindowMode:  windowMode,
			Now:         now,
		})
	}
	if cfg.EmailChange.Enabled {
		provider, ok := b.userProvider.(EmailChangeProvider)
		if !ok {
			return nil, errors.New("EmailChange is enabled but the user provider does not implement EmailChangeProvider")
		}
		resolved := cfg.EmailChange.resolved()
		engine.emailChangeProvider = provider
		engine.emailChangeStore = stores.NewEmailChangeStore(b.redis, "aec").WithClock(now)
		engine.emailChangeLimiter = limiters.NewEmailChangeLimiter(b.redis, limiters.EmailChangeConfig{
			MaxAttempts: resolved.RequestMaxAttempts,
			Cooldown:    resolved.RequestCooldown,
			WindowMode:  windowMode,
			Now:         now,
		})
	}
	if cfg.ExternalAuth.Enabled {
		provider, ok := b.userProvider.(ExternalIdentityProvider)
		if !ok {
			return nil, errors.New("ExternalAuth is enabled but the user provider does not implement ExternalIdentityProvider")
		}
		verifier, err := newExternalVerifierWithClock(cfg, b.redis, b.httpClient, sessionNow)
		if err != nil {
			return nil, fmt.Errorf("invalid ExternalAuth configuration: %w", err)
		}
		engine.externalProvider = provider
		engine.externalVerifier = verifier
		engine.externalLimiter = limiters.NewExternalLimiter(b.redis, limiters.ExternalConfig{
			MaxAttempts: cfg.ExternalAuth.MaxAttempts,
			Cooldown:    cfg.ExternalAuth.Cooldown,
			WindowMode:  windowMode,
			Now:         now,
		})
	}
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
	dummy, err := newDummyTimingHash(ph)
	if err != nil {
		return nil, fmt.Errorf("goauth: cannot prepare the timing-equalization hash: %w", err)
	}
	engine.dummyHash = dummy

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
		Now:           now,
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
		// go-webauthn v0.18 defaults to rejecting a ceremony whose client
		// returned an extension output this Relying Party never requested
		// (protocol.UnsolicitedOutputPolicyReject). goAuth requests no
		// extensions at all, so a real browser or password manager that
		// volunteers one unprompted would fail login/registration under the
		// new default. v0.17.4 performed no such check, so pin Ignore to
		// keep that behavior.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
}
