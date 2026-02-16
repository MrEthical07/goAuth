package goAuth

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	internalaudit "github.com/MrEthical07/goAuth/internal/audit"
	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/rate"
	internalsecurity "github.com/MrEthical07/goAuth/internal/security"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/jwt"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// Engine defines a public type used by goAuth APIs.
//
// Engine instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Engine struct {
	config              Config
	registry            *permission.Registry
	roleManager         *permission.RoleManager
	sessionStore        *session.Store
	rateLimiter         *rate.Limiter
	resetStore          *stores.PasswordResetStore
	resetLimiter        *limiters.PasswordResetLimiter
	verificationStore   *stores.EmailVerificationStore
	verificationLimiter *limiters.EmailVerificationLimiter
	accountLimiter      *limiters.AccountCreationLimiter
	totpLimiter         *limiters.TOTPLimiter
	backupLimiter       *limiters.BackupCodeLimiter
	mfaLoginStore       *stores.MFALoginChallengeStore
	audit               *auditDispatcher
	metrics             *Metrics
	passwordHash        *password.Argon2
	totp                *totpManager
	jwtManager          *jwt.Manager
	userProvider        UserProvider
	logger              *slog.Logger
	flowDeps            internalflows.Deps
}

type auditDispatcher = internalaudit.Dispatcher
type totpManager = internalsecurity.TOTPManager

func newAuditDispatcher(cfg AuditConfig, sink AuditSink) *auditDispatcher {
	return internalaudit.NewDispatcher(internalaudit.Config{
		Enabled:    cfg.Enabled,
		BufferSize: cfg.BufferSize,
		DropIfFull: cfg.DropIfFull,
	}, sink)
}

func newTOTPManager(cfg TOTPConfig) *totpManager {
	return internalsecurity.NewTOTPManager(internalsecurity.TOTPConfig{
		Issuer:    cfg.Issuer,
		Period:    cfg.Period,
		Digits:    cfg.Digits,
		Algorithm: cfg.Algorithm,
		Skew:      cfg.Skew,
	})
}

func hotpCode(secret []byte, counter int64, digits int, algorithm string) (string, error) {
	return internalsecurity.HOTPCode(secret, counter, digits, algorithm)
}

// Close describes the close operation and its observable behavior.
//
// Close may return an error when input validation, dependency calls, or security checks fail.
// Close does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	if e.audit != nil {
		e.audit.Close()
	}
}

// AuditDropped describes the auditdropped operation and its observable behavior.
//
// AuditDropped may return an error when input validation, dependency calls, or security checks fail.
// AuditDropped does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) AuditDropped() uint64 {
	if e == nil || e.audit == nil {
		return 0
	}
	return e.audit.Dropped()
}

// MetricsSnapshot describes the metricssnapshot operation and its observable behavior.
//
// MetricsSnapshot may return an error when input validation, dependency calls, or security checks fail.
// MetricsSnapshot does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) MetricsSnapshot() MetricsSnapshot {
	if e == nil || e.metrics == nil {
		return MetricsSnapshot{
			Counters:   map[MetricID]uint64{},
			Histograms: map[MetricID][]uint64{},
		}
	}
	return e.metrics.Snapshot()
}

// SecurityReport describes the securityreport operation and its observable behavior.
//
// SecurityReport may return an error when input validation, dependency calls, or security checks fail.
// SecurityReport does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) SecurityReport() SecurityReport {
	if e == nil {
		return SecurityReport{}
	}

	report := internalsecurity.BuildReport(internalsecurity.ReportInput{
		ProductionMode:               e.config.Security.ProductionMode,
		SigningAlgorithm:             e.config.JWT.SigningMethod,
		ValidationMode:               int(e.config.ValidationMode),
		StrictMode:                   e.config.ValidationMode == ModeStrict || e.config.Security.StrictMode,
		AccessTTL:                    e.config.JWT.AccessTTL,
		RefreshTTL:                   e.config.JWT.RefreshTTL,
		Password:                     internalsecurity.PasswordReport{Memory: e.config.Password.Memory, Time: e.config.Password.Time, Parallelism: e.config.Password.Parallelism, SaltLength: e.config.Password.SaltLength, KeyLength: e.config.Password.KeyLength},
		TOTPEnabled:                  e.config.TOTP.Enabled,
		BackupCodeCount:              e.config.TOTP.BackupCodeCount,
		DeviceBindingEnabled:         e.config.DeviceBinding.Enabled,
		RefreshRotationEnabled:       e.config.Security.EnforceRefreshRotation,
		RefreshReuseDetectionEnabled: e.config.Security.EnforceRefreshReuseDetection,
		EnableRefreshThrottle:        e.config.Security.EnableRefreshThrottle,
		EmailVerificationEnabled:     e.config.EmailVerification.Enabled,
		PasswordResetEnabled:         e.config.PasswordReset.Enabled,
		MaxSessionsPerUser:           e.config.SessionHardening.MaxSessionsPerUser,
		MaxSessionsPerTenant:         e.config.SessionHardening.MaxSessionsPerTenant,
		EnforceSingleSession:         e.config.SessionHardening.EnforceSingleSession,
		ConcurrentLoginLimit:         e.config.SessionHardening.ConcurrentLoginLimit,
		MaxLoginAttempts:             e.config.Security.MaxLoginAttempts,
		LoginCooldownDuration:        e.config.Security.LoginCooldownDuration,
	})

	return SecurityReport{
		ProductionMode:               report.ProductionMode,
		SigningAlgorithm:             report.SigningAlgorithm,
		ValidationMode:               ValidationMode(report.ValidationMode),
		StrictMode:                   report.StrictMode,
		AccessTTL:                    report.AccessTTL,
		RefreshTTL:                   report.RefreshTTL,
		Argon2:                       PasswordConfigReport{Memory: report.Argon2.Memory, Time: report.Argon2.Time, Parallelism: report.Argon2.Parallelism, SaltLength: report.Argon2.SaltLength, KeyLength: report.Argon2.KeyLength},
		TOTPEnabled:                  report.TOTPEnabled,
		BackupEnabled:                report.BackupEnabled,
		DeviceBindingEnabled:         report.DeviceBindingEnabled,
		RefreshRotationEnabled:       report.RefreshRotationEnabled,
		RefreshReuseDetectionEnabled: report.RefreshReuseDetectionEnabled,
		SessionCapsActive:            report.SessionCapsActive,
		RateLimitingActive:           report.RateLimitingActive,
		EmailVerificationActive:      report.EmailVerificationActive,
		PasswordResetActive:          report.PasswordResetActive,
	}
}

func (e *Engine) metricInc(id MetricID) {
	if e == nil || e.metrics == nil {
		return
	}
	e.metrics.Inc(id)
}

func (e *Engine) warn(msg string, args ...any) {
	if e == nil || e.logger == nil {
		return
	}
	e.logger.Warn(msg, args...)
}

// Login describes the login operation and its observable behavior.
//
// Login may return an error when input validation, dependency calls, or security checks fail.
// Login does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Login(ctx context.Context, username, password string) (string, string, error) {
	result, err := e.LoginWithResult(ctx, username, password)
	if err != nil {
		return "", "", err
	}
	if result == nil {
		return "", "", ErrEngineNotReady
	}
	if result.MFARequired {
		return "", "", ErrTOTPRequired
	}
	return result.AccessToken, result.RefreshToken, nil
}

// LoginWithTOTP describes the loginwithtotp operation and its observable behavior.
//
// LoginWithTOTP may return an error when input validation, dependency calls, or security checks fail.
// LoginWithTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LoginWithTOTP(ctx context.Context, username, password, totpCode string) (string, string, error) {
	result, err := e.LoginWithResult(ctx, username, password)
	if err != nil {
		return "", "", err
	}
	if result == nil {
		return "", "", ErrEngineNotReady
	}
	if result.MFARequired {
		result, err = e.ConfirmLoginMFAWithType(ctx, result.MFASession, totpCode, "totp")
		if err != nil {
			switch {
			case errors.Is(err, ErrMFALoginInvalid), errors.Is(err, ErrMFALoginExpired):
				return "", "", ErrTOTPInvalid
			case errors.Is(err, ErrMFALoginAttemptsExceeded):
				return "", "", ErrTOTPRateLimited
			case errors.Is(err, ErrMFALoginUnavailable):
				return "", "", ErrTOTPUnavailable
			}
			return "", "", err
		}
	}
	return result.AccessToken, result.RefreshToken, nil
}

// LoginWithBackupCode describes the loginwithbackupcode operation and its observable behavior.
//
// LoginWithBackupCode may return an error when input validation, dependency calls, or security checks fail.
// LoginWithBackupCode does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LoginWithBackupCode(ctx context.Context, username, password, backupCode string) (string, string, error) {
	result, err := e.LoginWithResult(ctx, username, password)
	if err != nil {
		return "", "", err
	}
	if result == nil {
		return "", "", ErrEngineNotReady
	}
	if result.MFARequired {
		result, err = e.ConfirmLoginMFAWithType(ctx, result.MFASession, backupCode, "backup")
		if err != nil {
			switch {
			case errors.Is(err, ErrMFALoginInvalid), errors.Is(err, ErrMFALoginExpired):
				return "", "", ErrBackupCodeInvalid
			case errors.Is(err, ErrMFALoginAttemptsExceeded):
				return "", "", ErrBackupCodeRateLimited
			case errors.Is(err, ErrMFALoginUnavailable):
				return "", "", ErrBackupCodeUnavailable
			}
			return "", "", err
		}
	}
	return result.AccessToken, result.RefreshToken, nil
}

func (e *Engine) loginInternal(ctx context.Context, username, password, totpCode string) (string, string, error) {
	ip := clientIPFromContext(ctx)
	tenantID := tenantIDFromContext(ctx)
	if e.passwordHash == nil {
		return "", "", ErrEngineNotReady
	}
	if e.rateLimiter != nil {
		if err := e.rateLimiter.CheckLogin(ctx, username, ip); err != nil {
			e.metricInc(MetricLoginRateLimited)
			e.emitAudit(ctx, auditEventLoginRateLimited, false, "", tenantID, "", ErrLoginRateLimited, func() map[string]string {
				return map[string]string{
					"identifier": username,
				}
			})
			e.emitRateLimit(ctx, "login", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": username,
				}
			})
			return "", "", ErrLoginRateLimited
		}
	}
	if password == "" {
		if e.rateLimiter != nil {
			if err := e.rateLimiter.IncrementLogin(ctx, username, ip); err != nil {
				e.metricInc(MetricLoginRateLimited)
				e.emitAudit(ctx, auditEventLoginRateLimited, false, "", tenantID, "", ErrLoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				e.emitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return "", "", ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, "", tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "empty_password",
			}
		})
		return "", "", ErrInvalidCredentials
	}

	user, err := e.userProvider.GetUserByIdentifier(username)
	if err != nil {
		if e.rateLimiter != nil {
			if err := e.rateLimiter.IncrementLogin(ctx, username, ip); err != nil {
				e.metricInc(MetricLoginRateLimited)
				e.emitAudit(ctx, auditEventLoginRateLimited, false, "", tenantID, "", ErrLoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				e.emitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return "", "", ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, "", tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "user_not_found",
			}
		})
		return "", "", ErrInvalidCredentials
	}

	ok, err := e.passwordHash.Verify(password, user.PasswordHash)
	if err != nil || !ok {
		if e.rateLimiter != nil {
			if err := e.rateLimiter.IncrementLogin(ctx, username, ip); err != nil {
				e.metricInc(MetricLoginRateLimited)
				e.emitAudit(ctx, auditEventLoginRateLimited, false, user.UserID, tenantID, "", ErrLoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				e.emitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return "", "", ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "password_mismatch",
			}
		})
		return "", "", ErrInvalidCredentials
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "account_status",
			}
		})
		return "", "", statusErr
	}
	if e.shouldRequireVerified() && user.Status == AccountPendingVerification {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrAccountUnverified, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "pending_verification",
			}
		})
		return "", "", ErrAccountUnverified
	}
	if err := e.enforceTOTPForLogin(ctx, user, totpCode); err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "totp_validation",
			}
		})
		return "", "", err
	}

	if e.config.Password.UpgradeOnLogin {
		if needsUpgrade, err := e.passwordHash.NeedsUpgrade(user.PasswordHash); err == nil && needsUpgrade {
			if upgradedHash, err := e.passwordHash.Hash(password); err == nil {
				// Rehash update is best-effort and must not block successful login.
				if err := e.userProvider.UpdatePasswordHash(user.UserID, upgradedHash); err != nil {
					e.warn("goAuth: password hash upgrade update failed")
				}
			} else {
				e.warn("goAuth: password hash upgrade generation failed")
			}
		}
	}
	password = ""

	mask, ok := e.roleManager.GetMask(user.Role)
	if !ok {
		if e.rateLimiter != nil {
			if err := e.rateLimiter.IncrementLogin(ctx, username, ip); err != nil {
				e.metricInc(MetricLoginRateLimited)
				e.emitAudit(ctx, auditEventLoginRateLimited, false, user.UserID, tenantID, "", ErrLoginRateLimited, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				e.emitRateLimit(ctx, "login", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": username,
					}
				})
				return "", "", ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "role_mask_missing",
			}
		})
		return "", "", ErrInvalidCredentials
	}

	if e.config.DeviceBinding.Enabled {
		if e.config.DeviceBinding.EnforceIPBinding && clientIPFromContext(ctx) == "" {
			e.metricInc(MetricLoginFailure)
			e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrDeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_ip_context",
				}
			})
			return "", "", ErrDeviceBindingRejected
		}
		if e.config.DeviceBinding.EnforceUserAgentBinding && userAgentFromContext(ctx) == "" {
			e.metricInc(MetricLoginFailure)
			e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrDeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_user_agent_context",
				}
			})
			return "", "", ErrDeviceBindingRejected
		}
	}

	if err := e.enforceSessionHardeningOnLogin(ctx, tenantID, user.UserID); err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_hardening",
			}
		})
		return "", "", err
	}

	sid, err := internal.NewSessionID()
	if err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_id_generation",
			}
		})
		return "", "", err
	}
	sessionID := sid.String()
	refreshSecret, err := internal.NewRefreshSecret()
	if err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "refresh_secret_generation",
			}
		})
		return "", "", err
	}

	now := time.Now()
	sessionLifetime := e.sessionLifetime()
	accountVersion := user.AccountVersion
	if accountVersion == 0 {
		accountVersion = 1
	}
	var ipHash [32]byte
	var userAgentHash [32]byte
	if e.config.DeviceBinding.Enabled {
		if ip := clientIPFromContext(ctx); ip != "" {
			ipHash = internal.HashBindingValue(ip)
		}
		if ua := userAgentFromContext(ctx); ua != "" {
			userAgentHash = internal.HashBindingValue(ua)
		}
	}

	sess := &session.Session{
		SessionID:         sessionID,
		UserID:            user.UserID,
		TenantID:          tenantID,
		Role:              user.Role,
		Mask:              mask,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    accountVersion,
		Status:            uint8(user.Status),
		RefreshHash:       internal.HashRefreshSecret(refreshSecret),
		IPHash:            ipHash,
		UserAgentHash:     userAgentHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(sessionLifetime).Unix(),
	}

	if err := e.sessionStore.Save(ctx, sess, sessionLifetime); err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "session_save_failed",
			}
		})
		return "", "", err
	}

	access, err := e.issueAccessToken(sess)
	if err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "issue_access_failed",
			}
		})
		return "", "", err
	}

	refresh, err := internal.EncodeRefreshToken(sessionID, refreshSecret)
	if err != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "encode_refresh_failed",
			}
		})
		return "", "", err
	}

	if e.rateLimiter != nil {
		if err := e.rateLimiter.ResetLogin(ctx, username, ip); err != nil {
			e.metricInc(MetricLoginRateLimited)
			e.emitAudit(ctx, auditEventLoginRateLimited, false, user.UserID, tenantID, sessionID, ErrLoginRateLimited, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "reset_limiter_failed",
				}
			})
			return "", "", ErrLoginRateLimited
		}
	}

	e.metricInc(MetricSessionCreated)
	e.metricInc(MetricLoginSuccess)
	e.emitAudit(ctx, auditEventLoginSuccess, true, user.UserID, tenantID, sessionID, nil, func() map[string]string {
		return map[string]string{
			"identifier": username,
		}
	})

	return access, refresh, nil
}

// Refresh describes the refresh operation and its observable behavior.
//
// Refresh may return an error when input validation, dependency calls, or security checks fail.
// Refresh does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	e.ensureFlowDeps()
	result := internalflows.RunRefresh(ctx, refreshToken, e.flowDeps.Refresh)

	switch result.Failure {
	case internalflows.RefreshFailureDecode:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", result.TenantID, "", ErrRefreshInvalid, func() map[string]string {
			return map[string]string{
				"reason": "decode_failed",
			}
		})
		return "", "", ErrRefreshInvalid
	case internalflows.RefreshFailureRateLimited:
		e.metricInc(MetricRefreshRateLimited)
		e.emitAudit(ctx, auditEventRefreshRateLimited, false, "", result.TenantID, result.SessionID, ErrRefreshRateLimited, nil)
		e.emitRateLimit(ctx, "refresh", result.TenantID, func() map[string]string {
			return map[string]string{
				"session_id": result.SessionID,
			}
		})
		return "", "", ErrRefreshRateLimited
	case internalflows.RefreshFailureNextSecret:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", result.TenantID, result.SessionID, result.Err, func() map[string]string {
			return map[string]string{
				"reason": "next_secret_generation",
			}
		})
		return "", "", result.Err
	case internalflows.RefreshFailureReuse:
		e.metricInc(MetricRefreshReuseDetected)
		e.metricInc(MetricReplayDetected)
		e.metricInc(MetricSessionInvalidated)
		e.emitAudit(ctx, auditEventRefreshReuseDetected, false, "", result.TenantID, result.SessionID, ErrRefreshReuse, nil)
		return "", "", ErrRefreshReuse
	case internalflows.RefreshFailureSessionNotFound:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", result.TenantID, result.SessionID, ErrSessionNotFound, func() map[string]string {
			return map[string]string{
				"reason": "session_not_found",
			}
		})
		return "", "", ErrSessionNotFound
	case internalflows.RefreshFailureRotate:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", result.TenantID, result.SessionID, result.Err, func() map[string]string {
			return map[string]string{
				"reason": "rotate_failed",
			}
		})
		return "", "", result.Err
	case internalflows.RefreshFailureAccountStatus:
		e.metricInc(MetricSessionInvalidated)
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, result.UserID, result.TenantID, result.SessionID, result.Err, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return "", "", result.Err
	case internalflows.RefreshFailureUnverified:
		e.metricInc(MetricSessionInvalidated)
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, result.UserID, result.TenantID, result.SessionID, ErrAccountUnverified, func() map[string]string {
			return map[string]string{
				"reason": "pending_verification",
			}
		})
		return "", "", ErrAccountUnverified
	case internalflows.RefreshFailureIssueAccess:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, result.UserID, result.TenantID, result.SessionID, result.Err, func() map[string]string {
			return map[string]string{
				"reason": "issue_access_failed",
			}
		})
		return "", "", result.Err
	case internalflows.RefreshFailureEncode:
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, result.UserID, result.TenantID, result.SessionID, result.Err, func() map[string]string {
			return map[string]string{
				"reason": "encode_refresh_failed",
			}
		})
		return "", "", result.Err
	}

	e.metricInc(MetricRefreshSuccess)
	e.emitAudit(ctx, auditEventRefreshSuccess, true, result.UserID, result.TenantID, result.SessionID, nil, nil)

	return result.AccessToken, result.RefreshToken, nil
}

// ValidateAccess describes the validateaccess operation and its observable behavior.
//
// ValidateAccess may return an error when input validation, dependency calls, or security checks fail.
// ValidateAccess does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ValidateAccess(ctx context.Context, tokenStr string) (*AuthResult, error) {
	return e.Validate(ctx, tokenStr, ModeInherit)
}

// Validate describes the validate operation and its observable behavior.
//
// Validate may return an error when input validation, dependency calls, or security checks fail.
// Validate does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Validate(ctx context.Context, tokenStr string, routeMode RouteMode) (*AuthResult, error) {
	e.ensureFlowDeps()
	if e.metrics != nil && e.metrics.LatencyEnabled() {
		start := time.Now()
		defer e.metrics.Observe(MetricValidateLatency, time.Since(start))
	}

	result := internalflows.RunValidate(ctx, tokenStr, int(routeMode), e.flowDeps.Validate)
	switch result.Failure {
	case internalflows.ValidateFailureUnauthorized:
		return nil, ErrUnauthorized
	case internalflows.ValidateFailureTokenClockSkew:
		return nil, ErrTokenClockSkew
	case internalflows.ValidateFailureInvalidRouteMode:
		return nil, ErrInvalidRouteMode
	case internalflows.ValidateFailureSessionNotFound:
		return nil, ErrSessionNotFound
	case internalflows.ValidateFailureStatus:
		return nil, result.Err
	case internalflows.ValidateFailureUnverified:
		return nil, ErrAccountUnverified
	case internalflows.ValidateFailureDeviceBinding:
		return nil, result.Err
	}

	if result.Session != nil {
		return e.buildResult(result.Session), nil
	}
	return e.buildResultFromClaims(result.Claims), nil
}

func (e *Engine) buildResult(s *session.Session) *AuthResult {
	res := &AuthResult{
		UserID:   s.UserID,
		TenantID: s.TenantID,
		Mask:     s.Mask,
	}

	if e.config.Result.IncludeRole {
		res.Role = s.Role
	}

	if e.config.Result.IncludePermissions {
		res.Permissions = e.permissionsFromMask(s.Mask)
	}

	return res
}

func (e *Engine) permissionsFromMask(mask interface{}) []string {
	var perms []string

	for bit := 0; bit < e.registry.Count(); bit++ {
		name, ok := e.registry.Name(bit)
		if !ok {
			continue
		}
		if e.HasPermission(mask, name) {
			perms = append(perms, name)
		}
	}

	return perms
}

func (e *Engine) buildResultFromClaims(claims *jwt.AccessClaims) *AuthResult {
	var mask interface{}

	if claims.Mask != nil {
		decodedMask, err := permission.DecodeMask(claims.Mask)
		if err == nil {
			mask = decodedMask
		}
	}

	res := &AuthResult{
		UserID: claims.UID,
		Mask:   mask,
	}

	if e.config.Result.IncludePermissions && mask != nil {
		res.Permissions = e.permissionsFromMask(mask)
	}

	return res
}

// HasPermission describes the haspermission operation and its observable behavior.
//
// HasPermission may return an error when input validation, dependency calls, or security checks fail.
// HasPermission does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) HasPermission(mask interface{}, perm string) bool {
	bit, ok := e.registry.Bit(perm)
	if !ok {
		return false
	}

	switch m := mask.(type) {
	case *permission.Mask64:
		return m.Has(bit, e.config.Permission.RootBitReserved)
	case *permission.Mask128:
		return m.Has(bit, e.config.Permission.RootBitReserved)
	case *permission.Mask256:
		return m.Has(bit, e.config.Permission.RootBitReserved)
	case *permission.Mask512:
		return m.Has(bit, e.config.Permission.RootBitReserved)
	default:
		return false
	}
}

func (e *Engine) issueAccessToken(sess *session.Session) (string, error) {
	// Always include JWT claims required for JWT-only route overrides.
	includeMask := true
	includePermVersion := true
	includeRoleVersion := true
	includeAccountVersion := true

	var (
		maskBytes []byte
		err       error
	)

	if includeMask {
		maskBytes, err = permission.EncodeMask(sess.Mask)
		if err != nil {
			return "", err
		}
	}

	return e.jwtManager.CreateAccess(
		sess.UserID,
		parseTenantIDToUint32(sess.TenantID),
		sess.SessionID,
		maskBytes,
		sess.PermissionVersion,
		sess.RoleVersion,
		sess.AccountVersion,
		includeMask,
		includePermVersion,
		includeRoleVersion,
		includeAccountVersion,
		e.isRootMask(sess.Mask),
	)
}

// Logout describes the logout operation and its observable behavior.
//
// Logout may return an error when input validation, dependency calls, or security checks fail.
// Logout does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Logout(ctx context.Context, sessionID string) error {
	e.ensureFlowDeps()
	return e.LogoutInTenant(ctx, e.flowDeps.Logout.TenantIDFromContext(ctx), sessionID)
}

// LogoutInTenant describes the logoutintenant operation and its observable behavior.
//
// LogoutInTenant may return an error when input validation, dependency calls, or security checks fail.
// LogoutInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutInTenant(ctx context.Context, tenantID, sessionID string) error {
	e.ensureFlowDeps()
	err := internalflows.RunLogoutInTenant(ctx, tenantID, sessionID, e.flowDeps.Logout)
	if err == nil {
		e.metricInc(MetricLogout)
		e.metricInc(MetricSessionInvalidated)
	}
	e.emitAudit(ctx, auditEventLogoutSession, err == nil, "", tenantID, sessionID, err, nil)
	return err
}

// LogoutByAccessToken describes the logoutbyaccesstoken operation and its observable behavior.
//
// LogoutByAccessToken may return an error when input validation, dependency calls, or security checks fail.
// LogoutByAccessToken does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutByAccessToken(ctx context.Context, tokenStr string) error {
	e.ensureFlowDeps()
	result := internalflows.RunLogoutByAccessToken(ctx, tokenStr, e.flowDeps.Logout)
	if result.Err != nil && result.SessionID == "" {
		e.emitAudit(ctx, auditEventLogoutSession, false, "", tenantIDFromContext(ctx), "", ErrTokenInvalid, func() map[string]string {
			return map[string]string{
				"reason": "invalid_access_token",
			}
		})
		return ErrTokenInvalid
	}
	if result.Err != nil {
		e.emitAudit(ctx, auditEventLogoutSession, false, "", result.TenantID, result.SessionID, result.Err, nil)
		return result.Err
	}
	e.metricInc(MetricLogout)
	e.metricInc(MetricSessionInvalidated)
	e.emitAudit(ctx, auditEventLogoutSession, true, "", result.TenantID, result.SessionID, nil, nil)
	return nil
}

// LogoutAll describes the logoutall operation and its observable behavior.
//
// LogoutAll may return an error when input validation, dependency calls, or security checks fail.
// LogoutAll does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutAll(ctx context.Context, userID string) error {
	e.ensureFlowDeps()
	return e.LogoutAllInTenant(ctx, e.flowDeps.Logout.TenantIDFromContext(ctx), userID)
}

// LogoutAllInTenant describes the logoutallintenant operation and its observable behavior.
//
// LogoutAllInTenant may return an error when input validation, dependency calls, or security checks fail.
// LogoutAllInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutAllInTenant(ctx context.Context, tenantID, userID string) error {
	e.ensureFlowDeps()
	err := internalflows.RunLogoutAllInTenant(ctx, tenantID, userID, e.flowDeps.Logout)
	if err == nil {
		e.metricInc(MetricLogoutAll)
		e.metricInc(MetricSessionInvalidated)
	}
	e.emitAudit(ctx, auditEventLogoutAll, err == nil, userID, tenantID, "", err, nil)
	return err
}

// InvalidateUserSessions describes the invalidateusersessions operation and its observable behavior.
//
// InvalidateUserSessions may return an error when input validation, dependency calls, or security checks fail.
// InvalidateUserSessions does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) InvalidateUserSessions(ctx context.Context, userID string) error {
	return e.LogoutAll(ctx, userID)
}

// ChangePassword describes the changepassword operation and its observable behavior.
//
// ChangePassword may return an error when input validation, dependency calls, or security checks fail.
// ChangePassword does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if e.passwordHash == nil {
		return ErrEngineNotReady
	}
	if userID == "" || oldPassword == "" || newPassword == "" {
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, tenantIDFromContext(ctx), "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "invalid_input",
			}
		})
		return ErrPasswordPolicy
	}

	user, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, tenantIDFromContext(ctx), "", ErrUserNotFound, func() map[string]string {
			return map[string]string{
				"reason": "user_not_found",
			}
		})
		return ErrUserNotFound
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	oldOK, err := e.passwordHash.Verify(oldPassword, user.PasswordHash)
	if err != nil || !oldOK {
		e.metricInc(MetricPasswordChangeInvalidOld)
		e.emitAudit(ctx, auditEventPasswordChangeInvalidOld, false, userID, user.TenantID, "", ErrInvalidCredentials, nil)
		return ErrInvalidCredentials
	}

	samePassword, err := e.passwordHash.Verify(newPassword, user.PasswordHash)
	if err == nil && samePassword {
		e.metricInc(MetricPasswordChangeReuseRejected)
		e.emitAudit(ctx, auditEventPasswordChangeReuse, false, userID, user.TenantID, "", ErrPasswordReuse, nil)
		return ErrPasswordReuse
	}

	newHash, err := e.passwordHash.Hash(newPassword)
	if err != nil {
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, user.TenantID, "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "hash_policy",
			}
		})
		return ErrPasswordPolicy
	}

	if err := e.userProvider.UpdatePasswordHash(userID, newHash); err != nil {
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "update_hash_failed",
			}
		})
		return err
	}

	invalidateTenant := tenantIDFromContext(ctx)
	if user.TenantID != "" {
		invalidateTenant = user.TenantID
	}

	if err := e.LogoutAllInTenant(ctx, invalidateTenant, userID); err != nil {
		e.warn("goAuth: session invalidation failed after password change")
		e.emitAudit(ctx, auditEventPasswordChangeFailure, false, userID, invalidateTenant, "", ErrSessionInvalidationFailed, func() map[string]string {
			return map[string]string{
				"reason": "session_invalidation_failed",
			}
		})
		return errors.Join(ErrSessionInvalidationFailed, err)
	}

	if e.rateLimiter != nil {
		identifier := user.Identifier
		if identifier == "" {
			identifier = userID
		}
		// Limiter reset is best-effort and must not block successful password change.
		if err := e.rateLimiter.ResetLogin(ctx, identifier, clientIPFromContext(ctx)); err != nil {
			e.warn("goAuth: login limiter reset failed after password change")
		}
	}

	oldPassword = ""
	newPassword = ""
	e.metricInc(MetricPasswordChangeSuccess)
	e.emitAudit(ctx, auditEventPasswordChangeSuccess, true, userID, invalidateTenant, "", nil, nil)

	return nil
}

func (e *Engine) isRootMask(mask interface{}) bool {
	if !e.config.Permission.RootBitReserved {
		return false
	}

	rootBit, ok := e.registry.RootBit()
	if !ok {
		return false
	}

	rootName, ok := e.registry.Name(rootBit)
	if !ok {
		return false
	}

	return e.HasPermission(mask, rootName)
}

func (e *Engine) sessionLifetime() time.Duration {
	lifetime := e.config.Session.AbsoluteSessionLifetime
	if e.config.JWT.RefreshTTL > 0 && e.config.JWT.RefreshTTL < lifetime {
		return e.config.JWT.RefreshTTL
	}
	return lifetime
}

func (e *Engine) initFlowDeps() {
	e.flowDeps = internalflows.Deps{
		Refresh: internalflows.RefreshDeps{
			TenantIDFromContext:       tenantIDFromContext,
			DecodeRefreshToken:        internal.DecodeRefreshToken,
			NewRefreshSecret:          internal.NewRefreshSecret,
			HashRefreshSecret:         internal.HashRefreshSecret,
			EncodeRefreshToken:        internal.EncodeRefreshToken,
			IssueAccessToken:          e.issueAccessToken,
			AccountStatusError:        func(status uint8) error { return accountStatusToError(AccountStatus(status)) },
			ShouldRequireVerified:     e.shouldRequireVerified,
			PendingVerificationStatus: uint8(AccountPendingVerification),
			SessionLifetime:           e.sessionLifetime,
			EnableReplayTracking:      e.config.SessionHardening.EnableReplayTracking,
			Warn:                      e.warn,
			RateLimiter:               e.rateLimiter,
			SessionStore:              e.sessionStore,
			RefreshHashMismatch:       session.ErrRefreshHashMismatch,
			RedisNil:                  redis.Nil,
		},
		Validate: internalflows.ValidateDeps{
			ParseAccess: e.jwtManager.ParseAccess,
			ResolveRouteMode: func(routeMode int) (int, error) {
				mode, err := e.resolveRouteMode(RouteMode(routeMode))
				return int(mode), err
			},
			Now:                       time.Now,
			MaxClockSkew:              e.config.SessionHardening.MaxClockSkew,
			ModeJWTOnly:               int(ModeJWTOnly),
			ModeHybrid:                int(ModeHybrid),
			EnablePermissionCheck:     e.config.Security.EnablePermissionVersionCheck,
			EnableRoleCheck:           e.config.Security.EnableRoleVersionCheck,
			EnableAccountCheck:        e.config.Security.EnableAccountVersionCheck,
			ShouldRequireVerified:     e.shouldRequireVerified,
			PendingVerificationStatus: uint8(AccountPendingVerification),
			AccountStatusError:        func(status uint8) error { return accountStatusToError(AccountStatus(status)) },
			ValidateDeviceBinding:     e.validateDeviceBinding,
			TenantIDFromToken:         tenantIDFromToken,
			SessionLifetime:           e.sessionLifetime,
			SessionStore:              e.sessionStore,
			RedisUnavailable:          session.ErrRedisUnavailable,
			RedisNil:                  redis.Nil,
		},
		Logout: internalflows.LogoutDeps{
			ParseAccess:         e.jwtManager.ParseAccess,
			TenantIDFromContext: tenantIDFromContext,
			TenantIDFromToken:   tenantIDFromToken,
			SessionStore:        e.sessionStore,
		},
		Introspection: internalflows.IntrospectionDeps{
			SessionStore:                e.sessionStore,
			RateLimiter:                 e.rateLimiter,
			MultiTenantEnabled:          e.config.MultiTenant.Enabled,
			TenantIDFromContext:         tenantIDFromContext,
			TenantIDFromContextExplicit: tenantIDFromContextExplicit,
			UnauthorizedErr:             ErrUnauthorized,
			EngineNotReadyErr:           ErrEngineNotReady,
			UserNotFoundErr:             ErrUserNotFound,
			SessionNotFoundErr:          ErrSessionNotFound,
			RedisNil:                    redis.Nil,
		},
	}
}

func (e *Engine) ensureFlowDeps() {
	if e == nil {
		return
	}
	if e.flowDeps.Refresh.TenantIDFromContext != nil {
		return
	}
	e.initFlowDeps()
}

func (e *Engine) resolveRouteMode(routeMode RouteMode) (ValidationMode, error) {
	mode, ok := internalflows.ResolveRouteMode(int(routeMode), int(e.config.ValidationMode), internalflows.ModeResolverConfig{
		ModeInherit: int(ModeInherit),
		ModeJWTOnly: int(ModeJWTOnly),
		ModeHybrid:  int(ModeHybrid),
		ModeStrict:  int(ModeStrict),
	})
	if !ok {
		return 0, ErrInvalidRouteMode
	}
	return ValidationMode(mode), nil
}

func parseTenantIDToUint32(tenantID string) uint32 {
	if tenantID == "" || tenantID == "0" {
		return 0
	}

	v, err := strconv.ParseUint(tenantID, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func (e *Engine) enforceSessionHardeningOnLogin(ctx context.Context, tenantID, userID string) error {
	h := e.config.SessionHardening
	if e.sessionStore == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}

	if h.EnforceSingleSession {
		if err := e.sessionStore.DeleteAllForUser(ctx, tenantID, userID); err != nil {
			return err
		}
	}

	currentUserSessions, err := e.sessionStore.ActiveSessionCount(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	if h.ConcurrentLoginLimit > 0 && currentUserSessions >= h.ConcurrentLoginLimit {
		return ErrSessionLimitExceeded
	}
	if h.MaxSessionsPerUser > 0 && currentUserSessions >= h.MaxSessionsPerUser {
		return ErrSessionLimitExceeded
	}
	if h.MaxSessionsPerTenant > 0 {
		tenantSessions, err := e.sessionStore.TenantSessionCount(ctx, tenantID)
		if err != nil {
			return err
		}

		if tenantSessions >= h.MaxSessionsPerTenant {
			// Counter can drift when sessions expire naturally; reconcile before denying.
			actual, scanErr := e.sessionStore.EstimateActiveSessions(ctx, tenantID)
			if scanErr == nil {
				tenantSessions = actual
				if setErr := e.sessionStore.SetTenantSessionCount(ctx, tenantID, actual); setErr != nil {
					e.warn("goAuth: tenant session counter reconciliation failed")
				}
			}
		}
		if tenantSessions >= h.MaxSessionsPerTenant {
			return ErrTenantSessionLimitExceeded
		}
	}

	return nil
}

func (e *Engine) enforceTOTPForLogin(ctx context.Context, user UserRecord, totpCode string) error {
	if e == nil || !e.config.TOTP.Enabled || !e.config.TOTP.RequireForLogin {
		return nil
	}
	if e.totp == nil || e.totpLimiter == nil || e.userProvider == nil {
		return ErrEngineNotReady
	}

	record, err := e.userProvider.GetTOTPSecret(ctx, user.UserID)
	if err != nil {
		return ErrTOTPUnavailable
	}
	if record == nil || !record.Enabled || len(record.Secret) == 0 {
		return nil
	}

	if err := e.totpLimiter.Check(ctx, user.UserID); err != nil {
		e.metricInc(MetricTOTPFailure)
		if errors.Is(err, limiters.ErrTOTPRateLimited) {
			e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPRateLimited, nil)
			return ErrTOTPRateLimited
		}
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPUnavailable, nil)
		return ErrTOTPUnavailable
	}

	if totpCode == "" {
		e.metricInc(MetricTOTPRequired)
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPRequired, nil)
		return ErrTOTPRequired
	}

	ok, counter, err := e.totp.VerifyCode(record.Secret, totpCode, time.Now())
	if err != nil {
		e.metricInc(MetricTOTPFailure)
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPInvalid, nil)
		return ErrTOTPInvalid
	}
	if !ok {
		recErr := e.totpLimiter.RecordFailure(ctx, user.UserID)
		e.metricInc(MetricTOTPFailure)
		if recErr != nil {
			if errors.Is(recErr, limiters.ErrTOTPRateLimited) {
				e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPRateLimited, nil)
				return ErrTOTPRateLimited
			}
			e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPUnavailable, nil)
			return ErrTOTPUnavailable
		}
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPInvalid, nil)
		return ErrTOTPInvalid
	}
	if e.config.TOTP.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			e.metricInc(MetricTOTPFailure)
			e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPInvalid, nil)
			return ErrTOTPInvalid
		}
		if err := e.userProvider.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
			e.metricInc(MetricTOTPFailure)
			e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPUnavailable, nil)
			return ErrTOTPUnavailable
		}
	}

	if err := e.totpLimiter.Reset(ctx, user.UserID); err != nil {
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPUnavailable, nil)
		return ErrTOTPUnavailable
	}
	e.metricInc(MetricTOTPSuccess)
	e.emitAudit(ctx, auditEventTOTPSuccess, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

func tenantIDFromToken(tid uint32) string {
	return strconv.FormatUint(uint64(tid), 10)
}
