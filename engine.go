package goAuth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	internalaudit "github.com/MrEthical07/goAuth/internal/audit"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/rate"
	internalsecurity "github.com/MrEthical07/goAuth/internal/security"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/jwt"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/google/uuid"
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

// CreateAccount describes the createaccount operation and its observable behavior.
//
// CreateAccount may return an error when input validation, dependency calls, or security checks fail.
// CreateAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) CreateAccount(ctx context.Context, req CreateAccountRequest) (*CreateAccountResult, error) {
	result, err := internalflows.RunCreateAccount(ctx, toFlowAccountCreateRequest(req), e.accountFlowDeps())
	out := fromFlowAccountCreateResult(result)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (e *Engine) issueSessionTokens(ctx context.Context, user UserRecord) (string, string, error) {
	return internalflows.RunIssueAccountSessionTokens(ctx, toFlowAccountUser(user), e.accountSessionDeps())
}

func (e *Engine) accountFlowDeps() internalflows.AccountDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.AccountDeps{
		Enabled:                     cfg.Account.Enabled,
		AutoLogin:                   cfg.Account.AutoLogin,
		RefreshTTL:                  cfg.JWT.RefreshTTL,
		MultiTenantEnabled:          cfg.MultiTenant.Enabled,
		DefaultRole:                 cfg.Account.DefaultRole,
		EmailVerificationEnabled:    cfg.EmailVerification.Enabled,
		ShouldRequireVerified:       e != nil && e.shouldRequireVerified(),
		ActiveStatus:                uint8(AccountActive),
		PendingStatus:               uint8(AccountPendingVerification),
		TenantIDFromContext:         tenantIDFromContext,
		TenantIDFromContextExplicit: tenantIDFromContextExplicit,
		ClientIPFromContext:         clientIPFromContext,
		MapLimiterError:             mapAccountLimiterError,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit:     e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Metrics: internalflows.AccountMetrics{
			AccountCreationSuccess:     int(MetricAccountCreationSuccess),
			AccountCreationDuplicate:   int(MetricAccountCreationDuplicate),
			AccountCreationRateLimited: int(MetricAccountCreationRateLimited),
		},
		Events: internalflows.AccountEvents{
			AccountCreationSuccess:     auditEventAccountCreationSuccess,
			AccountCreationFailure:     auditEventAccountCreationFailure,
			AccountCreationDuplicate:   auditEventAccountCreationDuplicate,
			AccountCreationRateLimited: auditEventAccountCreationRateLimited,
		},
		Errors: internalflows.AccountErrors{
			EngineNotReady:              ErrEngineNotReady,
			AccountCreationDisabled:     ErrAccountCreationDisabled,
			AccountCreationUnavailable:  ErrAccountCreationUnavailable,
			AccountCreationInvalid:      ErrAccountCreationInvalid,
			AccountRoleInvalid:          ErrAccountRoleInvalid,
			AccountCreationRateLimited:  ErrAccountCreationRateLimited,
			PasswordPolicy:              ErrPasswordPolicy,
			AccountExists:               ErrAccountExists,
			ProviderDuplicateIdentifier: ErrProviderDuplicateIdentifier,
			SessionCreationFailed:       ErrSessionCreationFailed,
		},
	}

	if e != nil && e.accountLimiter != nil {
		deps.EnforceAccountLimiter = e.accountLimiter.Enforce
	}
	if e != nil && e.roleManager != nil {
		deps.RoleExists = func(role string) bool {
			_, ok := e.roleManager.GetMask(role)
			return ok
		}
	}
	if e != nil && e.passwordHash != nil {
		deps.HashPassword = e.passwordHash.Hash
	}
	if e != nil && e.userProvider != nil {
		deps.CreateUser = func(ctx context.Context, input internalflows.AccountCreateUserInput) (internalflows.AccountUserRecord, error) {
			record, err := e.userProvider.CreateUser(ctx, CreateUserInput{
				Identifier:        input.Identifier,
				PasswordHash:      input.PasswordHash,
				Role:              input.Role,
				TenantID:          input.TenantID,
				Status:            AccountStatus(input.Status),
				PermissionVersion: input.PermissionVersion,
				RoleVersion:       input.RoleVersion,
				AccountVersion:    input.AccountVersion,
			})
			if err != nil {
				return internalflows.AccountUserRecord{}, err
			}
			return toFlowAccountUser(record), nil
		}
	}
	if e != nil {
		deps.IssueSessionTokens = func(ctx context.Context, user internalflows.AccountUserRecord) (string, string, error) {
			return e.issueSessionTokens(ctx, fromFlowAccountUser(user))
		}
	}

	return deps
}

func (e *Engine) accountSessionDeps() internalflows.AccountSessionDeps {
	deps := internalflows.AccountSessionDeps{
		TenantIDFromContext: tenantIDFromContext,
		Now:                 time.Now,
		NewSessionID: func() (string, error) {
			sid, err := internal.NewSessionID()
			if err != nil {
				return "", err
			}
			return sid.String(), nil
		},
		NewRefreshSecret:   internal.NewRefreshSecret,
		HashRefreshSecret:  internal.HashRefreshSecret,
		EncodeRefreshToken: internal.EncodeRefreshToken,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		SessionCreatedMetric:  int(MetricSessionCreated),
		ErrEngineNotReady:     ErrEngineNotReady,
		ErrAccountRoleInvalid: ErrAccountRoleInvalid,
	}

	if e != nil && e.roleManager != nil {
		deps.GetRoleMask = e.roleManager.GetMask
	}
	if e != nil {
		deps.SessionLifetime = e.sessionLifetime
		deps.IssueAccessToken = e.issueAccessToken
	}
	if e != nil && e.sessionStore != nil {
		deps.SaveSession = e.sessionStore.Save
	}

	return deps
}

func toFlowAccountCreateRequest(req CreateAccountRequest) internalflows.AccountCreateRequest {
	return internalflows.AccountCreateRequest{
		Identifier: req.Identifier,
		Password:   req.Password,
		Role:       req.Role,
	}
}

func fromFlowAccountCreateResult(result *internalflows.AccountCreateResult) *CreateAccountResult {
	if result == nil {
		return nil
	}
	return &CreateAccountResult{
		UserID:       result.UserID,
		Role:         result.Role,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	}
}

func toFlowAccountUser(user UserRecord) internalflows.AccountUserRecord {
	return internalflows.AccountUserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Status:            uint8(user.Status),
		Role:              user.Role,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowAccountUser(user internalflows.AccountUserRecord) UserRecord {
	return UserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Status:            AccountStatus(user.Status),
		Role:              user.Role,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func mapAccountLimiterError(err error) error {
	switch {
	case errors.Is(err, limiters.ErrAccountRateLimited):
		return ErrAccountCreationRateLimited
	case errors.Is(err, limiters.ErrAccountRedisUnavailable):
		return ErrAccountCreationUnavailable
	default:
		return ErrAccountCreationUnavailable
	}
}

// DisableAccount describes the disableaccount operation and its observable behavior.
//
// DisableAccount may return an error when input validation, dependency calls, or security checks fail.
// DisableAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DisableAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountDisabled)
	if err == nil {
		e.metricInc(MetricAccountDisabled)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "disable",
		}
	})
	return err
}

// EnableAccount describes the enableaccount operation and its observable behavior.
//
// EnableAccount may return an error when input validation, dependency calls, or security checks fail.
// EnableAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) EnableAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountActive)
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "enable",
		}
	})
	return err
}

// LockAccount describes the lockaccount operation and its observable behavior.
//
// LockAccount may return an error when input validation, dependency calls, or security checks fail.
// LockAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LockAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountLocked)
	if err == nil {
		e.metricInc(MetricAccountLocked)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "lock",
		}
	})
	return err
}

// DeleteAccount describes the deleteaccount operation and its observable behavior.
//
// DeleteAccount may return an error when input validation, dependency calls, or security checks fail.
// DeleteAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DeleteAccount(ctx context.Context, userID string) error {
	err := e.updateAccountStatusAndInvalidate(ctx, userID, AccountDeleted)
	if err == nil {
		e.metricInc(MetricAccountDeleted)
	}
	e.emitAudit(ctx, auditEventAccountStatusChange, err == nil, userID, tenantIDFromContext(ctx), "", err, func() map[string]string {
		return map[string]string{
			"action": "delete",
		}
	})
	return err
}

func (e *Engine) updateAccountStatusAndInvalidate(ctx context.Context, userID string, status AccountStatus) error {
	if e == nil || e.userProvider == nil {
		return ErrEngineNotReady
	}

	return internalflows.RunUpdateAccountStatusAndInvalidate(ctx, userID, uint8(status), internalflows.UpdateAccountStatusDeps{
		GetUserByID: func(userID string) (internalflows.AccountStatusRecord, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.AccountStatusRecord{}, err
			}
			return internalflows.AccountStatusRecord{
				Status:         uint8(user.Status),
				AccountVersion: user.AccountVersion,
				TenantID:       user.TenantID,
			}, nil
		},
		UpdateAccountStatus: func(ctx context.Context, userID string, status uint8) (internalflows.AccountStatusRecord, error) {
			user, err := e.userProvider.UpdateAccountStatus(ctx, userID, AccountStatus(status))
			if err != nil {
				return internalflows.AccountStatusRecord{}, err
			}
			return internalflows.AccountStatusRecord{
				Status:         uint8(user.Status),
				AccountVersion: user.AccountVersion,
				TenantID:       user.TenantID,
			}, nil
		},
		LogoutAllInTenant:            e.LogoutAllInTenant,
		TenantIDFromContext:          tenantIDFromContext,
		ErrEngineNotReady:            ErrEngineNotReady,
		ErrUserNotFound:              ErrUserNotFound,
		ErrAccountVersionNotAdvanced: ErrAccountVersionNotAdvanced,
		ErrUnauthorized:              ErrUnauthorized,
		ErrSessionInvalidationFailed: ErrSessionInvalidationFailed,
	})
}

func accountStatusToError(status AccountStatus) error {
	switch status {
	case AccountActive:
		return nil
	case AccountPendingVerification:
		return nil
	case AccountDisabled:
		return ErrAccountDisabled
	case AccountLocked:
		return ErrAccountLocked
	case AccountDeleted:
		return ErrAccountDeleted
	default:
		return ErrUnauthorized
	}
}

func (e *Engine) shouldRequireVerified() bool {
	return e.config.EmailVerification.Enabled && e.config.EmailVerification.RequireForLogin
}

const (
	auditEventLoginSuccess               = "login_success"
	auditEventLoginFailure               = "login_failure"
	auditEventLoginRateLimited           = "login_rate_limited"
	auditEventRefreshSuccess             = "refresh_success"
	auditEventRefreshInvalid             = "refresh_invalid"
	auditEventRefreshRateLimited         = "refresh_rate_limited"
	auditEventRefreshReuseDetected       = "refresh_reuse_detected"
	auditEventPasswordChangeSuccess      = "password_change_success"
	auditEventPasswordChangeInvalidOld   = "password_change_invalid_old"
	auditEventPasswordChangeReuse        = "password_change_reuse_attempt"
	auditEventPasswordChangeFailure      = "password_change_failure"
	auditEventPasswordResetRequest       = "password_reset_request"
	auditEventPasswordResetConfirm       = "password_reset_confirm"
	auditEventPasswordResetReplay        = "password_reset_replay"
	auditEventEmailVerificationRequest   = "email_verification_request"
	auditEventEmailVerificationConfirm   = "email_verification_confirm"
	auditEventAccountCreationSuccess     = "account_creation_success"
	auditEventAccountCreationFailure     = "account_creation_failure"
	auditEventAccountCreationDuplicate   = "account_creation_duplicate"
	auditEventAccountCreationRateLimited = "account_creation_rate_limited"
	auditEventAccountStatusChange        = "account_status_change"
	auditEventLogoutSession              = "logout_session"
	auditEventLogoutAll                  = "logout_all"
	auditEventRateLimitTriggered         = "rate_limit_triggered"
	auditEventDeviceAnomalyDetected      = "device_anomaly_detected"
	auditEventDeviceBindingRejected      = "device_binding_rejected"
	auditEventTOTPSetupRequested         = "totp_setup_requested"
	auditEventTOTPEnabled                = "totp_enabled"
	auditEventTOTPDisabled               = "totp_disabled"
	auditEventTOTPFailure                = "totp_failure"
	auditEventTOTPSuccess                = "totp_success"
	auditEventMFARequired                = "mfa_required"
	auditEventMFASuccess                 = "mfa_success"
	auditEventMFAFailure                 = "mfa_failure"
	auditEventMFAAttemptsExceeded        = "mfa_attempts_exceeded"
	auditEventBackupCodesGenerated       = "backup_codes_generated"
	auditEventBackupCodeUsed             = "backup_code_used"
	auditEventBackupCodeFailed           = "backup_code_failed"
)

// AuditErrorCode defines a public type used by goAuth APIs.
//
// AuditErrorCode instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuditErrorCode string

const (
	auditErrUnauthorized          AuditErrorCode = "unauthorized"
	auditErrInvalidCredentials    AuditErrorCode = "invalid_credentials"
	auditErrRateLimited           AuditErrorCode = "rate_limited"
	auditErrRefreshReuse          AuditErrorCode = "refresh_reuse"
	auditErrInvalidToken          AuditErrorCode = "invalid_token"
	auditErrSessionNotFound       AuditErrorCode = "session_not_found"
	auditErrUserNotFound          AuditErrorCode = "user_not_found"
	auditErrAccountDisabled       AuditErrorCode = "account_disabled"
	auditErrAccountLocked         AuditErrorCode = "account_locked"
	auditErrAccountDeleted        AuditErrorCode = "account_deleted"
	auditErrAccountUnverified     AuditErrorCode = "account_unverified"
	auditErrPasswordPolicy        AuditErrorCode = "password_policy"
	auditErrPasswordReuse         AuditErrorCode = "password_reuse"
	auditErrAttemptsExceeded      AuditErrorCode = "attempts_exceeded"
	auditErrSessionCreationFailed AuditErrorCode = "session_creation_failed"
	auditErrSessionInvalidation   AuditErrorCode = "session_invalidation_failed"
	auditErrSessionLimitExceeded  AuditErrorCode = "session_limit_exceeded"
	auditErrDeviceBindingRejected AuditErrorCode = "device_binding_rejected"
	auditErrTOTPRequired          AuditErrorCode = "totp_required"
	auditErrTOTPInvalid           AuditErrorCode = "totp_invalid"
	auditErrTOTPRateLimited       AuditErrorCode = "totp_rate_limited"
	auditErrMFARequired           AuditErrorCode = "mfa_required"
	auditErrMFAInvalid            AuditErrorCode = "mfa_invalid"
	auditErrMFAAttemptsExceeded   AuditErrorCode = "mfa_attempts_exceeded"
	auditErrMFAReplay             AuditErrorCode = "mfa_replay"
	auditErrBackupCodeInvalid     AuditErrorCode = "backup_code_invalid"
	auditErrBackupCodeRateLimited AuditErrorCode = "backup_code_rate_limited"
	auditErrDuplicate             AuditErrorCode = "duplicate"
	auditErrUnavailable           AuditErrorCode = "backend_unavailable"
	auditErrInternal              AuditErrorCode = "internal_error"
)

func (e *Engine) emitAudit(
	ctx context.Context,
	eventType string,
	success bool,
	userID string,
	tenantID string,
	sessionID string,
	err error,
	metadataBuilder func() map[string]string,
) {
	if e == nil || e.audit == nil {
		return
	}
	if tenantID == "" {
		tenantID = tenantIDFromContext(ctx)
	}

	var metadata map[string]string
	if metadataBuilder != nil {
		metadata = metadataBuilder()
	}

	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		IP:        clientIPFromContext(ctx),
		Success:   success,
		Metadata:  metadata,
	}
	if code := auditErrorCode(err); code != "" {
		event.Error = string(code)
	}

	e.audit.Emit(ctx, event)
}

func (e *Engine) emitRateLimit(
	ctx context.Context,
	scope string,
	tenantID string,
	metadataBuilder func() map[string]string,
) {
	e.metricInc(MetricRateLimitHit)
	e.emitAudit(ctx, auditEventRateLimitTriggered, false, "", tenantID, "", nil, func() map[string]string {
		base := map[string]string{
			"scope": scope,
		}
		if metadataBuilder == nil {
			return base
		}
		for k, v := range metadataBuilder() {
			base[k] = v
		}
		return base
	})
}

func auditErrorCode(err error) AuditErrorCode {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrUnauthorized):
		return auditErrUnauthorized
	case errors.Is(err, ErrInvalidCredentials):
		return auditErrInvalidCredentials
	case errors.Is(err, ErrLoginRateLimited),
		errors.Is(err, ErrRefreshRateLimited),
		errors.Is(err, ErrPasswordResetRateLimited),
		errors.Is(err, ErrEmailVerificationRateLimited),
		errors.Is(err, ErrAccountCreationRateLimited):
		return auditErrRateLimited
	case errors.Is(err, ErrRefreshReuse):
		return auditErrRefreshReuse
	case errors.Is(err, ErrRefreshInvalid),
		errors.Is(err, ErrPasswordResetInvalid),
		errors.Is(err, ErrEmailVerificationInvalid),
		errors.Is(err, ErrTokenInvalid),
		errors.Is(err, ErrTokenClockSkew):
		return auditErrInvalidToken
	case errors.Is(err, ErrSessionNotFound):
		return auditErrSessionNotFound
	case errors.Is(err, ErrUserNotFound):
		return auditErrUserNotFound
	case errors.Is(err, ErrAccountDisabled):
		return auditErrAccountDisabled
	case errors.Is(err, ErrAccountLocked):
		return auditErrAccountLocked
	case errors.Is(err, ErrAccountDeleted):
		return auditErrAccountDeleted
	case errors.Is(err, ErrAccountUnverified):
		return auditErrAccountUnverified
	case errors.Is(err, ErrPasswordPolicy):
		return auditErrPasswordPolicy
	case errors.Is(err, ErrPasswordReuse):
		return auditErrPasswordReuse
	case errors.Is(err, ErrPasswordResetAttempts),
		errors.Is(err, ErrEmailVerificationAttempts):
		return auditErrAttemptsExceeded
	case errors.Is(err, ErrSessionCreationFailed):
		return auditErrSessionCreationFailed
	case errors.Is(err, ErrSessionInvalidationFailed):
		return auditErrSessionInvalidation
	case errors.Is(err, ErrSessionLimitExceeded),
		errors.Is(err, ErrTenantSessionLimitExceeded):
		return auditErrSessionLimitExceeded
	case errors.Is(err, ErrDeviceBindingRejected):
		return auditErrDeviceBindingRejected
	case errors.Is(err, ErrTOTPRequired):
		return auditErrTOTPRequired
	case errors.Is(err, ErrTOTPInvalid),
		errors.Is(err, ErrTOTPNotConfigured):
		return auditErrTOTPInvalid
	case errors.Is(err, ErrTOTPRateLimited):
		return auditErrTOTPRateLimited
	case errors.Is(err, ErrMFALoginRequired):
		return auditErrMFARequired
	case errors.Is(err, ErrMFALoginInvalid),
		errors.Is(err, ErrMFALoginExpired):
		return auditErrMFAInvalid
	case errors.Is(err, ErrMFALoginAttemptsExceeded):
		return auditErrMFAAttemptsExceeded
	case errors.Is(err, ErrMFALoginReplay):
		return auditErrMFAReplay
	case errors.Is(err, ErrBackupCodeInvalid),
		errors.Is(err, ErrBackupCodesNotConfigured),
		errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP):
		return auditErrBackupCodeInvalid
	case errors.Is(err, ErrBackupCodeRateLimited):
		return auditErrBackupCodeRateLimited
	case errors.Is(err, ErrTOTPFeatureDisabled),
		errors.Is(err, ErrTOTPUnavailable),
		errors.Is(err, ErrMFALoginUnavailable),
		errors.Is(err, ErrBackupCodeUnavailable):
		return auditErrUnavailable
	case errors.Is(err, ErrAccountExists),
		errors.Is(err, ErrProviderDuplicateIdentifier):
		return auditErrDuplicate
	case errors.Is(err, ErrPasswordResetUnavailable),
		errors.Is(err, ErrEmailVerificationUnavailable),
		errors.Is(err, ErrAccountCreationUnavailable),
		errors.Is(err, ErrTOTPUnavailable),
		errors.Is(err, ErrMFALoginUnavailable),
		errors.Is(err, ErrBackupCodeUnavailable),
		errors.Is(err, ErrStrictBackendDown):
		return auditErrUnavailable
	default:
		return auditErrInternal
	}
}

// GenerateBackupCodes describes the generatebackupcodes operation and its observable behavior.
//
// GenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// GenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	return internalflows.RunGenerateBackupCodes(ctx, userID, e.backupCodeFlowDeps())
}

// RegenerateBackupCodes describes the regeneratebackupcodes operation and its observable behavior.
//
// RegenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// RegenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	return internalflows.RunRegenerateBackupCodes(ctx, userID, totpCode, e.backupCodeFlowDeps())
}

// VerifyBackupCode describes the verifybackupcode operation and its observable behavior.
//
// VerifyBackupCode may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCode does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCode(ctx context.Context, userID, code string) error {
	return internalflows.RunVerifyBackupCode(ctx, userID, code, e.backupCodeFlowDeps())
}

// VerifyBackupCodeInTenant describes the verifybackupcodeintenant operation and its observable behavior.
//
// VerifyBackupCodeInTenant may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCodeInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCodeInTenant(ctx context.Context, tenantID, userID, code string) error {
	return internalflows.RunVerifyBackupCodeInTenant(ctx, tenantID, userID, code, e.backupCodeFlowDeps())
}

func (e *Engine) backupCodeFlowDeps() internalflows.BackupCodeDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.BackupCodeDeps{
		Enabled:             cfg.TOTP.Enabled,
		BackupCodeCount:     cfg.TOTP.BackupCodeCount,
		BackupCodeLength:    cfg.TOTP.BackupCodeLength,
		TenantIDFromContext: tenantIDFromContext,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		IsRateLimited: func(err error) bool {
			return errors.Is(err, limiters.ErrBackupCodeRateLimited)
		},
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit: e.emitAudit,
		Metrics: internalflows.BackupCodeMetrics{
			BackupCodeUsed:        int(MetricBackupCodeUsed),
			BackupCodeFailed:      int(MetricBackupCodeFailed),
			BackupCodeRegenerated: int(MetricBackupCodeRegenerated),
		},
		Events: internalflows.BackupCodeEvents{
			BackupCodesGenerated: auditEventBackupCodesGenerated,
			BackupCodeUsed:       auditEventBackupCodeUsed,
			BackupCodeFailed:     auditEventBackupCodeFailed,
		},
		Errors: internalflows.BackupCodeErrors{
			TOTPFeatureDisabled:                ErrTOTPFeatureDisabled,
			EngineNotReady:                     ErrEngineNotReady,
			UserNotFound:                       ErrUserNotFound,
			BackupCodeUnavailable:              ErrBackupCodeUnavailable,
			BackupCodeRegenerationRequiresTOTP: ErrBackupCodeRegenerationRequiresTOTP,
			BackupCodeInvalid:                  ErrBackupCodeInvalid,
			BackupCodeRateLimited:              ErrBackupCodeRateLimited,
		},
	}

	if e != nil && e.userProvider != nil {
		deps.GetUserByID = func(userID string) (internalflows.BackupCodeUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.BackupCodeUser{}, err
			}
			return toFlowBackupCodeUser(user), nil
		}
		deps.GetBackupCodes = func(ctx context.Context, userID string) ([]internalflows.BackupCodeRecord, error) {
			records, err := e.userProvider.GetBackupCodes(ctx, userID)
			if err != nil {
				return nil, err
			}
			return toFlowBackupCodeRecords(records), nil
		}
		deps.ReplaceBackupCodes = func(ctx context.Context, userID string, records []internalflows.BackupCodeRecord) error {
			return e.userProvider.ReplaceBackupCodes(ctx, userID, fromFlowBackupCodeRecords(records))
		}
		deps.ConsumeBackupCode = e.userProvider.ConsumeBackupCode
	}
	if e != nil {
		deps.VerifyTOTPForUser = func(ctx context.Context, user internalflows.BackupCodeUser, code string) error {
			return e.verifyTOTPForUser(ctx, fromFlowBackupCodeUser(user), code)
		}
	}
	if e != nil && e.backupLimiter != nil {
		deps.CheckLimiter = e.backupLimiter.Check
		deps.RecordLimiterFailure = e.backupLimiter.RecordFailure
		deps.ResetLimiter = e.backupLimiter.Reset
	}

	return deps
}

func toFlowBackupCodeUser(user UserRecord) internalflows.BackupCodeUser {
	return internalflows.BackupCodeUser{
		UserID:   user.UserID,
		TenantID: user.TenantID,
		Status:   uint8(user.Status),
	}
}

func fromFlowBackupCodeUser(user internalflows.BackupCodeUser) UserRecord {
	return UserRecord{
		UserID:   user.UserID,
		TenantID: user.TenantID,
		Status:   AccountStatus(user.Status),
	}
}

func toFlowBackupCodeRecords(records []BackupCodeRecord) []internalflows.BackupCodeRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]internalflows.BackupCodeRecord, 0, len(records))
	for _, record := range records {
		out = append(out, internalflows.BackupCodeRecord{
			Hash: record.Hash,
		})
	}
	return out
}

func fromFlowBackupCodeRecords(records []internalflows.BackupCodeRecord) []BackupCodeRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]BackupCodeRecord, 0, len(records))
	for _, record := range records {
		out = append(out, BackupCodeRecord{
			Hash: record.Hash,
		})
	}
	return out
}

func newBackupCode(length int) (string, error) {
	return internalflows.NewBackupCode(length, nil)
}

func formatBackupCode(code string) string {
	return internalflows.FormatBackupCode(code)
}

func canonicalizeBackupCode(code string) string {
	return internalflows.CanonicalizeBackupCode(code)
}

func backupCodeHash(userID, canonicalCode string) [32]byte {
	return internalflows.BackupCodeHash(userID, canonicalCode)
}

const deviceAnomalyWindow = time.Minute

func (e *Engine) validateDeviceBinding(ctx context.Context, sess *session.Session) error {
	if e == nil || sess == nil || !e.config.DeviceBinding.Enabled {
		return nil
	}
	return internalflows.RunValidateDeviceBinding(ctx, internalflows.DeviceBindingSession{
		SessionID:     sess.SessionID,
		UserID:        sess.UserID,
		TenantID:      sess.TenantID,
		IPHash:        sess.IPHash,
		UserAgentHash: sess.UserAgentHash,
	}, internalflows.DeviceBindingDeps{
		Config: internalflows.DeviceBindingConfig{
			Enabled:                 e.config.DeviceBinding.Enabled,
			EnforceIPBinding:        e.config.DeviceBinding.EnforceIPBinding,
			DetectIPChange:          e.config.DeviceBinding.DetectIPChange,
			EnforceUserAgentBinding: e.config.DeviceBinding.EnforceUserAgentBinding,
			DetectUserAgentChange:   e.config.DeviceBinding.DetectUserAgentChange,
		},
		ClientIPFromContext:        clientIPFromContext,
		UserAgentFromContext:       userAgentFromContext,
		HashBindingValue:           internal.HashBindingValue,
		ShouldEmitDeviceAnomaly:    e.shouldEmitDeviceAnomaly,
		MetricInc:                  func(id int) { e.metricInc(MetricID(id)) },
		EmitAudit:                  e.emitAudit,
		EventDeviceAnomalyDetected: auditEventDeviceAnomalyDetected,
		EventDeviceBindingRejected: auditEventDeviceBindingRejected,
		MetricDeviceIPMismatch:     int(MetricDeviceIPMismatch),
		MetricDeviceUAMismatch:     int(MetricDeviceUAMismatch),
		MetricDeviceRejected:       int(MetricDeviceRejected),
		ErrDeviceBindingRejected:   ErrDeviceBindingRejected,
	})
}

func (e *Engine) shouldEmitDeviceAnomaly(ctx context.Context, sessionID, kind string) bool {
	if e == nil || e.sessionStore == nil || sessionID == "" {
		return true
	}
	ok, err := e.sessionStore.ShouldEmitDeviceAnomaly(ctx, sessionID, kind, deviceAnomalyWindow)
	if err != nil {
		return false
	}
	return ok
}

// RequestEmailVerification describes the requestemailverification operation and its observable behavior.
//
// RequestEmailVerification may return an error when input validation, dependency calls, or security checks fail.
// RequestEmailVerification does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RequestEmailVerification(ctx context.Context, identifier string) (string, error) {
	return internalflows.RunRequestEmailVerification(ctx, identifier, e.emailVerificationFlowDeps())
}

// ConfirmEmailVerification describes the confirmemailverification operation and its observable behavior.
//
// ConfirmEmailVerification may return an error when input validation, dependency calls, or security checks fail.
// ConfirmEmailVerification does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmEmailVerification(ctx context.Context, challenge string) error {
	return internalflows.RunConfirmEmailVerification(ctx, challenge, e.emailVerificationFlowDeps())
}

func (e *Engine) emailVerificationFlowDeps() internalflows.EmailVerificationDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.EmailVerificationDeps{
		Enabled:             cfg.EmailVerification.Enabled,
		Strategy:            int(cfg.EmailVerification.Strategy),
		OTPDigits:           cfg.EmailVerification.OTPDigits,
		VerificationTTL:     cfg.EmailVerification.VerificationTTL,
		MaxAttempts:         cfg.EmailVerification.MaxAttempts,
		ActiveStatus:        uint8(AccountActive),
		TenantIDFromContext: tenantIDFromContext,
		ClientIPFromContext: clientIPFromContext,
		Now:                 time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MapLimiterError: mapEmailVerificationLimiterError,
		MapStoreError:   mapEmailVerificationStoreError,
		GenerateChallenge: func(strategy int, otpDigits int) (string, string, [32]byte, error) {
			return generateEmailVerificationChallenge(VerificationStrategyType(strategy), otpDigits)
		},
		ParseChallenge: func(strategy int, challenge string, otpDigits int) (string, [32]byte, error) {
			return parseEmailVerificationChallenge(VerificationStrategyType(strategy), challenge, otpDigits)
		},
		SleepEnumerationDelay: sleepPasswordResetEnumerationDelay,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit:     e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Metrics: internalflows.EmailVerificationMetrics{
			EmailVerificationRequest:          int(MetricEmailVerificationRequest),
			EmailVerificationSuccess:          int(MetricEmailVerificationSuccess),
			EmailVerificationFailure:          int(MetricEmailVerificationFailure),
			EmailVerificationAttemptsExceeded: int(MetricEmailVerificationAttemptsExceeded),
		},
		Events: internalflows.EmailVerificationEvents{
			EmailVerificationRequest: auditEventEmailVerificationRequest,
			EmailVerificationConfirm: auditEventEmailVerificationConfirm,
		},
		Errors: internalflows.EmailVerificationErrors{
			EngineNotReady:               ErrEngineNotReady,
			EmailVerificationDisabled:    ErrEmailVerificationDisabled,
			EmailVerificationInvalid:     ErrEmailVerificationInvalid,
			EmailVerificationRateLimited: ErrEmailVerificationRateLimited,
			EmailVerificationUnavailable: ErrEmailVerificationUnavailable,
			EmailVerificationAttempts:    ErrEmailVerificationAttempts,
			UserNotFound:                 ErrUserNotFound,
		},
	}

	if e != nil && e.verificationLimiter != nil {
		deps.CheckRequestLimiter = e.verificationLimiter.CheckRequest
		deps.CheckConfirmLimiter = e.verificationLimiter.CheckConfirm
	}
	if e != nil && e.userProvider != nil {
		deps.GetUserByIdentifier = func(identifier string) (internalflows.EmailVerificationUser, error) {
			user, err := e.userProvider.GetUserByIdentifier(identifier)
			if err != nil {
				return internalflows.EmailVerificationUser{}, err
			}
			return internalflows.EmailVerificationUser{
				UserID:   user.UserID,
				TenantID: user.TenantID,
				Status:   uint8(user.Status),
			}, nil
		}
		deps.GetUserByID = func(userID string) (internalflows.EmailVerificationUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.EmailVerificationUser{}, err
			}
			return internalflows.EmailVerificationUser{
				UserID:   user.UserID,
				TenantID: user.TenantID,
				Status:   uint8(user.Status),
			}, nil
		}
	}
	if e != nil {
		deps.UpdateStatusAndInvalidate = func(ctx context.Context, userID string, status uint8) error {
			return e.updateAccountStatusAndInvalidate(ctx, userID, AccountStatus(status))
		}
	}
	if e != nil && e.verificationStore != nil {
		deps.SaveVerificationRecord = func(ctx context.Context, tenantID, verificationID string, record internalflows.EmailVerificationStoreRecord, ttl time.Duration) error {
			return e.verificationStore.Save(ctx, tenantID, verificationID, &stores.EmailVerificationRecord{
				UserID:     record.UserID,
				SecretHash: record.SecretHash,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				Strategy:   record.Strategy,
			}, ttl)
		}
		deps.ConsumeVerificationRecord = func(ctx context.Context, tenantID, verificationID string, providedHash [32]byte, expectedStrategy int, maxAttempts int) (internalflows.EmailVerificationStoreRecord, error) {
			record, err := e.verificationStore.Consume(ctx, tenantID, verificationID, providedHash, expectedStrategy, maxAttempts)
			if err != nil {
				return internalflows.EmailVerificationStoreRecord{}, err
			}
			return internalflows.EmailVerificationStoreRecord{
				UserID:     record.UserID,
				SecretHash: record.SecretHash,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				Strategy:   record.Strategy,
			}, nil
		}
	}

	return deps
}

func generateEmailVerificationChallenge(
	strategy VerificationStrategyType,
	otpDigits int,
) (string, string, [32]byte, error) {
	var emptyHash [32]byte

	switch strategy {
	case VerificationToken:
		verificationID, err := internal.NewSessionID()
		if err != nil {
			return "", "", emptyHash, err
		}

		secret, err := internal.NewResetSecret()
		if err != nil {
			return "", "", emptyHash, err
		}

		challenge, err := internal.EncodeResetToken(verificationID.String(), secret)
		if err != nil {
			return "", "", emptyHash, err
		}

		return verificationID.String(), challenge, internal.HashResetSecret(secret), nil

	case VerificationUUID:
		verificationUUID := uuid.New()
		verificationID := verificationUUID.String()
		return verificationID, verificationID, internal.HashResetBytes([]byte(verificationID)), nil

	case VerificationOTP:
		verificationID, err := internal.NewSessionID()
		if err != nil {
			return "", "", emptyHash, err
		}
		otp, err := internal.NewOTP(otpDigits)
		if err != nil {
			return "", "", emptyHash, err
		}

		challenge := verificationID.String() + "." + otp
		return verificationID.String(), challenge, internal.HashResetBytes([]byte(otp)), nil

	default:
		return "", "", emptyHash, fmt.Errorf("unsupported verification strategy")
	}
}

func parseEmailVerificationChallenge(
	strategy VerificationStrategyType,
	challenge string,
	otpDigits int,
) (string, [32]byte, error) {
	var emptyHash [32]byte

	switch strategy {
	case VerificationToken:
		verificationID, secret, err := internal.DecodeResetToken(challenge)
		if err != nil {
			return "", emptyHash, err
		}
		return verificationID, internal.HashResetSecret(secret), nil

	case VerificationUUID:
		parsed, err := uuid.Parse(challenge)
		if err != nil {
			return "", emptyHash, err
		}
		verificationID := parsed.String()
		return verificationID, internal.HashResetBytes([]byte(verificationID)), nil

	case VerificationOTP:
		parts := strings.SplitN(challenge, ".", 2)
		if len(parts) != 2 {
			return "", emptyHash, errors.New("invalid verification otp challenge format")
		}

		verificationID := parts[0]
		otp := parts[1]
		if _, err := internal.ParseSessionID(verificationID); err != nil {
			return "", emptyHash, err
		}
		if len(otp) != otpDigits {
			return "", emptyHash, errors.New("invalid verification otp length")
		}
		if !isNumericString(otp) {
			return "", emptyHash, errors.New("invalid verification otp format")
		}
		return verificationID, internal.HashResetBytes([]byte(otp)), nil

	default:
		return "", emptyHash, errors.New("unsupported verification strategy")
	}
}

func mapEmailVerificationLimiterError(err error) error {
	switch {
	case errors.Is(err, limiters.ErrVerificationRateLimited):
		return ErrEmailVerificationRateLimited
	case errors.Is(err, limiters.ErrVerificationLimiterUnavailable):
		return ErrEmailVerificationUnavailable
	default:
		return ErrEmailVerificationUnavailable
	}
}

func mapEmailVerificationStoreError(err error) error {
	switch {
	case errors.Is(err, stores.ErrVerificationSecretMismatch),
		errors.Is(err, stores.ErrVerificationNotFound),
		errors.Is(err, redis.Nil):
		return ErrEmailVerificationInvalid
	case errors.Is(err, stores.ErrVerificationAttemptsExceeded):
		return ErrEmailVerificationAttempts
	case errors.Is(err, stores.ErrVerificationRedisUnavailable):
		return ErrEmailVerificationUnavailable
	default:
		return ErrEmailVerificationUnavailable
	}
}

// SessionInfo is the safe introspection view for a session.
// It intentionally excludes refresh hashes, token material, and raw mask bits.
type SessionInfo struct {
	SessionID         string
	CreatedAt         int64
	ExpiresAt         int64
	Role              string
	Status            AccountStatus
	AccountVersion    uint32
	PermissionVersion uint32
}

// HealthStatus is an on-demand backend health result.
type HealthStatus struct {
	RedisAvailable bool
	RedisLatency   time.Duration
}

// GetActiveSessionCount describes the getactivesessioncount operation and its observable behavior.
//
// GetActiveSessionCount may return an error when input validation, dependency calls, or security checks fail.
// GetActiveSessionCount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetActiveSessionCount(ctx context.Context, userID string) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunGetActiveSessionCount(ctx, userID, e.flowDeps.Introspection)
}

// ListActiveSessions describes the listactivesessions operation and its observable behavior.
//
// ListActiveSessions may return an error when input validation, dependency calls, or security checks fail.
// ListActiveSessions does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ListActiveSessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	e.ensureFlowDeps()
	sessions, err := internalflows.RunListActiveSessions(ctx, userID, e.flowDeps.Introspection)
	if err != nil {
		return nil, err
	}

	out := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, toSessionInfo(sess))
	}

	return out, nil
}

// GetSessionInfo describes the getsessioninfo operation and its observable behavior.
//
// GetSessionInfo may return an error when input validation, dependency calls, or security checks fail.
// GetSessionInfo does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetSessionInfo(ctx context.Context, tenantID, sessionID string) (*SessionInfo, error) {
	e.ensureFlowDeps()
	sess, err := internalflows.RunGetSessionInfo(ctx, tenantID, sessionID, e.flowDeps.Introspection)
	if err != nil {
		return nil, err
	}

	info := toSessionInfo(sess)
	return &info, nil
}

// ActiveSessionEstimate describes the activesessionestimate operation and its observable behavior.
//
// ActiveSessionEstimate may return an error when input validation, dependency calls, or security checks fail.
// ActiveSessionEstimate does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ActiveSessionEstimate(ctx context.Context) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunActiveSessionEstimate(ctx, e.flowDeps.Introspection)
}

// Health describes the health operation and its observable behavior.
//
// Health may return an error when input validation, dependency calls, or security checks fail.
// Health does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) Health(ctx context.Context) HealthStatus {
	e.ensureFlowDeps()
	available, latency := internalflows.RunHealth(ctx, e.flowDeps.Introspection)
	return HealthStatus{
		RedisAvailable: available,
		RedisLatency:   latency,
	}
}

// GetLoginAttempts describes the getloginattempts operation and its observable behavior.
//
// GetLoginAttempts may return an error when input validation, dependency calls, or security checks fail.
// GetLoginAttempts does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GetLoginAttempts(ctx context.Context, identifier string) (int, error) {
	e.ensureFlowDeps()
	return internalflows.RunGetLoginAttempts(ctx, identifier, e.flowDeps.Introspection)
}

func toSessionInfo(sess *session.Session) SessionInfo {
	return SessionInfo{
		SessionID:         sess.SessionID,
		CreatedAt:         sess.CreatedAt,
		ExpiresAt:         sess.ExpiresAt,
		Role:              sess.Role,
		Status:            AccountStatus(sess.Status),
		AccountVersion:    sess.AccountVersion,
		PermissionVersion: sess.PermissionVersion,
	}
}

// LoginWithResult describes the loginwithresult operation and its observable behavior.
//
// LoginWithResult may return an error when input validation, dependency calls, or security checks fail.
// LoginWithResult does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LoginWithResult(ctx context.Context, username, password string) (*LoginResult, error) {
	result, err := internalflows.RunLoginWithResult(ctx, username, password, e.loginFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowLoginResult(result), nil
}

// ConfirmLoginMFA describes the confirmloginmfa operation and its observable behavior.
//
// ConfirmLoginMFA may return an error when input validation, dependency calls, or security checks fail.
// ConfirmLoginMFA does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmLoginMFA(ctx context.Context, challengeID, code string) (*LoginResult, error) {
	return e.ConfirmLoginMFAWithType(ctx, challengeID, code, "totp")
}

// ConfirmLoginMFAWithType describes the confirmloginmfawithtype operation and its observable behavior.
//
// ConfirmLoginMFAWithType may return an error when input validation, dependency calls, or security checks fail.
// ConfirmLoginMFAWithType does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmLoginMFAWithType(ctx context.Context, challengeID, code, mfaType string) (*LoginResult, error) {
	result, err := internalflows.RunConfirmLoginMFAWithType(ctx, challengeID, code, mfaType, e.loginFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowLoginResult(result), nil
}

func (e *Engine) loginWithResultInternal(ctx context.Context, username, password string) (*LoginResult, error) {
	return e.LoginWithResult(ctx, username, password)
}

func (e *Engine) createMFALoginChallenge(ctx context.Context, userID, tenantID string) (string, error) {
	return internalflows.RunCreateMFALoginChallenge(ctx, userID, tenantID, e.loginFlowDeps())
}

func (e *Engine) issueLoginSessionTokensForResult(
	ctx context.Context,
	username string,
	user UserRecord,
	tenantID string,
) (string, string, error) {
	return internalflows.RunIssueLoginSessionTokens(ctx, username, toFlowLoginUser(user), tenantID, e.loginFlowDeps())
}

func (e *Engine) loginFlowDeps() internalflows.LoginDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.LoginDeps{
		TOTPEnabled:               cfg.TOTP.Enabled,
		RequireTOTPForLogin:       cfg.TOTP.RequireForLogin,
		EnforceReplayProtection:   cfg.TOTP.EnforceReplayProtection,
		RequireVerified:           e != nil && e.shouldRequireVerified(),
		PendingVerificationStatus: uint8(AccountPendingVerification),
		PasswordUpgradeOnLogin:    cfg.Password.UpgradeOnLogin,
		MFALoginMaxAttempts:       cfg.TOTP.MFALoginMaxAttempts,
		MFALoginChallengeTTL:      cfg.TOTP.MFALoginChallengeTTL,
		DeviceBindingEnabled:      cfg.DeviceBinding.Enabled,
		EnforceIPBinding:          cfg.DeviceBinding.EnforceIPBinding,
		EnforceUserAgentBinding:   cfg.DeviceBinding.EnforceUserAgentBinding,
		TenantIDFromContext:       tenantIDFromContext,
		ClientIPFromContext:       clientIPFromContext,
		UserAgentFromContext:      userAgentFromContext,
		Now:                       time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MetricInc:     func(id int) { e.metricInc(MetricID(id)) },
		EmitAudit:     e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Warn:          e.warn,
		Errors: internalflows.LoginErrors{
			EngineNotReady:           ErrEngineNotReady,
			InvalidCredentials:       ErrInvalidCredentials,
			LoginRateLimited:         ErrLoginRateLimited,
			AccountUnverified:        ErrAccountUnverified,
			DeviceBindingRejected:    ErrDeviceBindingRejected,
			TOTPFeatureDisabled:      ErrTOTPFeatureDisabled,
			MFALoginInvalid:          ErrMFALoginInvalid,
			MFALoginExpired:          ErrMFALoginExpired,
			MFALoginAttemptsExceeded: ErrMFALoginAttemptsExceeded,
			MFALoginReplay:           ErrMFALoginReplay,
			MFALoginUnavailable:      ErrMFALoginUnavailable,
			UserNotFound:             ErrUserNotFound,
			BackupCodeRateLimited:    ErrBackupCodeRateLimited,
			BackupCodeInvalid:        ErrBackupCodeInvalid,
			BackupCodesNotConfigured: ErrBackupCodesNotConfigured,
		},
		Metrics: internalflows.LoginMetrics{
			LoginSuccess:     int(MetricLoginSuccess),
			LoginFailure:     int(MetricLoginFailure),
			LoginRateLimited: int(MetricLoginRateLimited),
			SessionCreated:   int(MetricSessionCreated),
			MFALoginRequired: int(MetricMFALoginRequired),
			MFALoginSuccess:  int(MetricMFALoginSuccess),
			MFALoginFailure:  int(MetricMFALoginFailure),
			MFAReplayAttempt: int(MetricMFAReplayAttempt),
		},
		Events: internalflows.LoginEvents{
			LoginSuccess:        auditEventLoginSuccess,
			LoginFailure:        auditEventLoginFailure,
			LoginRateLimited:    auditEventLoginRateLimited,
			MFARequired:         auditEventMFARequired,
			MFASuccess:          auditEventMFASuccess,
			MFAFailure:          auditEventMFAFailure,
			MFAAttemptsExceeded: auditEventMFAAttemptsExceeded,
		},
	}

	if e != nil && e.rateLimiter != nil {
		deps.CheckLoginRate = e.rateLimiter.CheckLogin
		deps.IncrementLoginRate = e.rateLimiter.IncrementLogin
		deps.ResetLoginRate = e.rateLimiter.ResetLogin
	}
	if e != nil && e.userProvider != nil {
		deps.GetUserByIdentifier = func(identifier string) (internalflows.LoginUserRecord, error) {
			user, err := e.userProvider.GetUserByIdentifier(identifier)
			if err != nil {
				return internalflows.LoginUserRecord{}, err
			}
			return toFlowLoginUser(user), nil
		}
		deps.GetUserByID = func(userID string) (internalflows.LoginUserRecord, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.LoginUserRecord{}, err
			}
			return toFlowLoginUser(user), nil
		}
		deps.UpdatePasswordHash = e.userProvider.UpdatePasswordHash
		deps.GetTOTPSecret = func(ctx context.Context, userID string) (*internalflows.LoginTOTPRecord, error) {
			record, err := e.userProvider.GetTOTPSecret(ctx, userID)
			if err != nil {
				return nil, err
			}
			if record == nil {
				return nil, nil
			}
			return &internalflows.LoginTOTPRecord{
				Secret:          record.Secret,
				Enabled:         record.Enabled,
				LastUsedCounter: record.LastUsedCounter,
			}, nil
		}
		deps.UpdateTOTPLastUsedCounter = e.userProvider.UpdateTOTPLastUsedCounter
	}
	if e != nil && e.passwordHash != nil {
		deps.VerifyPassword = e.passwordHash.Verify
		deps.PasswordNeedsUpgrade = e.passwordHash.NeedsUpgrade
		deps.HashPassword = e.passwordHash.Hash
	}
	if e != nil && e.totp != nil {
		deps.VerifyTOTPCode = e.totp.VerifyCode
	}
	if e != nil {
		deps.VerifyBackupCodeInTenant = e.VerifyBackupCodeInTenant
		deps.CreateMFALoginChallenge = e.createMFALoginChallenge
		deps.IssueLoginSessionTokens = func(ctx context.Context, username string, user internalflows.LoginUserRecord, tenantID string) (string, string, error) {
			return e.issueLoginSessionTokensForResult(ctx, username, fromFlowLoginUser(user), tenantID)
		}
		deps.EnforceSessionHardening = e.enforceSessionHardeningOnLogin
	}
	if e != nil && e.mfaLoginStore != nil {
		deps.GetMFAChallenge = func(ctx context.Context, challengeID string) (*internalflows.MFALoginChallengeRecord, error) {
			record, err := e.mfaLoginStore.Get(ctx, challengeID)
			if err != nil {
				return nil, err
			}
			return &internalflows.MFALoginChallengeRecord{
				UserID:    record.UserID,
				TenantID:  record.TenantID,
				ExpiresAt: record.ExpiresAt,
				Attempts:  record.Attempts,
			}, nil
		}
		deps.SaveMFAChallenge = func(ctx context.Context, challengeID string, record *internalflows.MFALoginChallengeRecord, ttl time.Duration) error {
			return e.mfaLoginStore.Save(ctx, challengeID, &stores.MFALoginChallenge{
				UserID:    record.UserID,
				TenantID:  record.TenantID,
				ExpiresAt: record.ExpiresAt,
				Attempts:  record.Attempts,
			}, ttl)
		}
		deps.DeleteMFAChallenge = e.mfaLoginStore.Delete
		deps.RecordMFAFailure = e.mfaLoginStore.RecordFailure
	}
	deps.MapMFAStoreError = mapMFALoginStoreError
	if e != nil && e.roleManager != nil {
		deps.GetRoleMask = e.roleManager.GetMask
	}
	deps.NewSessionID = func() (string, error) {
		sid, err := internal.NewSessionID()
		if err != nil {
			return "", err
		}
		return sid.String(), nil
	}
	deps.NewRefreshSecret = internal.NewRefreshSecret
	deps.HashRefreshSecret = internal.HashRefreshSecret
	deps.EncodeRefreshToken = internal.EncodeRefreshToken
	deps.HashBindingValue = internal.HashBindingValue
	if e != nil {
		deps.SessionLifetime = e.sessionLifetime
		deps.IssueAccessToken = e.issueAccessToken
	}
	if e != nil && e.sessionStore != nil {
		deps.SaveSession = e.sessionStore.Save
	}

	return deps
}

func toFlowLoginUser(user UserRecord) internalflows.LoginUserRecord {
	return internalflows.LoginUserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Role:              user.Role,
		Status:            uint8(user.Status),
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowLoginUser(user internalflows.LoginUserRecord) UserRecord {
	return UserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Role:              user.Role,
		Status:            AccountStatus(user.Status),
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowLoginResult(result *internalflows.LoginResult) *LoginResult {
	if result == nil {
		return nil
	}
	return &LoginResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		MFARequired:  result.MFARequired,
		MFAType:      result.MFAType,
		MFASession:   result.MFASession,
	}
}

func mapMFALoginStoreError(err error) error {
	switch {
	case errors.Is(err, stores.ErrMFALoginChallengeNotFound):
		return ErrMFALoginInvalid
	case errors.Is(err, stores.ErrMFALoginChallengeExpired):
		return ErrMFALoginExpired
	case errors.Is(err, stores.ErrMFALoginChallengeExceeded):
		return ErrMFALoginAttemptsExceeded
	case errors.Is(err, stores.ErrMFALoginChallengeBackend):
		return ErrMFALoginUnavailable
	default:
		return ErrMFALoginUnavailable
	}
}

// RequestPasswordReset describes the requestpasswordreset operation and its observable behavior.
//
// RequestPasswordReset may return an error when input validation, dependency calls, or security checks fail.
// RequestPasswordReset does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RequestPasswordReset(ctx context.Context, identifier string) (string, error) {
	return internalflows.RunRequestPasswordReset(ctx, identifier, e.passwordResetFlowDeps())
}

// ConfirmPasswordReset describes the confirmpasswordreset operation and its observable behavior.
//
// ConfirmPasswordReset may return an error when input validation, dependency calls, or security checks fail.
// ConfirmPasswordReset does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmPasswordReset(ctx context.Context, challenge, newPassword string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "totp", "")
}

// ConfirmPasswordResetWithTOTP describes the confirmpasswordresetwithtotp operation and its observable behavior.
//
// ConfirmPasswordResetWithTOTP may return an error when input validation, dependency calls, or security checks fail.
// ConfirmPasswordResetWithTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmPasswordResetWithTOTP(ctx context.Context, challenge, newPassword, totpCode string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "totp", totpCode)
}

// ConfirmPasswordResetWithBackupCode describes the confirmpasswordresetwithbackupcode operation and its observable behavior.
//
// ConfirmPasswordResetWithBackupCode may return an error when input validation, dependency calls, or security checks fail.
// ConfirmPasswordResetWithBackupCode does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmPasswordResetWithBackupCode(ctx context.Context, challenge, newPassword, backupCode string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "backup", backupCode)
}

// ConfirmPasswordResetWithMFA describes the confirmpasswordresetwithmfa operation and its observable behavior.
//
// ConfirmPasswordResetWithMFA may return an error when input validation, dependency calls, or security checks fail.
// ConfirmPasswordResetWithMFA does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmPasswordResetWithMFA(ctx context.Context, challenge, newPassword, mfaType, mfaCode string) error {
	return internalflows.RunConfirmPasswordResetWithMFA(ctx, challenge, newPassword, mfaType, mfaCode, e.passwordResetFlowDeps())
}

func (e *Engine) passwordResetFlowDeps() internalflows.PasswordResetDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.PasswordResetDeps{
		Enabled:             cfg.PasswordReset.Enabled,
		Strategy:            int(cfg.PasswordReset.Strategy),
		OTPDigits:           cfg.PasswordReset.OTPDigits,
		ResetTTL:            cfg.PasswordReset.ResetTTL,
		MaxAttempts:         cfg.PasswordReset.MaxAttempts,
		RequireMFA:          cfg.TOTP.Enabled && (cfg.TOTP.RequireTOTPForPasswordReset || cfg.TOTP.RequireForPasswordReset),
		TenantIDFromContext: tenantIDFromContext,
		ClientIPFromContext: clientIPFromContext,
		Now:                 time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MapLimiterError: mapPasswordResetLimiterError,
		MapStoreError:   mapPasswordResetStoreError,
		IsStoreNotFound: func(err error) bool {
			return errors.Is(err, stores.ErrResetNotFound)
		},
		GenerateChallenge: func(strategy int, otpDigits int) (string, string, [32]byte, error) {
			return e.generatePasswordResetChallenge(ResetStrategyType(strategy), otpDigits)
		},
		ParseChallenge: func(strategy int, challenge string, otpDigits int) (string, [32]byte, error) {
			return parsePasswordResetChallenge(ResetStrategyType(strategy), challenge, otpDigits)
		},
		SleepEnumerationDelay: sleepPasswordResetEnumerationDelay,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit:     e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Metrics: internalflows.PasswordResetMetrics{
			PasswordResetRequest:          int(MetricPasswordResetRequest),
			PasswordResetConfirmSuccess:   int(MetricPasswordResetConfirmSuccess),
			PasswordResetConfirmFailure:   int(MetricPasswordResetConfirmFailure),
			PasswordResetAttemptsExceeded: int(MetricPasswordResetAttemptsExceeded),
		},
		Events: internalflows.PasswordResetEvents{
			PasswordResetRequest: auditEventPasswordResetRequest,
			PasswordResetConfirm: auditEventPasswordResetConfirm,
			PasswordResetReplay:  auditEventPasswordResetReplay,
		},
		Errors: internalflows.PasswordResetErrors{
			EngineNotReady:            ErrEngineNotReady,
			PasswordResetDisabled:     ErrPasswordResetDisabled,
			PasswordResetInvalid:      ErrPasswordResetInvalid,
			PasswordResetRateLimited:  ErrPasswordResetRateLimited,
			PasswordResetUnavailable:  ErrPasswordResetUnavailable,
			PasswordResetAttempts:     ErrPasswordResetAttempts,
			PasswordPolicy:            ErrPasswordPolicy,
			UserNotFound:              ErrUserNotFound,
			SessionInvalidationFailed: ErrSessionInvalidationFailed,
			TOTPInvalid:               ErrTOTPInvalid,
		},
	}

	if e != nil && e.resetLimiter != nil {
		deps.CheckRequestLimiter = e.resetLimiter.CheckRequest
		deps.CheckConfirmLimiter = e.resetLimiter.CheckConfirm
	}
	if e != nil && e.userProvider != nil {
		deps.GetUserByIdentifier = func(identifier string) (internalflows.PasswordResetUser, error) {
			user, err := e.userProvider.GetUserByIdentifier(identifier)
			if err != nil {
				return internalflows.PasswordResetUser{}, err
			}
			return internalflows.PasswordResetUser{
				UserID:   user.UserID,
				TenantID: user.TenantID,
				Status:   uint8(user.Status),
			}, nil
		}
		deps.GetUserByID = func(userID string) (internalflows.PasswordResetUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.PasswordResetUser{}, err
			}
			return internalflows.PasswordResetUser{
				UserID:   user.UserID,
				TenantID: user.TenantID,
				Status:   uint8(user.Status),
			}, nil
		}
		deps.UpdatePasswordHash = e.userProvider.UpdatePasswordHash
	}
	if e != nil && e.passwordHash != nil {
		deps.HashPassword = e.passwordHash.Hash
	}
	if e != nil && e.resetStore != nil {
		deps.SaveResetRecord = func(ctx context.Context, tenantID, resetID string, record internalflows.PasswordResetStoreRecord, ttl time.Duration) error {
			return e.resetStore.Save(ctx, tenantID, resetID, &stores.PasswordResetRecord{
				UserID:     record.UserID,
				SecretHash: record.SecretHash,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				Strategy:   record.Strategy,
			}, ttl)
		}
		deps.GetResetRecord = func(ctx context.Context, tenantID, resetID string) (internalflows.PasswordResetStoreRecord, error) {
			record, err := e.resetStore.Get(ctx, tenantID, resetID)
			if err != nil {
				return internalflows.PasswordResetStoreRecord{}, err
			}
			return internalflows.PasswordResetStoreRecord{
				UserID:     record.UserID,
				SecretHash: record.SecretHash,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				Strategy:   record.Strategy,
			}, nil
		}
		deps.ConsumeResetRecord = func(ctx context.Context, tenantID, resetID string, providedHash [32]byte, expectedStrategy int, maxAttempts int) (internalflows.PasswordResetStoreRecord, error) {
			record, err := e.resetStore.Consume(ctx, tenantID, resetID, providedHash, expectedStrategy, maxAttempts)
			if err != nil {
				return internalflows.PasswordResetStoreRecord{}, err
			}
			return internalflows.PasswordResetStoreRecord{
				UserID:     record.UserID,
				SecretHash: record.SecretHash,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				Strategy:   record.Strategy,
			}, nil
		}
	}
	if e != nil {
		deps.LogoutAllInTenant = e.LogoutAllInTenant
		deps.VerifyTOTPForUser = func(ctx context.Context, user internalflows.PasswordResetUser, code string) error {
			return e.verifyTOTPForUser(ctx, UserRecord{
				UserID:   user.UserID,
				TenantID: user.TenantID,
				Status:   AccountStatus(user.Status),
			}, code)
		}
		deps.VerifyBackupCodeInTenant = e.VerifyBackupCodeInTenant
	}

	return deps
}

func (e *Engine) generatePasswordResetChallenge(
	strategy ResetStrategyType,
	otpDigits int,
) (string, string, [32]byte, error) {
	var emptyHash [32]byte

	switch strategy {
	case ResetToken:
		resetID, err := internal.NewSessionID()
		if err != nil {
			return "", "", emptyHash, err
		}

		secret, err := internal.NewResetSecret()
		if err != nil {
			return "", "", emptyHash, err
		}

		challenge, err := internal.EncodeResetToken(resetID.String(), secret)
		if err != nil {
			return "", "", emptyHash, err
		}

		return resetID.String(), challenge, internal.HashResetSecret(secret), nil

	case ResetUUID:
		resetUUID := uuid.New()
		resetID := resetUUID.String()
		return resetID, resetID, internal.HashResetBytes([]byte(resetID)), nil

	case ResetOTP:
		resetID, err := internal.NewSessionID()
		if err != nil {
			return "", "", emptyHash, err
		}

		otp, err := internal.NewOTP(otpDigits)
		if err != nil {
			return "", "", emptyHash, err
		}

		challenge := resetID.String() + "." + otp
		return resetID.String(), challenge, internal.HashResetBytes([]byte(otp)), nil

	default:
		return "", "", emptyHash, fmt.Errorf("unsupported reset strategy")
	}
}

func parsePasswordResetChallenge(
	strategy ResetStrategyType,
	challenge string,
	otpDigits int,
) (string, [32]byte, error) {
	var emptyHash [32]byte

	switch strategy {
	case ResetToken:
		resetID, secret, err := internal.DecodeResetToken(challenge)
		if err != nil {
			return "", emptyHash, err
		}
		return resetID, internal.HashResetSecret(secret), nil

	case ResetUUID:
		parsed, err := uuid.Parse(challenge)
		if err != nil {
			return "", emptyHash, err
		}
		resetID := parsed.String()
		return resetID, internal.HashResetBytes([]byte(resetID)), nil

	case ResetOTP:
		parts := strings.SplitN(challenge, ".", 2)
		if len(parts) != 2 {
			return "", emptyHash, errors.New("invalid otp challenge format")
		}

		resetID := parts[0]
		otp := parts[1]

		if _, err := internal.ParseSessionID(resetID); err != nil {
			return "", emptyHash, err
		}
		if len(otp) != otpDigits {
			return "", emptyHash, errors.New("invalid otp length")
		}
		if !isNumericString(otp) {
			return "", emptyHash, errors.New("invalid otp format")
		}

		return resetID, internal.HashResetBytes([]byte(otp)), nil

	default:
		return "", emptyHash, errors.New("unsupported strategy")
	}
}

func mapPasswordResetLimiterError(err error) error {
	switch {
	case errors.Is(err, limiters.ErrResetRateLimited):
		return ErrPasswordResetRateLimited
	case errors.Is(err, limiters.ErrResetRedisUnavailable):
		return ErrPasswordResetUnavailable
	default:
		return ErrPasswordResetUnavailable
	}
}

func mapPasswordResetStoreError(err error) error {
	switch {
	case errors.Is(err, stores.ErrResetSecretMismatch), errors.Is(err, stores.ErrResetNotFound), errors.Is(err, redis.Nil):
		return ErrPasswordResetInvalid
	case errors.Is(err, stores.ErrResetAttemptsExceeded):
		return ErrPasswordResetAttempts
	case errors.Is(err, stores.ErrResetRedisUnavailable):
		return ErrPasswordResetUnavailable
	default:
		return ErrPasswordResetUnavailable
	}
}

func sleepPasswordResetEnumerationDelay(ctx context.Context) error {
	minMs := int64(20)
	maxMs := int64(40)
	span := maxMs - minMs + 1

	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return err
	}

	delay := time.Duration(minMs+n.Int64()) * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isNumericString(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// GenerateTOTPSetup describes the generatetotpsetup operation and its observable behavior.
//
// GenerateTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// GenerateTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateTOTPSetup(ctx context.Context, userID string) (*TOTPSetup, error) {
	setup, err := internalflows.RunGenerateTOTPSetup(ctx, userID, e.totpFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowTOTPSetup(setup), nil
}

// ProvisionTOTP describes the provisiontotp operation and its observable behavior.
//
// ProvisionTOTP may return an error when input validation, dependency calls, or security checks fail.
// ProvisionTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ProvisionTOTP(ctx context.Context, userID string) (*TOTPProvision, error) {
	provision, err := internalflows.RunProvisionTOTP(ctx, userID, e.totpFlowDeps())
	if err != nil {
		return nil, err
	}
	return fromFlowTOTPProvision(provision), nil
}

// ConfirmTOTPSetup describes the confirmtotpsetup operation and its observable behavior.
//
// ConfirmTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// ConfirmTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmTOTPSetup(ctx context.Context, userID, code string) error {
	return internalflows.RunConfirmTOTPSetup(ctx, userID, code, e.totpFlowDeps())
}

// VerifyTOTP describes the verifytotp operation and its observable behavior.
//
// VerifyTOTP may return an error when input validation, dependency calls, or security checks fail.
// VerifyTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyTOTP(ctx context.Context, userID, code string) error {
	return internalflows.RunVerifyTOTP(ctx, userID, code, e.totpFlowDeps())
}

// DisableTOTP describes the disabletotp operation and its observable behavior.
//
// DisableTOTP may return an error when input validation, dependency calls, or security checks fail.
// DisableTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DisableTOTP(ctx context.Context, userID string) error {
	return internalflows.RunDisableTOTP(ctx, userID, e.totpFlowDeps())
}

func (e *Engine) verifyTOTPForUser(ctx context.Context, user UserRecord, code string) error {
	return internalflows.RunVerifyTOTPForUser(ctx, toFlowTOTPUser(user), code, e.totpFlowDeps())
}

func (e *Engine) totpFlowDeps() internalflows.TOTPDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.TOTPDeps{
		Enabled:                 cfg.TOTP.Enabled,
		EnforceReplayProtection: cfg.TOTP.EnforceReplayProtection,
		Now:                     time.Now,
		TenantIDFromContext:     tenantIDFromContext,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		IsTOTPRateLimited: func(err error) bool {
			return errors.Is(err, limiters.ErrTOTPRateLimited)
		},
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit: e.emitAudit,
		Metrics: internalflows.TOTPMetrics{
			TOTPRequired: int(MetricTOTPRequired),
			TOTPFailure:  int(MetricTOTPFailure),
			TOTPSuccess:  int(MetricTOTPSuccess),
		},
		Events: internalflows.TOTPEvents{
			TOTPSetupRequested: auditEventTOTPSetupRequested,
			TOTPEnabled:        auditEventTOTPEnabled,
			TOTPDisabled:       auditEventTOTPDisabled,
			TOTPFailure:        auditEventTOTPFailure,
			TOTPSuccess:        auditEventTOTPSuccess,
		},
		Errors: internalflows.TOTPErrors{
			TOTPFeatureDisabled:       ErrTOTPFeatureDisabled,
			EngineNotReady:            ErrEngineNotReady,
			UserNotFound:              ErrUserNotFound,
			TOTPUnavailable:           ErrTOTPUnavailable,
			TOTPNotConfigured:         ErrTOTPNotConfigured,
			TOTPRequired:              ErrTOTPRequired,
			TOTPInvalid:               ErrTOTPInvalid,
			TOTPRateLimited:           ErrTOTPRateLimited,
			AccountVersionNotAdvanced: ErrAccountVersionNotAdvanced,
			SessionInvalidationFailed: ErrSessionInvalidationFailed,
		},
	}

	if e != nil && e.userProvider != nil {
		deps.GetUserByID = func(userID string) (internalflows.TOTPUser, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.TOTPUser{}, err
			}
			return toFlowTOTPUser(user), nil
		}
		deps.GetTOTPSecret = func(ctx context.Context, userID string) (*internalflows.TOTPRecord, error) {
			record, err := e.userProvider.GetTOTPSecret(ctx, userID)
			if err != nil {
				return nil, err
			}
			if record == nil {
				return nil, nil
			}
			return &internalflows.TOTPRecord{
				Secret:          record.Secret,
				Enabled:         record.Enabled,
				LastUsedCounter: record.LastUsedCounter,
			}, nil
		}
		deps.EnableTOTP = e.userProvider.EnableTOTP
		deps.DisableTOTP = e.userProvider.DisableTOTP
		deps.MarkTOTPVerified = e.userProvider.MarkTOTPVerified
		deps.UpdateTOTPLastUsedCounter = e.userProvider.UpdateTOTPLastUsedCounter
	}
	if e != nil {
		deps.LogoutAllInTenant = e.LogoutAllInTenant
	}
	if e != nil && e.totp != nil {
		deps.GenerateSecret = e.totp.GenerateSecret
		deps.ProvisionURI = e.totp.ProvisionURI
		deps.VerifyCode = e.totp.VerifyCode
	}
	if e != nil && e.totpLimiter != nil {
		deps.CheckTOTPLimiter = e.totpLimiter.Check
		deps.RecordTOTPLimiterFailure = e.totpLimiter.RecordFailure
		deps.ResetTOTPLimiter = e.totpLimiter.Reset
	}

	return deps
}

func toFlowTOTPUser(user UserRecord) internalflows.TOTPUser {
	return internalflows.TOTPUser{
		UserID:         user.UserID,
		Identifier:     user.Identifier,
		TenantID:       user.TenantID,
		Status:         uint8(user.Status),
		AccountVersion: user.AccountVersion,
	}
}

func fromFlowTOTPSetup(setup *internalflows.TOTPSetup) *TOTPSetup {
	if setup == nil {
		return nil
	}
	return &TOTPSetup{
		SecretBase32: setup.SecretBase32,
		QRCodeURL:    setup.QRCodeURL,
	}
}

func fromFlowTOTPProvision(provision *internalflows.TOTPProvision) *TOTPProvision {
	if provision == nil {
		return nil
	}
	return &TOTPProvision{
		Secret: provision.Secret,
		URI:    provision.URI,
	}
}
