package goAuth

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/internal/rate"
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
	resetStore          *passwordResetStore
	resetLimiter        *passwordResetLimiter
	verificationStore   *emailVerificationStore
	verificationLimiter *emailVerificationLimiter
	accountLimiter      *accountCreationLimiter
	totpLimiter         *totpLimiter
	backupLimiter       *backupCodeLimiter
	mfaLoginStore       *mfaLoginChallengeStore
	audit               *auditDispatcher
	metrics             *Metrics
	passwordHash        *password.Argon2
	totp                *totpManager
	jwtManager          *jwt.Manager
	userProvider        UserProvider
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

func (e *Engine) metricInc(id MetricID) {
	if e == nil || e.metrics == nil {
		return
	}
	e.metrics.Inc(id)
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
					log.Print("goAuth: password hash upgrade update failed")
				}
			} else {
				log.Print("goAuth: password hash upgrade generation failed")
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
	tenantID := tenantIDFromContext(ctx)
	sessionID, providedSecret, err := internal.DecodeRefreshToken(refreshToken)
	if err != nil {
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", tenantID, "", ErrRefreshInvalid, func() map[string]string {
			return map[string]string{
				"reason": "decode_failed",
			}
		})
		return "", "", ErrRefreshInvalid
	}

	if e.rateLimiter != nil {
		if err := e.rateLimiter.CheckRefresh(ctx, sessionID); err != nil {
			e.metricInc(MetricRefreshRateLimited)
			e.emitAudit(ctx, auditEventRefreshRateLimited, false, "", tenantID, sessionID, ErrRefreshRateLimited, nil)
			e.emitRateLimit(ctx, "refresh", tenantID, func() map[string]string {
				return map[string]string{
					"session_id": sessionID,
				}
			})
			return "", "", ErrRefreshRateLimited
		}
	}

	nextSecret, err := internal.NewRefreshSecret()
	if err != nil {
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, "", tenantID, sessionID, err, func() map[string]string {
			return map[string]string{
				"reason": "next_secret_generation",
			}
		})
		return "", "", err
	}

	sess, err := e.sessionStore.RotateRefreshHash(
		ctx,
		tenantID,
		sessionID,
		internal.HashRefreshSecret(providedSecret),
		internal.HashRefreshSecret(nextSecret),
	)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrRefreshHashMismatch):
			e.metricInc(MetricRefreshReuseDetected)
			e.metricInc(MetricReplayDetected)
			e.metricInc(MetricSessionInvalidated)
			if e.config.SessionHardening.EnableReplayTracking {
				if trackErr := e.sessionStore.TrackReplayAnomaly(ctx, sessionID, e.sessionLifetime()); trackErr != nil {
					log.Print("goAuth: replay anomaly tracking failed")
				}
			}
			e.emitAudit(ctx, auditEventRefreshReuseDetected, false, "", tenantID, sessionID, ErrRefreshReuse, nil)
			return "", "", ErrRefreshReuse
		case errors.Is(err, redis.Nil):
			e.metricInc(MetricRefreshFailure)
			e.emitAudit(ctx, auditEventRefreshInvalid, false, "", tenantID, sessionID, ErrSessionNotFound, func() map[string]string {
				return map[string]string{
					"reason": "session_not_found",
				}
			})
			return "", "", ErrSessionNotFound
		default:
			e.metricInc(MetricRefreshFailure)
			e.emitAudit(ctx, auditEventRefreshInvalid, false, "", tenantID, sessionID, err, func() map[string]string {
				return map[string]string{
					"reason": "rotate_failed",
				}
			})
			return "", "", err
		}
	}
	if statusErr := accountStatusToError(AccountStatus(sess.Status)); statusErr != nil {
		_ = e.sessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		e.metricInc(MetricSessionInvalidated)
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, sess.UserID, sess.TenantID, sess.SessionID, statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return "", "", statusErr
	}
	if e.shouldRequireVerified() && AccountStatus(sess.Status) == AccountPendingVerification {
		_ = e.sessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		e.metricInc(MetricSessionInvalidated)
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, sess.UserID, sess.TenantID, sess.SessionID, ErrAccountUnverified, func() map[string]string {
			return map[string]string{
				"reason": "pending_verification",
			}
		})
		return "", "", ErrAccountUnverified
	}

	access, err := e.issueAccessToken(sess)
	if err != nil {
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, sess.UserID, sess.TenantID, sess.SessionID, err, func() map[string]string {
			return map[string]string{
				"reason": "issue_access_failed",
			}
		})
		return "", "", err
	}

	refresh, err := internal.EncodeRefreshToken(sess.SessionID, nextSecret)
	if err != nil {
		e.metricInc(MetricRefreshFailure)
		e.emitAudit(ctx, auditEventRefreshInvalid, false, sess.UserID, sess.TenantID, sess.SessionID, err, func() map[string]string {
			return map[string]string{
				"reason": "encode_refresh_failed",
			}
		})
		return "", "", err
	}

	e.metricInc(MetricRefreshSuccess)
	e.emitAudit(ctx, auditEventRefreshSuccess, true, sess.UserID, sess.TenantID, sess.SessionID, nil, nil)

	return access, refresh, nil
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
	if e.metrics != nil && e.metrics.LatencyEnabled() {
		start := time.Now()
		defer e.metrics.Observe(MetricValidateLatency, time.Since(start))
	}

	claims, err := e.jwtManager.ParseAccess(tokenStr)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if e.config.SessionHardening.MaxClockSkew >= 0 && claims.IssuedAt != nil {
		if claims.IssuedAt.Time.After(time.Now().Add(e.config.SessionHardening.MaxClockSkew)) {
			return nil, ErrTokenClockSkew
		}
	}

	effectiveMode, err := e.resolveRouteMode(routeMode)
	if err != nil {
		return nil, err
	}

	// JWT-only and hybrid-default validation paths: no Redis.
	if effectiveMode == ModeJWTOnly || effectiveMode == ModeHybrid {
		return e.buildResultFromClaims(claims), nil
	}

	// Strict validation path: Redis is mandatory and fail-closed.
	sess, err := e.sessionStore.Get(ctx, tenantIDFromToken(claims.TID), claims.SID, e.sessionLifetime())
	if err != nil {
		if errors.Is(err, session.ErrRedisUnavailable) {
			return nil, ErrUnauthorized
		}
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, ErrSessionNotFound
	}

	if e.config.Security.EnablePermissionVersionCheck {
		if claims.PermVersion != sess.PermissionVersion {
			return nil, ErrSessionNotFound
		}
	}
	if e.config.Security.EnableRoleVersionCheck {
		if claims.RoleVersion != sess.RoleVersion {
			_ = e.sessionStore.Delete(ctx, tenantIDFromToken(claims.TID), claims.SID)
			return nil, ErrSessionNotFound
		}
	}
	if e.config.Security.EnableAccountVersionCheck {
		if claims.AccountVersion != 0 && sess.AccountVersion != 0 && claims.AccountVersion != sess.AccountVersion {
			_ = e.sessionStore.Delete(ctx, tenantIDFromToken(claims.TID), claims.SID)
			return nil, ErrSessionNotFound
		}
	}
	if statusErr := accountStatusToError(AccountStatus(sess.Status)); statusErr != nil {
		_ = e.sessionStore.Delete(ctx, tenantIDFromToken(claims.TID), claims.SID)
		return nil, statusErr
	}
	if e.shouldRequireVerified() && AccountStatus(sess.Status) == AccountPendingVerification {
		_ = e.sessionStore.Delete(ctx, tenantIDFromToken(claims.TID), claims.SID)
		return nil, ErrAccountUnverified
	}
	if err := e.validateDeviceBinding(ctx, sess); err != nil {
		return nil, err
	}

	return e.buildResult(sess), nil
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
	return e.LogoutInTenant(ctx, tenantIDFromContext(ctx), sessionID)
}

// LogoutInTenant describes the logoutintenant operation and its observable behavior.
//
// LogoutInTenant may return an error when input validation, dependency calls, or security checks fail.
// LogoutInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutInTenant(ctx context.Context, tenantID, sessionID string) error {
	err := e.sessionStore.Delete(ctx, tenantID, sessionID)
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
	claims, err := e.jwtManager.ParseAccess(tokenStr)
	if err != nil {
		e.emitAudit(ctx, auditEventLogoutSession, false, "", tenantIDFromContext(ctx), "", ErrTokenInvalid, func() map[string]string {
			return map[string]string{
				"reason": "invalid_access_token",
			}
		})
		return ErrTokenInvalid
	}

	return e.LogoutInTenant(ctx, tenantIDFromToken(claims.TID), claims.SID)
}

// LogoutAll describes the logoutall operation and its observable behavior.
//
// LogoutAll may return an error when input validation, dependency calls, or security checks fail.
// LogoutAll does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutAll(ctx context.Context, userID string) error {
	return e.LogoutAllInTenant(ctx, tenantIDFromContext(ctx), userID)
}

// LogoutAllInTenant describes the logoutallintenant operation and its observable behavior.
//
// LogoutAllInTenant may return an error when input validation, dependency calls, or security checks fail.
// LogoutAllInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LogoutAllInTenant(ctx context.Context, tenantID, userID string) error {
	err := e.sessionStore.DeleteAllForUser(ctx, tenantID, userID)
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
		log.Print("goAuth: session invalidation failed after password change")
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
			log.Print("goAuth: login limiter reset failed after password change")
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

func (e *Engine) resolveRouteMode(routeMode RouteMode) (ValidationMode, error) {
	switch routeMode {
	case ModeInherit:
		switch e.config.ValidationMode {
		case ModeJWTOnly:
			return ModeJWTOnly, nil
		case ModeHybrid:
			return ModeHybrid, nil
		case ModeStrict:
			return ModeStrict, nil
		default:
			return 0, ErrInvalidRouteMode
		}
	case ModeJWTOnly:
		return ModeJWTOnly, nil
	case ModeStrict:
		return ModeStrict, nil
	default:
		return 0, ErrInvalidRouteMode
	}
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
					log.Print("goAuth: tenant session counter reconciliation failed")
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
		if errors.Is(err, errTOTPRateLimited) {
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
			if errors.Is(recErr, errTOTPRateLimited) {
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
