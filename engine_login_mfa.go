package goAuth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/session"
)

// LoginWithResult describes the loginwithresult operation and its observable behavior.
//
// LoginWithResult may return an error when input validation, dependency calls, or security checks fail.
// LoginWithResult does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) LoginWithResult(ctx context.Context, username, password string) (*LoginResult, error) {
	return e.loginWithResultInternal(ctx, username, password)
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
	if !e.config.TOTP.Enabled || !e.config.TOTP.RequireForLogin {
		return nil, ErrTOTPFeatureDisabled
	}
	if e.mfaLoginStore == nil || e.userProvider == nil || e.totp == nil {
		return nil, ErrEngineNotReady
	}
	if challengeID == "" {
		return nil, ErrMFALoginInvalid
	}

	record, err := e.mfaLoginStore.Get(ctx, challengeID)
	if err != nil {
		mapped := mapMFALoginStoreError(err)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, "", tenantIDFromContext(ctx), "", mapped, func() map[string]string {
			return map[string]string{
				"reason": "challenge_load_failed",
			}
		})
		return nil, mapped
	}

	if tenant := tenantIDFromContext(ctx); tenant != "" && record.TenantID != "" && tenant != record.TenantID {
		_, _ = e.mfaLoginStore.Delete(ctx, challengeID)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, "", tenant, "", ErrMFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "tenant_mismatch",
			}
		})
		return nil, ErrMFALoginInvalid
	}

	user, err := e.userProvider.GetUserByID(record.UserID)
	if err != nil {
		_, _ = e.mfaLoginStore.Delete(ctx, challengeID)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, record.UserID, record.TenantID, "", ErrUserNotFound, nil)
		return nil, ErrUserNotFound
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		_, _ = e.mfaLoginStore.Delete(ctx, challengeID)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return nil, statusErr
	}
	if e.shouldRequireVerified() && user.Status == AccountPendingVerification {
		_, _ = e.mfaLoginStore.Delete(ctx, challengeID)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrAccountUnverified, nil)
		return nil, ErrAccountUnverified
	}

	totpRecord, err := e.userProvider.GetTOTPSecret(ctx, user.UserID)
	if err != nil {
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginUnavailable, nil)
		return nil, ErrMFALoginUnavailable
	}
	if totpRecord == nil || !totpRecord.Enabled || len(totpRecord.Secret) == 0 {
		_, _ = e.mfaLoginStore.Delete(ctx, challengeID)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginInvalid, func() map[string]string {
			return map[string]string{
				"reason": "totp_disabled_or_missing",
			}
		})
		return nil, ErrMFALoginInvalid
	}
	if code == "" {
		return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginInvalid)
	}

	switch strings.ToLower(strings.TrimSpace(mfaType)) {
	case "", "totp":
		ok, counter, verr := e.totp.VerifyCode(totpRecord.Secret, code, time.Now())
		if verr != nil || !ok {
			return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginInvalid)
		}

		if e.config.TOTP.EnforceReplayProtection {
			if counter <= totpRecord.LastUsedCounter {
				e.metricInc(MetricMFAReplayAttempt)
				e.metricInc(MetricMFALoginFailure)
				e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginReplay, nil)
				return nil, ErrMFALoginReplay
			}
			if err := e.userProvider.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
				e.metricInc(MetricMFALoginFailure)
				e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginUnavailable, nil)
				return nil, ErrMFALoginUnavailable
			}
		}
	case "backup":
		if berr := e.VerifyBackupCodeInTenant(ctx, record.TenantID, user.UserID, code); berr != nil {
			switch {
			case errors.Is(berr, ErrBackupCodeRateLimited):
				return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginAttemptsExceeded)
			case errors.Is(berr, ErrBackupCodeInvalid), errors.Is(berr, ErrBackupCodesNotConfigured):
				return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginInvalid)
			default:
				return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginUnavailable)
			}
		}
	default:
		return e.failLoginMFAAttempt(ctx, challengeID, user.UserID, record.TenantID, ErrMFALoginInvalid)
	}

	deleted, err := e.mfaLoginStore.Delete(ctx, challengeID)
	if err != nil {
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginUnavailable, nil)
		return nil, ErrMFALoginUnavailable
	}
	if !deleted {
		e.metricInc(MetricMFAReplayAttempt)
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", ErrMFALoginReplay, nil)
		return nil, ErrMFALoginReplay
	}

	identifier := user.Identifier
	if identifier == "" {
		identifier = user.UserID
	}
	access, refresh, err := e.issueLoginSessionTokensForResult(ctx, identifier, user, record.TenantID)
	if err != nil {
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, record.TenantID, "", err, nil)
		return nil, err
	}

	e.metricInc(MetricMFALoginSuccess)
	e.emitAudit(ctx, auditEventMFASuccess, true, user.UserID, record.TenantID, "", nil, nil)
	return &LoginResult{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (e *Engine) failLoginMFAAttempt(
	ctx context.Context,
	challengeID string,
	userID string,
	tenantID string,
	cause error,
) (*LoginResult, error) {
	exceeded, recErr := e.mfaLoginStore.RecordFailure(ctx, challengeID, e.config.TOTP.MFALoginMaxAttempts)
	if recErr != nil {
		e.metricInc(MetricMFALoginFailure)
		mapped := mapMFALoginStoreError(recErr)
		e.emitAudit(ctx, auditEventMFAFailure, false, userID, tenantID, "", mapped, nil)
		return nil, mapped
	}
	if exceeded {
		e.metricInc(MetricMFALoginFailure)
		e.emitAudit(ctx, auditEventMFAAttemptsExceeded, false, userID, tenantID, "", ErrMFALoginAttemptsExceeded, nil)
		return nil, ErrMFALoginAttemptsExceeded
	}
	e.metricInc(MetricMFALoginFailure)
	if cause == nil {
		cause = ErrMFALoginInvalid
	}
	e.emitAudit(ctx, auditEventMFAFailure, false, userID, tenantID, "", cause, nil)
	return nil, cause
}

func (e *Engine) loginWithResultInternal(ctx context.Context, username, password string) (*LoginResult, error) {
	ip := clientIPFromContext(ctx)
	tenantID := tenantIDFromContext(ctx)
	if e.passwordHash == nil {
		return nil, ErrEngineNotReady
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
			return nil, ErrLoginRateLimited
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
				return nil, ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, "", tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "empty_password",
			}
		})
		return nil, ErrInvalidCredentials
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
				return nil, ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, "", tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "user_not_found",
			}
		})
		return nil, ErrInvalidCredentials
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
				return nil, ErrLoginRateLimited
			}
		}
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrInvalidCredentials, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "password_mismatch",
			}
		})
		return nil, ErrInvalidCredentials
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "account_status",
			}
		})
		return nil, statusErr
	}
	if e.shouldRequireVerified() && user.Status == AccountPendingVerification {
		e.metricInc(MetricLoginFailure)
		e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrAccountUnverified, func() map[string]string {
			return map[string]string{
				"identifier": username,
				"reason":     "pending_verification",
			}
		})
		return nil, ErrAccountUnverified
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

	if e.config.DeviceBinding.Enabled {
		if e.config.DeviceBinding.EnforceIPBinding && clientIPFromContext(ctx) == "" {
			e.metricInc(MetricLoginFailure)
			e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrDeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_ip_context",
				}
			})
			return nil, ErrDeviceBindingRejected
		}
		if e.config.DeviceBinding.EnforceUserAgentBinding && userAgentFromContext(ctx) == "" {
			e.metricInc(MetricLoginFailure)
			e.emitAudit(ctx, auditEventLoginFailure, false, user.UserID, tenantID, "", ErrDeviceBindingRejected, func() map[string]string {
				return map[string]string{
					"identifier": username,
					"reason":     "missing_user_agent_context",
				}
			})
			return nil, ErrDeviceBindingRejected
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
		return nil, err
	}

	if e.config.TOTP.Enabled && e.config.TOTP.RequireForLogin {
		record, err := e.userProvider.GetTOTPSecret(ctx, user.UserID)
		if err != nil {
			e.metricInc(MetricMFALoginFailure)
			e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, tenantID, "", ErrMFALoginUnavailable, nil)
			return nil, ErrMFALoginUnavailable
		}
		if record != nil && record.Enabled && len(record.Secret) > 0 {
			challengeID, err := e.createMFALoginChallenge(ctx, user.UserID, tenantID)
			if err != nil {
				e.metricInc(MetricMFALoginFailure)
				e.emitAudit(ctx, auditEventMFAFailure, false, user.UserID, tenantID, "", err, nil)
				return nil, err
			}
			e.metricInc(MetricMFALoginRequired)
			e.emitAudit(ctx, auditEventMFARequired, true, user.UserID, tenantID, "", nil, func() map[string]string {
				return map[string]string{
					"identifier": username,
				}
			})
			return &LoginResult{
				MFARequired: true,
				MFAType:     "totp",
				MFASession:  challengeID,
			}, nil
		}
	}

	access, refresh, err := e.issueLoginSessionTokensForResult(ctx, username, user, tenantID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (e *Engine) createMFALoginChallenge(ctx context.Context, userID, tenantID string) (string, error) {
	if e.mfaLoginStore == nil {
		return "", ErrEngineNotReady
	}
	id, err := internal.NewSessionID()
	if err != nil {
		return "", ErrMFALoginUnavailable
	}
	challengeID := id.String()

	ttl := e.config.TOTP.MFALoginChallengeTTL
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	record := &stores.MFALoginChallenge{
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Attempts:  0,
	}

	if err := e.mfaLoginStore.Save(ctx, challengeID, record, ttl); err != nil {
		return "", mapMFALoginStoreError(err)
	}
	return challengeID, nil
}

func (e *Engine) issueLoginSessionTokensForResult(
	ctx context.Context,
	username string,
	user UserRecord,
	tenantID string,
) (string, string, error) {
	ip := clientIPFromContext(ctx)
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
