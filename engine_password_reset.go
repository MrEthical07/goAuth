package goAuth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func (e *Engine) RequestPasswordReset(ctx context.Context, identifier string) (string, error) {
	if !e.config.PasswordReset.Enabled {
		e.emitAudit(ctx, auditEventPasswordResetRequest, false, "", tenantIDFromContext(ctx), "", ErrPasswordResetDisabled, nil)
		return "", ErrPasswordResetDisabled
	}
	if e.passwordHash == nil || e.resetStore == nil || e.resetLimiter == nil {
		return "", ErrEngineNotReady
	}
	if identifier == "" {
		e.emitAudit(ctx, auditEventPasswordResetRequest, false, "", tenantIDFromContext(ctx), "", ErrPasswordResetInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return "", ErrPasswordResetInvalid
	}

	tenantID := tenantIDFromContext(ctx)
	ip := clientIPFromContext(ctx)
	if err := e.resetLimiter.CheckRequest(ctx, tenantID, identifier, ip); err != nil {
		mapped := mapPasswordResetLimiterError(err)
		if errors.Is(mapped, ErrPasswordResetRateLimited) {
			e.emitAudit(ctx, auditEventPasswordResetRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
			e.emitRateLimit(ctx, "password_reset_request", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		} else {
			e.emitAudit(ctx, auditEventPasswordResetRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		}
		return "", mapped
	}

	user, err := e.userProvider.GetUserByIdentifier(identifier)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		if sleepErr := sleepPasswordResetEnumerationDelay(ctx); sleepErr != nil {
			return "", sleepErr
		}
		_, challenge, _, genErr := e.generatePasswordResetChallenge(e.config.PasswordReset.Strategy, e.config.PasswordReset.OTPDigits)
		if genErr != nil {
			e.emitAudit(ctx, auditEventPasswordResetRequest, false, "", tenantID, "", ErrPasswordResetUnavailable, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "fake_generation_failed",
				}
			})
			return "", ErrPasswordResetUnavailable
		}
		e.emitAudit(ctx, auditEventPasswordResetRequest, true, "", tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier":       identifier,
				"enumeration_safe": "true",
			}
		})
		e.metricInc(MetricPasswordResetRequest)
		return challenge, nil
	}

	effectiveTenant := tenantID
	if user.TenantID != "" {
		effectiveTenant = user.TenantID
	}

	resetID, challenge, secretHash, err := e.generatePasswordResetChallenge(
		e.config.PasswordReset.Strategy,
		e.config.PasswordReset.OTPDigits,
	)
	if err != nil {
		return "", ErrPasswordResetUnavailable
	}

	expiresAt := time.Now().Add(e.config.PasswordReset.ResetTTL).Unix()
	record := &passwordResetRecord{
		UserID:     user.UserID,
		SecretHash: secretHash,
		ExpiresAt:  expiresAt,
		Attempts:   0,
		Strategy:   e.config.PasswordReset.Strategy,
	}

	if err := e.resetStore.Save(ctx, effectiveTenant, resetID, record, e.config.PasswordReset.ResetTTL); err != nil {
		mapped := mapPasswordResetStoreError(err)
		e.emitAudit(ctx, auditEventPasswordResetRequest, false, user.UserID, effectiveTenant, "", mapped, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
			}
		})
		return "", mapped
	}

	e.emitAudit(ctx, auditEventPasswordResetRequest, true, user.UserID, effectiveTenant, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": identifier,
		}
	})
	e.metricInc(MetricPasswordResetRequest)
	return challenge, nil
}

func (e *Engine) ConfirmPasswordReset(ctx context.Context, challenge, newPassword string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "totp", "")
}

func (e *Engine) ConfirmPasswordResetWithTOTP(ctx context.Context, challenge, newPassword, totpCode string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "totp", totpCode)
}

func (e *Engine) ConfirmPasswordResetWithBackupCode(ctx context.Context, challenge, newPassword, backupCode string) error {
	return e.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, "backup", backupCode)
}

func (e *Engine) ConfirmPasswordResetWithMFA(ctx context.Context, challenge, newPassword, mfaType, mfaCode string) error {
	if !e.config.PasswordReset.Enabled {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantIDFromContext(ctx), "", ErrPasswordResetDisabled, nil)
		return ErrPasswordResetDisabled
	}
	if e.passwordHash == nil || e.resetStore == nil || e.resetLimiter == nil {
		return ErrEngineNotReady
	}
	if challenge == "" || newPassword == "" {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantIDFromContext(ctx), "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "invalid_input",
			}
		})
		return ErrPasswordPolicy
	}

	resetID, providedHash, err := parsePasswordResetChallenge(
		e.config.PasswordReset.Strategy,
		challenge,
		e.config.PasswordReset.OTPDigits,
	)
	if err != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantIDFromContext(ctx), "", ErrPasswordResetInvalid, func() map[string]string {
			return map[string]string{
				"reason": "parse_failed",
			}
		})
		return ErrPasswordResetInvalid
	}

	tenantID := tenantIDFromContext(ctx)
	if err := e.resetLimiter.CheckConfirm(ctx, tenantID, resetID, clientIPFromContext(ctx)); err != nil {
		mapped := mapPasswordResetLimiterError(err)
		e.metricInc(MetricPasswordResetConfirmFailure)
		if errors.Is(mapped, ErrPasswordResetRateLimited) {
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
			e.emitRateLimit(ctx, "password_reset_confirm", tenantID, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		} else {
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		}
		return mapped
	}

	if e.config.TOTP.Enabled && (e.config.TOTP.RequireTOTPForPasswordReset || e.config.TOTP.RequireForPasswordReset) {
		peek, err := e.resetStore.Get(ctx, tenantID, resetID)
		if err != nil {
			mapped := mapPasswordResetStoreError(err)
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
			return mapped
		}
		user, err := e.userProvider.GetUserByID(peek.UserID)
		if err != nil {
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, peek.UserID, tenantID, "", ErrUserNotFound, nil)
			return ErrUserNotFound
		}
		var mfaErr error
		switch strings.ToLower(strings.TrimSpace(mfaType)) {
		case "", "totp":
			mfaErr = e.verifyTOTPForUser(ctx, user, mfaCode)
		case "backup":
			mfaErr = e.VerifyBackupCodeInTenant(ctx, user.TenantID, user.UserID, mfaCode)
		default:
			mfaErr = ErrTOTPInvalid
		}
		if mfaErr != nil {
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, peek.UserID, user.TenantID, "", mfaErr, func() map[string]string {
				return map[string]string{
					"reason": "totp_required_for_reset",
				}
			})
			return mfaErr
		}
	}

	record, err := e.resetStore.Consume(
		ctx,
		tenantID,
		resetID,
		providedHash,
		e.config.PasswordReset.Strategy,
		e.config.PasswordReset.MaxAttempts,
	)
	if err != nil {
		mapped := mapPasswordResetStoreError(err)
		if errors.Is(err, errResetNotFound) {
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetReplay, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		} else if errors.Is(mapped, ErrPasswordResetAttempts) {
			e.metricInc(MetricPasswordResetAttemptsExceeded)
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
					"reason":   "attempts_exceeded",
				}
			})
		} else {
			e.metricInc(MetricPasswordResetConfirmFailure)
			e.emitAudit(ctx, auditEventPasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		}
		return mapped
	}
	user, err := e.userProvider.GetUserByID(record.UserID)
	if err != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, record.UserID, tenantID, "", ErrUserNotFound, nil)
		return ErrUserNotFound
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, record.UserID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	newHash, err := e.passwordHash.Hash(newPassword)
	if err != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, record.UserID, user.TenantID, "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "hash_policy",
			}
		})
		return ErrPasswordPolicy
	}

	if err := e.userProvider.UpdatePasswordHash(record.UserID, newHash); err != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, record.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "update_hash_failed",
			}
		})
		return err
	}

	invalidateTenant := tenantID
	if user.TenantID != "" {
		invalidateTenant = user.TenantID
	}
	if err := e.LogoutAllInTenant(ctx, invalidateTenant, record.UserID); err != nil {
		e.metricInc(MetricPasswordResetConfirmFailure)
		e.emitAudit(ctx, auditEventPasswordResetConfirm, false, record.UserID, invalidateTenant, "", ErrSessionInvalidationFailed, func() map[string]string {
			return map[string]string{
				"reason": "session_invalidation_failed",
			}
		})
		return errors.Join(ErrSessionInvalidationFailed, err)
	}

	e.metricInc(MetricPasswordResetConfirmSuccess)
	e.emitAudit(ctx, auditEventPasswordResetConfirm, true, record.UserID, invalidateTenant, "", nil, nil)
	return nil
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
	case errors.Is(err, errResetRateLimited):
		return ErrPasswordResetRateLimited
	case errors.Is(err, errResetRedisUnavailable):
		return ErrPasswordResetUnavailable
	default:
		return ErrPasswordResetUnavailable
	}
}

func mapPasswordResetStoreError(err error) error {
	switch {
	case errors.Is(err, errResetSecretMismatch), errors.Is(err, errResetNotFound), errors.Is(err, redis.Nil):
		return ErrPasswordResetInvalid
	case errors.Is(err, errResetAttemptsExceeded):
		return ErrPasswordResetAttempts
	case errors.Is(err, errResetRedisUnavailable):
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
