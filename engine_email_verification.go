package goAuth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RequestEmailVerification describes the requestemailverification operation and its observable behavior.
//
// RequestEmailVerification may return an error when input validation, dependency calls, or security checks fail.
// RequestEmailVerification does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RequestEmailVerification(ctx context.Context, identifier string) (string, error) {
	if !e.config.EmailVerification.Enabled {
		e.emitAudit(ctx, auditEventEmailVerificationRequest, false, "", tenantIDFromContext(ctx), "", ErrEmailVerificationDisabled, nil)
		return "", ErrEmailVerificationDisabled
	}
	if e.verificationStore == nil || e.verificationLimiter == nil || e.userProvider == nil {
		return "", ErrEngineNotReady
	}
	if identifier == "" {
		e.emitAudit(ctx, auditEventEmailVerificationRequest, false, "", tenantIDFromContext(ctx), "", ErrEmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return "", ErrEmailVerificationInvalid
	}

	tenantID := tenantIDFromContext(ctx)
	if err := e.verificationLimiter.CheckRequest(ctx, tenantID, identifier, clientIPFromContext(ctx)); err != nil {
		mapped := mapEmailVerificationLimiterError(err)
		e.metricInc(MetricEmailVerificationFailure)
		if errors.Is(mapped, ErrEmailVerificationRateLimited) {
			e.emitAudit(ctx, auditEventEmailVerificationRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
			e.emitRateLimit(ctx, "email_verification_request", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		} else {
			e.emitAudit(ctx, auditEventEmailVerificationRequest, false, "", tenantID, "", mapped, func() map[string]string {
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
		if err := sleepPasswordResetEnumerationDelay(ctx); err != nil {
			return "", err
		}
		_, fakeChallenge, _, genErr := generateEmailVerificationChallenge(
			e.config.EmailVerification.Strategy,
			e.config.EmailVerification.OTPDigits,
		)
		if genErr != nil {
			e.emitAudit(ctx, auditEventEmailVerificationRequest, false, "", tenantID, "", ErrEmailVerificationUnavailable, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "fake_generation_failed",
				}
			})
			return "", ErrEmailVerificationUnavailable
		}
		e.emitAudit(ctx, auditEventEmailVerificationRequest, true, "", tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier":       identifier,
				"enumeration_safe": "true",
			}
		})
		e.metricInc(MetricEmailVerificationRequest)
		return fakeChallenge, nil
	}

	if user.Status == AccountActive {
		e.emitAudit(ctx, auditEventEmailVerificationRequest, true, user.UserID, tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
				"noop":       "already_active",
			}
		})
		e.metricInc(MetricEmailVerificationRequest)
		return "", nil
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		// Keep request enumeration-safe for non-active terminal statuses.
		e.emitAudit(ctx, auditEventEmailVerificationRequest, true, user.UserID, tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
				"noop":       "non_verifiable_status",
			}
		})
		e.metricInc(MetricEmailVerificationRequest)
		return "", nil
	}

	effectiveTenant := tenantID
	if user.TenantID != "" {
		effectiveTenant = user.TenantID
	}

	verificationID, challenge, secretHash, err := generateEmailVerificationChallenge(
		e.config.EmailVerification.Strategy,
		e.config.EmailVerification.OTPDigits,
	)
	if err != nil {
		return "", ErrEmailVerificationUnavailable
	}

	record := &emailVerificationRecord{
		UserID:     user.UserID,
		SecretHash: secretHash,
		ExpiresAt:  time.Now().Add(e.config.EmailVerification.VerificationTTL).Unix(),
		Attempts:   0,
		Strategy:   e.config.EmailVerification.Strategy,
	}

	if err := e.verificationStore.Save(
		ctx,
		effectiveTenant,
		verificationID,
		record,
		e.config.EmailVerification.VerificationTTL,
	); err != nil {
		mapped := mapEmailVerificationStoreError(err)
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationRequest, false, user.UserID, effectiveTenant, "", mapped, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
			}
		})
		return "", mapped
	}

	e.emitAudit(ctx, auditEventEmailVerificationRequest, true, user.UserID, effectiveTenant, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": identifier,
		}
	})
	e.metricInc(MetricEmailVerificationRequest)
	return challenge, nil
}

// ConfirmEmailVerification describes the confirmemailverification operation and its observable behavior.
//
// ConfirmEmailVerification may return an error when input validation, dependency calls, or security checks fail.
// ConfirmEmailVerification does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmEmailVerification(ctx context.Context, challenge string) error {
	if !e.config.EmailVerification.Enabled {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantIDFromContext(ctx), "", ErrEmailVerificationDisabled, nil)
		return ErrEmailVerificationDisabled
	}
	if e.verificationStore == nil || e.verificationLimiter == nil || e.userProvider == nil {
		return ErrEngineNotReady
	}
	if challenge == "" {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantIDFromContext(ctx), "", ErrEmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_challenge",
			}
		})
		return ErrEmailVerificationInvalid
	}

	verificationID, providedHash, err := parseEmailVerificationChallenge(
		e.config.EmailVerification.Strategy,
		challenge,
		e.config.EmailVerification.OTPDigits,
	)
	if err != nil {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantIDFromContext(ctx), "", ErrEmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "parse_failed",
			}
		})
		return ErrEmailVerificationInvalid
	}

	tenantID := tenantIDFromContext(ctx)
	if err := e.verificationLimiter.CheckConfirm(ctx, tenantID, verificationID, clientIPFromContext(ctx)); err != nil {
		mapped := mapEmailVerificationLimiterError(err)
		e.metricInc(MetricEmailVerificationFailure)
		if errors.Is(mapped, ErrEmailVerificationRateLimited) {
			e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
			e.emitRateLimit(ctx, "email_verification_confirm", tenantID, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		} else {
			e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		}
		return mapped
	}

	record, err := e.verificationStore.Consume(
		ctx,
		tenantID,
		verificationID,
		providedHash,
		e.config.EmailVerification.Strategy,
		e.config.EmailVerification.MaxAttempts,
	)
	if err != nil {
		mapped := mapEmailVerificationStoreError(err)
		e.metricInc(MetricEmailVerificationFailure)
		if errors.Is(mapped, ErrEmailVerificationAttempts) {
			e.metricInc(MetricEmailVerificationAttemptsExceeded)
		}
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
			return map[string]string{
				"verification_id": verificationID,
			}
		})
		return mapped
	}

	user, err := e.userProvider.GetUserByID(record.UserID)
	if err != nil {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, record.UserID, tenantID, "", ErrUserNotFound, nil)
		return ErrUserNotFound
	}
	if user.Status == AccountActive {
		e.metricInc(MetricEmailVerificationSuccess)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, func() map[string]string {
			return map[string]string{
				"noop": "already_active",
			}
		})
		return nil
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, user.UserID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	if err := e.updateAccountStatusAndInvalidate(ctx, record.UserID, AccountActive); err != nil {
		e.metricInc(MetricEmailVerificationFailure)
		e.emitAudit(ctx, auditEventEmailVerificationConfirm, false, user.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "status_transition_failed",
			}
		})
		return err
	}

	e.metricInc(MetricEmailVerificationSuccess)
	e.emitAudit(ctx, auditEventEmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
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
	case errors.Is(err, errVerificationRateLimited):
		return ErrEmailVerificationRateLimited
	case errors.Is(err, errVerificationLimiterUnavailable):
		return ErrEmailVerificationUnavailable
	default:
		return ErrEmailVerificationUnavailable
	}
}

func mapEmailVerificationStoreError(err error) error {
	switch {
	case errors.Is(err, errVerificationSecretMismatch),
		errors.Is(err, errVerificationNotFound),
		errors.Is(err, redis.Nil):
		return ErrEmailVerificationInvalid
	case errors.Is(err, errVerificationAttemptsExceeded):
		return ErrEmailVerificationAttempts
	case errors.Is(err, errVerificationRedisUnavailable):
		return ErrEmailVerificationUnavailable
	default:
		return ErrEmailVerificationUnavailable
	}
}
