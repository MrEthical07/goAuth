package goAuth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

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
		Enabled:         cfg.EmailVerification.Enabled,
		Strategy:        int(cfg.EmailVerification.Strategy),
		OTPDigits:       cfg.EmailVerification.OTPDigits,
		VerificationTTL: cfg.EmailVerification.VerificationTTL,
		MaxAttempts:     cfg.EmailVerification.MaxAttempts,
		ActiveStatus:    uint8(AccountActive),
		TenantIDFromContext: tenantIDFromContext,
		ClientIPFromContext: clientIPFromContext,
		Now:                time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MapLimiterError:      mapEmailVerificationLimiterError,
		MapStoreError:        mapEmailVerificationStoreError,
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
