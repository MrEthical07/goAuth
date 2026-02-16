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
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

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
		Enabled:               cfg.PasswordReset.Enabled,
		Strategy:              int(cfg.PasswordReset.Strategy),
		OTPDigits:             cfg.PasswordReset.OTPDigits,
		ResetTTL:              cfg.PasswordReset.ResetTTL,
		MaxAttempts:           cfg.PasswordReset.MaxAttempts,
		RequireMFA:            cfg.TOTP.Enabled && (cfg.TOTP.RequireTOTPForPasswordReset || cfg.TOTP.RequireForPasswordReset),
		TenantIDFromContext:   tenantIDFromContext,
		ClientIPFromContext:   clientIPFromContext,
		Now:                   time.Now,
		AccountStatusError: func(status uint8) error {
			return accountStatusToError(AccountStatus(status))
		},
		MapLimiterError:   mapPasswordResetLimiterError,
		MapStoreError:     mapPasswordResetStoreError,
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
