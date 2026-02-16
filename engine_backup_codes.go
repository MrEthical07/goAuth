package goAuth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"

	"github.com/MrEthical07/goAuth/internal/limiters"
)

const backupCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateBackupCodes describes the generatebackupcodes operation and its observable behavior.
//
// GenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// GenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if !e.config.TOTP.Enabled {
		return nil, ErrTOTPFeatureDisabled
	}
	if e.userProvider == nil {
		return nil, ErrEngineNotReady
	}
	if userID == "" {
		return nil, ErrUserNotFound
	}

	user, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		return nil, statusErr
	}
	existing, err := e.userProvider.GetBackupCodes(ctx, userID)
	if err != nil {
		return nil, ErrBackupCodeUnavailable
	}
	if len(existing) > 0 {
		return nil, ErrBackupCodeRegenerationRequiresTOTP
	}

	return e.generateAndReplaceBackupCodes(ctx, user.UserID, user.TenantID)
}

// RegenerateBackupCodes describes the regeneratebackupcodes operation and its observable behavior.
//
// RegenerateBackupCodes may return an error when input validation, dependency calls, or security checks fail.
// RegenerateBackupCodes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	if !e.config.TOTP.Enabled {
		return nil, ErrTOTPFeatureDisabled
	}
	if e.userProvider == nil {
		return nil, ErrEngineNotReady
	}
	if userID == "" {
		return nil, ErrUserNotFound
	}

	user, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		return nil, statusErr
	}
	if err := e.verifyTOTPForUser(ctx, user, totpCode); err != nil {
		return nil, err
	}

	return e.generateAndReplaceBackupCodes(ctx, user.UserID, user.TenantID)
}

func (e *Engine) generateAndReplaceBackupCodes(ctx context.Context, userID, tenantID string) ([]string, error) {
	count := e.config.TOTP.BackupCodeCount
	length := e.config.TOTP.BackupCodeLength
	if count <= 0 || length <= 0 {
		return nil, ErrBackupCodeUnavailable
	}

	records := make([]BackupCodeRecord, 0, count)
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw, err := newBackupCode(length)
		if err != nil {
			return nil, ErrBackupCodeUnavailable
		}
		canonical := canonicalizeBackupCode(raw)
		records = append(records, BackupCodeRecord{Hash: backupCodeHash(userID, canonical)})
		codes = append(codes, formatBackupCode(raw))
	}

	if err := e.userProvider.ReplaceBackupCodes(ctx, userID, records); err != nil {
		return nil, ErrBackupCodeUnavailable
	}

	e.metricInc(MetricBackupCodeRegenerated)
	e.emitAudit(ctx, auditEventBackupCodesGenerated, true, userID, tenantID, "", nil, nil)
	return codes, nil
}

// VerifyBackupCode describes the verifybackupcode operation and its observable behavior.
//
// VerifyBackupCode may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCode does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCode(ctx context.Context, userID, code string) error {
	return e.VerifyBackupCodeInTenant(ctx, tenantIDFromContext(ctx), userID, code)
}

// VerifyBackupCodeInTenant describes the verifybackupcodeintenant operation and its observable behavior.
//
// VerifyBackupCodeInTenant may return an error when input validation, dependency calls, or security checks fail.
// VerifyBackupCodeInTenant does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyBackupCodeInTenant(ctx context.Context, tenantID, userID, code string) error {
	if e == nil || e.userProvider == nil || e.backupLimiter == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}
	if tenantID == "" {
		tenantID = "0"
	}

	if err := e.backupLimiter.Check(ctx, tenantID, userID); err != nil {
		if errors.Is(err, limiters.ErrBackupCodeRateLimited) {
			return ErrBackupCodeRateLimited
		}
		return ErrBackupCodeUnavailable
	}

	canonical := canonicalizeBackupCode(code)
	if canonical == "" {
		e.metricInc(MetricBackupCodeFailed)
		if err := e.backupLimiter.RecordFailure(ctx, tenantID, userID); err != nil {
			if errors.Is(err, limiters.ErrBackupCodeRateLimited) {
				return ErrBackupCodeRateLimited
			}
			return ErrBackupCodeUnavailable
		}
		return ErrBackupCodeInvalid
	}

	ok, err := e.userProvider.ConsumeBackupCode(ctx, userID, backupCodeHash(userID, canonical))
	if err != nil {
		return ErrBackupCodeUnavailable
	}
	if !ok {
		e.metricInc(MetricBackupCodeFailed)
		e.emitAudit(ctx, auditEventBackupCodeFailed, false, userID, tenantID, "", ErrBackupCodeInvalid, nil)
		if err := e.backupLimiter.RecordFailure(ctx, tenantID, userID); err != nil {
			if errors.Is(err, limiters.ErrBackupCodeRateLimited) {
				return ErrBackupCodeRateLimited
			}
			return ErrBackupCodeUnavailable
		}
		return ErrBackupCodeInvalid
	}

	_ = e.backupLimiter.Reset(ctx, tenantID, userID)
	e.metricInc(MetricBackupCodeUsed)
	e.emitAudit(ctx, auditEventBackupCodeUsed, true, userID, tenantID, "", nil, nil)
	return nil
}

func newBackupCode(length int) (string, error) {
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, bigInt(len(backupCodeAlphabet)))
		if err != nil {
			return "", err
		}
		b.WriteByte(backupCodeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

func formatBackupCode(code string) string {
	n := len(code)
	if n < 8 {
		return code
	}
	mid := n / 2
	return code[:mid] + "-" + code[mid:]
}

func canonicalizeBackupCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func backupCodeHash(userID, canonicalCode string) [32]byte {
	data := make([]byte, 0, len(userID)+1+len(canonicalCode))
	data = append(data, userID...)
	data = append(data, 0)
	data = append(data, canonicalCode...)
	return sha256.Sum256(data)
}

func bigInt(v int) *big.Int {
	return big.NewInt(int64(v))
}
