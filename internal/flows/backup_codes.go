package flows

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
)

const BackupCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

type BackupCodeUser struct {
	UserID   string
	TenantID string
	Status   uint8
}

type BackupCodeRecord struct {
	Hash [32]byte
}

type BackupCodeMetrics struct {
	BackupCodeUsed        int
	BackupCodeFailed      int
	BackupCodeRegenerated int
}

type BackupCodeEvents struct {
	BackupCodesGenerated string
	BackupCodeUsed       string
	BackupCodeFailed     string
}

type BackupCodeErrors struct {
	TOTPFeatureDisabled                error
	EngineNotReady                     error
	UserNotFound                       error
	BackupCodeUnavailable              error
	BackupCodeRegenerationRequiresTOTP error
	BackupCodeInvalid                  error
	BackupCodeRateLimited              error
}

type BackupCodeDeps struct {
	Enabled          bool
	BackupCodeCount  int
	BackupCodeLength int

	TenantIDFromContext func(context.Context) string
	AccountStatusError  func(uint8) error

	GetUserByID        func(string) (BackupCodeUser, error)
	GetBackupCodes     func(context.Context, string) ([]BackupCodeRecord, error)
	ReplaceBackupCodes func(context.Context, string, []BackupCodeRecord) error
	ConsumeBackupCode  func(context.Context, string, [32]byte) (bool, error)
	VerifyTOTPForUser  func(context.Context, BackupCodeUser, string) error

	CheckLimiter         func(context.Context, string, string) error
	RecordLimiterFailure func(context.Context, string, string) error
	ResetLimiter         func(context.Context, string, string) error
	IsRateLimited        func(error) bool

	RandomIndex func(int) (int, error)

	MetricInc func(int)
	EmitAudit func(context.Context, string, bool, string, string, string, error, func() map[string]string)

	Metrics BackupCodeMetrics
	Events  BackupCodeEvents
	Errors  BackupCodeErrors
}

func RunGenerateBackupCodes(ctx context.Context, userID string, deps BackupCodeDeps) ([]string, error) {
	normalizeBackupCodeDeps(&deps)

	if !deps.Enabled {
		emitBackupCodeFailure(ctx, deps, "", "", deps.Errors.TOTPFeatureDisabled, map[string]string{
			"action": "generate",
		})
		return nil, deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetUserByID == nil || deps.GetBackupCodes == nil || deps.ReplaceBackupCodes == nil {
		emitBackupCodeFailure(ctx, deps, userID, "", deps.Errors.EngineNotReady, map[string]string{
			"action": "generate",
		})
		return nil, deps.Errors.EngineNotReady
	}
	if userID == "" {
		emitBackupCodeFailure(ctx, deps, "", "", deps.Errors.UserNotFound, map[string]string{
			"action": "generate",
		})
		return nil, deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		emitBackupCodeFailure(ctx, deps, userID, "", deps.Errors.UserNotFound, map[string]string{
			"action": "generate",
		})
		return nil, deps.Errors.UserNotFound
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		emitBackupCodeFailure(ctx, deps, user.UserID, user.TenantID, statusErr, map[string]string{
			"action": "generate",
		})
		return nil, statusErr
	}
	existing, err := deps.GetBackupCodes(ctx, userID)
	if err != nil {
		emitBackupCodeFailure(ctx, deps, user.UserID, user.TenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
			"action": "generate",
			"reason": "load_existing_failed",
		})
		return nil, deps.Errors.BackupCodeUnavailable
	}
	if len(existing) > 0 {
		emitBackupCodeFailure(ctx, deps, user.UserID, user.TenantID, deps.Errors.BackupCodeRegenerationRequiresTOTP, map[string]string{
			"action": "generate",
		})
		return nil, deps.Errors.BackupCodeRegenerationRequiresTOTP
	}

	return runGenerateAndReplaceBackupCodes(ctx, user.UserID, user.TenantID, "generate", deps)
}

func RunRegenerateBackupCodes(ctx context.Context, userID, totpCode string, deps BackupCodeDeps) ([]string, error) {
	normalizeBackupCodeDeps(&deps)

	if !deps.Enabled {
		emitBackupCodeFailure(ctx, deps, "", "", deps.Errors.TOTPFeatureDisabled, map[string]string{
			"action": "regenerate",
		})
		return nil, deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetUserByID == nil || deps.VerifyTOTPForUser == nil || deps.ReplaceBackupCodes == nil {
		emitBackupCodeFailure(ctx, deps, userID, "", deps.Errors.EngineNotReady, map[string]string{
			"action": "regenerate",
		})
		return nil, deps.Errors.EngineNotReady
	}
	if userID == "" {
		emitBackupCodeFailure(ctx, deps, "", "", deps.Errors.UserNotFound, map[string]string{
			"action": "regenerate",
		})
		return nil, deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		emitBackupCodeFailure(ctx, deps, userID, "", deps.Errors.UserNotFound, map[string]string{
			"action": "regenerate",
		})
		return nil, deps.Errors.UserNotFound
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		emitBackupCodeFailure(ctx, deps, user.UserID, user.TenantID, statusErr, map[string]string{
			"action": "regenerate",
		})
		return nil, statusErr
	}
	if err := deps.VerifyTOTPForUser(ctx, user, totpCode); err != nil {
		emitBackupCodeFailure(ctx, deps, user.UserID, user.TenantID, err, map[string]string{
			"action": "regenerate",
		})
		return nil, err
	}

	return runGenerateAndReplaceBackupCodes(ctx, user.UserID, user.TenantID, "regenerate", deps)
}

func RunVerifyBackupCode(ctx context.Context, userID, code string, deps BackupCodeDeps) error {
	return RunVerifyBackupCodeInTenant(ctx, deps.TenantIDFromContext(ctx), userID, code, deps)
}

func RunVerifyBackupCodeInTenant(ctx context.Context, tenantID, userID, code string, deps BackupCodeDeps) error {
	normalizeBackupCodeDeps(&deps)

	if deps.ConsumeBackupCode == nil || deps.CheckLimiter == nil || deps.RecordLimiterFailure == nil || deps.ResetLimiter == nil {
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.EngineNotReady, nil)
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		emitBackupCodeFailure(ctx, deps, "", tenantID, deps.Errors.UserNotFound, nil)
		return deps.Errors.UserNotFound
	}
	if tenantID == "" {
		tenantID = "0"
	}

	if err := deps.CheckLimiter(ctx, tenantID, userID); err != nil {
		if deps.IsRateLimited(err) {
			emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeRateLimited, nil)
			return deps.Errors.BackupCodeRateLimited
		}
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
			"reason": "limiter_check_failed",
		})
		return deps.Errors.BackupCodeUnavailable
	}

	canonical := CanonicalizeBackupCode(code)
	if canonical == "" {
		deps.MetricInc(deps.Metrics.BackupCodeFailed)
		if err := deps.RecordLimiterFailure(ctx, tenantID, userID); err != nil {
			if deps.IsRateLimited(err) {
				emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeRateLimited, map[string]string{
					"reason": "invalid_format",
				})
				return deps.Errors.BackupCodeRateLimited
			}
			emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
				"reason": "invalid_format",
			})
			return deps.Errors.BackupCodeUnavailable
		}
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeInvalid, map[string]string{
			"reason": "invalid_format",
		})
		return deps.Errors.BackupCodeInvalid
	}

	ok, err := deps.ConsumeBackupCode(ctx, userID, BackupCodeHash(userID, canonical))
	if err != nil {
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
			"reason": "consume_failed",
		})
		return deps.Errors.BackupCodeUnavailable
	}
	if !ok {
		deps.MetricInc(deps.Metrics.BackupCodeFailed)
		if err := deps.RecordLimiterFailure(ctx, tenantID, userID); err != nil {
			if deps.IsRateLimited(err) {
				emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeRateLimited, map[string]string{
					"reason": "invalid_code",
				})
				return deps.Errors.BackupCodeRateLimited
			}
			emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
				"reason": "invalid_code",
			})
			return deps.Errors.BackupCodeUnavailable
		}
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeInvalid, map[string]string{
			"reason": "invalid_code",
		})
		return deps.Errors.BackupCodeInvalid
	}

	_ = deps.ResetLimiter(ctx, tenantID, userID)
	deps.MetricInc(deps.Metrics.BackupCodeUsed)
	deps.EmitAudit(ctx, deps.Events.BackupCodeUsed, true, userID, tenantID, "", nil, nil)
	return nil
}

func runGenerateAndReplaceBackupCodes(ctx context.Context, userID, tenantID, action string, deps BackupCodeDeps) ([]string, error) {
	count := deps.BackupCodeCount
	length := deps.BackupCodeLength
	if count <= 0 || length <= 0 {
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
			"action": action,
			"reason": "invalid_config",
		})
		return nil, deps.Errors.BackupCodeUnavailable
	}

	records := make([]BackupCodeRecord, 0, count)
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw, err := NewBackupCode(length, deps.RandomIndex)
		if err != nil {
			emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
				"action": action,
				"reason": "generation_failed",
			})
			return nil, deps.Errors.BackupCodeUnavailable
		}
		canonical := CanonicalizeBackupCode(raw)
		records = append(records, BackupCodeRecord{Hash: BackupCodeHash(userID, canonical)})
		codes = append(codes, FormatBackupCode(raw))
	}

	if err := deps.ReplaceBackupCodes(ctx, userID, records); err != nil {
		emitBackupCodeFailure(ctx, deps, userID, tenantID, deps.Errors.BackupCodeUnavailable, map[string]string{
			"action": action,
			"reason": "store_replace_failed",
		})
		return nil, deps.Errors.BackupCodeUnavailable
	}

	deps.MetricInc(deps.Metrics.BackupCodeRegenerated)
	deps.EmitAudit(ctx, deps.Events.BackupCodesGenerated, true, userID, tenantID, "", nil, func() map[string]string {
		return map[string]string{
			"action": action,
		}
	})
	return codes, nil
}

func NewBackupCode(length int, randomIndex func(int) (int, error)) (string, error) {
	if randomIndex == nil {
		randomIndex = cryptoRandomIndex
	}
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := randomIndex(len(BackupCodeAlphabet))
		if err != nil {
			return "", err
		}
		b.WriteByte(BackupCodeAlphabet[n])
	}
	return b.String(), nil
}

func FormatBackupCode(code string) string {
	n := len(code)
	if n < 8 {
		return code
	}
	mid := n / 2
	return code[:mid] + "-" + code[mid:]
}

func CanonicalizeBackupCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func BackupCodeHash(userID, canonicalCode string) [32]byte {
	data := make([]byte, 0, len(userID)+1+len(canonicalCode))
	data = append(data, userID...)
	data = append(data, 0)
	data = append(data, canonicalCode...)
	return sha256.Sum256(data)
}

func cryptoRandomIndex(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func normalizeBackupCodeDeps(deps *BackupCodeDeps) {
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "0" }
	}
	if deps.AccountStatusError == nil {
		deps.AccountStatusError = func(uint8) error { return nil }
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.IsRateLimited == nil {
		deps.IsRateLimited = func(error) bool { return false }
	}
	if deps.RandomIndex == nil {
		deps.RandomIndex = cryptoRandomIndex
	}
}

func emitBackupCodeFailure(ctx context.Context, deps BackupCodeDeps, userID, tenantID string, err error, metadata map[string]string) {
	if tenantID == "" {
		tenantID = deps.TenantIDFromContext(ctx)
	}
	if tenantID == "" {
		tenantID = "0"
	}
	deps.EmitAudit(ctx, deps.Events.BackupCodeFailed, false, userID, tenantID, "", err, func() map[string]string {
		if len(metadata) == 0 {
			return nil
		}
		out := make(map[string]string, len(metadata))
		for k, v := range metadata {
			out[k] = v
		}
		return out
	})
}
