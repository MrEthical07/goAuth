package flows

import (
	"context"
	"errors"
	"time"
)

type TOTPUser struct {
	UserID         string
	Identifier     string
	TenantID       string
	Status         uint8
	AccountVersion uint32
}

type TOTPRecord struct {
	Secret          []byte
	Enabled         bool
	LastUsedCounter int64
}

type TOTPSetup struct {
	SecretBase32 string
	QRCodeURL    string
}

type TOTPProvision struct {
	Secret string
	URI    string
}

type TOTPMetrics struct {
	TOTPRequired int
	TOTPFailure  int
	TOTPSuccess  int
}

type TOTPEvents struct {
	TOTPSetupRequested string
	TOTPEnabled        string
	TOTPDisabled       string
	TOTPFailure        string
	TOTPSuccess        string
}

type TOTPErrors struct {
	TOTPFeatureDisabled       error
	EngineNotReady            error
	UserNotFound              error
	TOTPUnavailable           error
	TOTPNotConfigured         error
	TOTPRequired              error
	TOTPInvalid               error
	TOTPRateLimited           error
	AccountVersionNotAdvanced error
	SessionInvalidationFailed error
}

type TOTPDeps struct {
	Enabled                 bool
	EnforceReplayProtection bool

	Now                 func() time.Time
	TenantIDFromContext func(context.Context) string
	AccountStatusError  func(uint8) error

	GetUserByID               func(string) (TOTPUser, error)
	GetTOTPSecret             func(context.Context, string) (*TOTPRecord, error)
	EnableTOTP                func(context.Context, string, []byte) error
	DisableTOTP               func(context.Context, string) error
	MarkTOTPVerified          func(context.Context, string) error
	UpdateTOTPLastUsedCounter func(context.Context, string, int64) error
	LogoutAllInTenant         func(context.Context, string, string) error

	GenerateSecret func() ([]byte, string, error)
	ProvisionURI   func(string, string) string
	VerifyCode     func([]byte, string, time.Time) (bool, int64, error)

	CheckTOTPLimiter         func(context.Context, string) error
	RecordTOTPLimiterFailure func(context.Context, string) error
	ResetTOTPLimiter         func(context.Context, string) error
	IsTOTPRateLimited        func(error) bool

	MetricInc func(int)
	EmitAudit func(context.Context, string, bool, string, string, string, error, func() map[string]string)

	Metrics TOTPMetrics
	Events  TOTPEvents
	Errors  TOTPErrors
}

func RunGenerateTOTPSetup(ctx context.Context, userID string, deps TOTPDeps) (*TOTPSetup, error) {
	normalizeTOTPDeps(&deps)

	if !deps.Enabled {
		return nil, deps.Errors.TOTPFeatureDisabled
	}
	if deps.GenerateSecret == nil || deps.ProvisionURI == nil || deps.GetUserByID == nil || deps.EnableTOTP == nil || deps.AccountStatusError == nil {
		return nil, deps.Errors.EngineNotReady
	}
	if userID == "" {
		return nil, deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		return nil, deps.Errors.UserNotFound
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		return nil, statusErr
	}

	secretRaw, secretBase32, err := deps.GenerateSecret()
	if err != nil {
		return nil, deps.Errors.TOTPUnavailable
	}
	if err := deps.EnableTOTP(ctx, userID, secretRaw); err != nil {
		return nil, deps.Errors.TOTPUnavailable
	}

	account := user.Identifier
	if account == "" {
		account = user.UserID
	}
	out := &TOTPSetup{
		SecretBase32: secretBase32,
		QRCodeURL:    deps.ProvisionURI(secretBase32, account),
	}

	deps.EmitAudit(ctx, deps.Events.TOTPSetupRequested, true, user.UserID, user.TenantID, "", nil, nil)
	return out, nil
}

func RunProvisionTOTP(ctx context.Context, userID string, deps TOTPDeps) (*TOTPProvision, error) {
	setup, err := RunGenerateTOTPSetup(ctx, userID, deps)
	if err != nil {
		return nil, err
	}
	return &TOTPProvision{
		Secret: setup.SecretBase32,
		URI:    setup.QRCodeURL,
	}, nil
}

func RunConfirmTOTPSetup(ctx context.Context, userID, code string, deps TOTPDeps) error {
	normalizeTOTPDeps(&deps)

	if !deps.Enabled {
		return deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetUserByID == nil ||
		deps.GetTOTPSecret == nil ||
		deps.VerifyCode == nil ||
		deps.MarkTOTPVerified == nil ||
		deps.EnableTOTP == nil ||
		deps.UpdateTOTPLastUsedCounter == nil ||
		deps.LogoutAllInTenant == nil {
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		return deps.Errors.UserNotFound
	}

	before, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	record, err := deps.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || len(record.Secret) == 0 {
		return deps.Errors.TOTPNotConfigured
	}

	if code == "" {
		deps.MetricInc(deps.Metrics.TOTPRequired)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPRequired, nil)
		return deps.Errors.TOTPRequired
	}

	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPUnavailable, nil)
		return deps.Errors.TOTPUnavailable
	}
	if !ok {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPInvalid, nil)
		return deps.Errors.TOTPInvalid
	}

	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPInvalid, nil)
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPUnavailable, nil)
			return deps.Errors.TOTPUnavailable
		}
	}

	if err := deps.MarkTOTPVerified(ctx, userID); err != nil {
		return deps.Errors.TOTPUnavailable
	}
	if err := deps.EnableTOTP(ctx, userID, record.Secret); err != nil {
		return deps.Errors.TOTPUnavailable
	}

	after, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}
	if after.AccountVersion <= before.AccountVersion {
		return deps.Errors.AccountVersionNotAdvanced
	}

	tenant := deps.TenantIDFromContext(ctx)
	if after.TenantID != "" {
		tenant = after.TenantID
	}
	if err := deps.LogoutAllInTenant(ctx, tenant, userID); err != nil {
		return errors.Join(deps.Errors.SessionInvalidationFailed, err)
	}

	deps.MetricInc(deps.Metrics.TOTPSuccess)
	deps.EmitAudit(ctx, deps.Events.TOTPEnabled, true, userID, tenant, "", nil, nil)
	return nil
}

func RunVerifyTOTP(ctx context.Context, userID, code string, deps TOTPDeps) error {
	normalizeTOTPDeps(&deps)

	if !deps.Enabled {
		return deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetUserByID == nil || deps.GetTOTPSecret == nil || deps.VerifyCode == nil || deps.UpdateTOTPLastUsedCounter == nil {
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		return deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	record, err := deps.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || !record.Enabled || len(record.Secret) == 0 {
		return deps.Errors.TOTPNotConfigured
	}

	if code == "" {
		return deps.Errors.TOTPRequired
	}

	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil {
		return deps.Errors.TOTPUnavailable
	}
	if !ok {
		return deps.Errors.TOTPInvalid
	}

	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			return deps.Errors.TOTPUnavailable
		}
	}

	deps.MetricInc(deps.Metrics.TOTPSuccess)
	deps.EmitAudit(ctx, deps.Events.TOTPSuccess, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

func RunDisableTOTP(ctx context.Context, userID string, deps TOTPDeps) error {
	normalizeTOTPDeps(&deps)

	if !deps.Enabled {
		return deps.Errors.TOTPFeatureDisabled
	}
	if deps.GetUserByID == nil || deps.DisableTOTP == nil || deps.LogoutAllInTenant == nil || deps.ResetTOTPLimiter == nil {
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		return deps.Errors.UserNotFound
	}

	before, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	if err := deps.DisableTOTP(ctx, userID); err != nil {
		return deps.Errors.TOTPUnavailable
	}

	after, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}
	if after.AccountVersion <= before.AccountVersion {
		return deps.Errors.AccountVersionNotAdvanced
	}

	tenant := deps.TenantIDFromContext(ctx)
	if after.TenantID != "" {
		tenant = after.TenantID
	}
	if err := deps.LogoutAllInTenant(ctx, tenant, userID); err != nil {
		return errors.Join(deps.Errors.SessionInvalidationFailed, err)
	}
	_ = deps.ResetTOTPLimiter(ctx, userID)

	deps.EmitAudit(ctx, deps.Events.TOTPDisabled, true, userID, tenant, "", nil, nil)
	return nil
}

func RunVerifyTOTPForUser(ctx context.Context, user TOTPUser, code string, deps TOTPDeps) error {
	normalizeTOTPDeps(&deps)

	if deps.GetTOTPSecret == nil ||
		deps.VerifyCode == nil ||
		deps.UpdateTOTPLastUsedCounter == nil ||
		deps.CheckTOTPLimiter == nil ||
		deps.RecordTOTPLimiterFailure == nil ||
		deps.ResetTOTPLimiter == nil {
		return deps.Errors.EngineNotReady
	}

	record, err := deps.GetTOTPSecret(ctx, user.UserID)
	if err != nil {
		return deps.Errors.TOTPUnavailable
	}
	if record == nil || !record.Enabled || len(record.Secret) == 0 {
		return nil
	}

	if err := deps.CheckTOTPLimiter(ctx, user.UserID); err != nil {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		if deps.IsTOTPRateLimited(err) {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPUnavailable, nil)
		return deps.Errors.TOTPUnavailable
	}
	if code == "" {
		deps.MetricInc(deps.Metrics.TOTPRequired)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRequired, nil)
		return deps.Errors.TOTPRequired
	}

	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil || !ok {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		recErr := deps.RecordTOTPLimiterFailure(ctx, user.UserID)
		if recErr != nil && deps.IsTOTPRateLimited(recErr) {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPInvalid, nil)
		return deps.Errors.TOTPInvalid
	}

	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPInvalid, nil)
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPUnavailable, nil)
			return deps.Errors.TOTPUnavailable
		}
	}

	_ = deps.ResetTOTPLimiter(ctx, user.UserID)
	deps.MetricInc(deps.Metrics.TOTPSuccess)
	deps.EmitAudit(ctx, deps.Events.TOTPSuccess, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

func normalizeTOTPDeps(deps *TOTPDeps) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.IsTOTPRateLimited == nil {
		deps.IsTOTPRateLimited = func(error) bool { return false }
	}
}
