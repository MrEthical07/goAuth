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
	TOTPAlreadyEnabled        error
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

	GetUserByID               func(context.Context, string) (TOTPUser, error)
	GetTOTPSecret             func(context.Context, string) (*TOTPRecord, error)
	EnableTOTP                func(context.Context, string, []byte) error
	DisableTOTP               func(context.Context, string) error
	MarkTOTPVerified          func(context.Context, string) error
	UpdateTOTPLastUsedCounter func(context.Context, string, int64) error
	LogoutAllInTenant         func(context.Context, string, string) error

	// GrantBackupCodeSetup records, for a few minutes, that the user has just
	// proven their authenticator, which lets them generate their first backup
	// codes without another proof. Optional; a failure only costs the user a
	// TOTP code at regeneration.
	GrantBackupCodeSetup func(ctx context.Context, tenantID, userID string) error
	// RevokeBackupCodeSetup removes that marker. Optional.
	RevokeBackupCodeSetup func(ctx context.Context, tenantID, userID string) error
	// ClearBackupCodes removes every backup code of the user. Disabling TOTP
	// calls it: the codes are a recovery artifact of the factor that is gone.
	ClearBackupCodes func(ctx context.Context, userID string) error

	GenerateSecret func() ([]byte, string, error)
	ProvisionURI   func(string, string) string
	VerifyCode     func([]byte, string, time.Time) (bool, int64, error)

	// CheckTOTPLimiter reports whether the budget is spent without claiming
	// anything; it only gates the requests refused before a code is evaluated.
	CheckTOTPLimiter func(context.Context, string) error
	// ReserveTOTPLimiter claims one attempt before a code is evaluated. last
	// is true when the claim took the final slot of the window, so a wrong
	// code must be reported as rate limited.
	ReserveTOTPLimiter func(context.Context, string) (last bool, err error)
	// ReleaseTOTPLimiter gives a claim back for an attempt that was not a
	// wrong guess (a replayed code, a provider failure). Optional.
	ReleaseTOTPLimiter func(context.Context, string)
	ResetTOTPLimiter   func(context.Context, string) error
	IsTOTPRateLimited  func(error) bool

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

	user, err := deps.GetUserByID(ctx, userID)
	if err != nil {
		return nil, deps.Errors.UserNotFound
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		return nil, statusErr
	}

	// Refuse to re-enroll TOTP while it is already active, using exactly the
	// predicate the login flow uses to decide TOTP is enabled (see
	// internal/flows/login.go). Without this guard a caller (including one
	// holding only a stolen access token) can silently replace a working
	// secret: either it goes live immediately, locking the real owner out and
	// handing the attacker a secret that defeats MFA, or the provider resets
	// to unverified and MFA is silently downgraded. There is no documented
	// "rotate while enabled" flow; the path is DisableTOTP then setup+confirm.
	//
	// If GetTOTPSecret errors or returns a nil record, proceed exactly as
	// v0.5.0 did (no guard). Some providers return an error (e.g.
	// sql.ErrNoRows) rather than an empty record for a user who has never set
	// up TOTP; failing closed here would break first-time enrollment for
	// those providers. Proceeding on error is no weaker than v0.5.0, which
	// never checked at all.
	if deps.GetTOTPSecret != nil {
		if record, terr := deps.GetTOTPSecret(ctx, userID); terr == nil && record != nil && record.Enabled && len(record.Secret) > 0 {
			// Not a TOTPFailure: a refused re-enroll is a policy rejection,
			// not a failed code, and TOTPFailure is a brute-force signal.
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPAlreadyEnabled, nil)
			return nil, deps.Errors.TOTPAlreadyEnabled
		}
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
		deps.CheckTOTPLimiter == nil ||
		deps.ReserveTOTPLimiter == nil ||
		deps.ResetTOTPLimiter == nil ||
		deps.UpdateTOTPLastUsedCounter == nil ||
		deps.LogoutAllInTenant == nil {
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		return deps.Errors.UserNotFound
	}

	before, err := deps.GetUserByID(ctx, userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	record, err := deps.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || len(record.Secret) == 0 {
		return deps.Errors.TOTPNotConfigured
	}

	limiterRefused := func(err error) error {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		if deps.IsTOTPRateLimited(err) {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPUnavailable, nil)
		return deps.Errors.TOTPUnavailable
	}
	if code == "" {
		if err := deps.CheckTOTPLimiter(ctx, userID); err != nil {
			return limiterRefused(err)
		}
		deps.MetricInc(deps.Metrics.TOTPRequired)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPRequired, nil)
		return deps.Errors.TOTPRequired
	}

	// The attempt is claimed before the code is evaluated, so concurrent
	// requests cannot evaluate more codes than the budget allows.
	last, err := deps.ReserveTOTPLimiter(ctx, userID)
	if err != nil {
		return limiterRefused(err)
	}
	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil || !ok {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		if last {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		if err != nil {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPUnavailable, nil)
			return deps.Errors.TOTPUnavailable
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPInvalid, nil)
		return deps.Errors.TOTPInvalid
	}

	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			releaseTOTPAttempt(ctx, userID, deps)
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPInvalid, nil)
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			releaseTOTPAttempt(ctx, userID, deps)
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, before.UserID, before.TenantID, "", deps.Errors.TOTPUnavailable, nil)
			return deps.Errors.TOTPUnavailable
		}
	}

	_ = deps.ResetTOTPLimiter(ctx, userID)
	if err := deps.MarkTOTPVerified(ctx, userID); err != nil {
		return deps.Errors.TOTPUnavailable
	}
	if err := deps.EnableTOTP(ctx, userID, record.Secret); err != nil {
		return deps.Errors.TOTPUnavailable
	}

	after, err := deps.GetUserByID(ctx, userID)
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

	if deps.GrantBackupCodeSetup != nil {
		_ = deps.GrantBackupCodeSetup(ctx, tenant, userID)
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
	if deps.GetUserByID == nil ||
		deps.GetTOTPSecret == nil ||
		deps.VerifyCode == nil ||
		deps.UpdateTOTPLastUsedCounter == nil ||
		deps.CheckTOTPLimiter == nil ||
		deps.ReserveTOTPLimiter == nil ||
		deps.ResetTOTPLimiter == nil {
		return deps.Errors.EngineNotReady
	}
	if userID == "" {
		return deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(ctx, userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	record, err := deps.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || !record.Enabled || len(record.Secret) == 0 {
		return deps.Errors.TOTPNotConfigured
	}

	limiterRefused := func(err error) error {
		if deps.IsTOTPRateLimited(err) {
			return deps.Errors.TOTPRateLimited
		}
		return deps.Errors.TOTPUnavailable
	}
	if code == "" {
		if err := deps.CheckTOTPLimiter(ctx, userID); err != nil {
			return limiterRefused(err)
		}
		return deps.Errors.TOTPRequired
	}

	// The attempt is claimed before the code is evaluated, so concurrent
	// requests cannot evaluate more codes than the budget allows.
	last, err := deps.ReserveTOTPLimiter(ctx, userID)
	if err != nil {
		return limiterRefused(err)
	}
	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil || !ok {
		if last {
			return deps.Errors.TOTPRateLimited
		}
		if err != nil {
			return deps.Errors.TOTPUnavailable
		}
		return deps.Errors.TOTPInvalid
	}
	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			releaseTOTPAttempt(ctx, userID, deps)
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			releaseTOTPAttempt(ctx, userID, deps)
			return deps.Errors.TOTPUnavailable
		}
	}

	_ = deps.ResetTOTPLimiter(ctx, userID)
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

	before, err := deps.GetUserByID(ctx, userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}

	if err := deps.DisableTOTP(ctx, userID); err != nil {
		return deps.Errors.TOTPUnavailable
	}
	// The backup codes belong to the factor that was just removed. A set left
	// behind would work again the day the user enrols a new authenticator.
	var clearErr error
	if deps.ClearBackupCodes != nil {
		clearErr = deps.ClearBackupCodes(ctx, userID)
	}

	after, err := deps.GetUserByID(ctx, userID)
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
	if deps.RevokeBackupCodeSetup != nil {
		_ = deps.RevokeBackupCodeSetup(ctx, tenant, userID)
	}
	if err := deps.LogoutAllInTenant(ctx, tenant, userID); err != nil {
		return errors.Join(deps.Errors.SessionInvalidationFailed, err)
	}
	_ = deps.ResetTOTPLimiter(ctx, userID)
	if clearErr != nil {
		deps.EmitAudit(ctx, deps.Events.TOTPDisabled, false, userID, tenant, "", clearErr, func() map[string]string {
			return map[string]string{"reason": "backup_codes_not_cleared"}
		})
		return errors.Join(deps.Errors.TOTPUnavailable, clearErr)
	}

	deps.EmitAudit(ctx, deps.Events.TOTPDisabled, true, userID, tenant, "", nil, nil)
	return nil
}

func RunVerifyTOTPForUser(ctx context.Context, user TOTPUser, code string, deps TOTPDeps) error {
	normalizeTOTPDeps(&deps)

	if deps.GetTOTPSecret == nil ||
		deps.VerifyCode == nil ||
		deps.UpdateTOTPLastUsedCounter == nil ||
		deps.CheckTOTPLimiter == nil ||
		deps.ReserveTOTPLimiter == nil ||
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

	limiterRefused := func(err error) error {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		if deps.IsTOTPRateLimited(err) {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPUnavailable, nil)
		return deps.Errors.TOTPUnavailable
	}
	if code == "" {
		if err := deps.CheckTOTPLimiter(ctx, user.UserID); err != nil {
			return limiterRefused(err)
		}
		deps.MetricInc(deps.Metrics.TOTPRequired)
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRequired, nil)
		return deps.Errors.TOTPRequired
	}

	// The attempt is claimed before the code is evaluated, so concurrent
	// requests cannot evaluate more codes than the budget allows.
	last, err := deps.ReserveTOTPLimiter(ctx, user.UserID)
	if err != nil {
		return limiterRefused(err)
	}
	ok, counter, err := deps.VerifyCode(record.Secret, code, deps.Now())
	if err != nil || !ok {
		deps.MetricInc(deps.Metrics.TOTPFailure)
		if last {
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPRateLimited, nil)
			return deps.Errors.TOTPRateLimited
		}
		deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPInvalid, nil)
		return deps.Errors.TOTPInvalid
	}

	if deps.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			releaseTOTPAttempt(ctx, user.UserID, deps)
			deps.MetricInc(deps.Metrics.TOTPFailure)
			deps.EmitAudit(ctx, deps.Events.TOTPFailure, false, user.UserID, user.TenantID, "", deps.Errors.TOTPInvalid, nil)
			return deps.Errors.TOTPInvalid
		}
		if err := deps.UpdateTOTPLastUsedCounter(ctx, user.UserID, counter); err != nil {
			releaseTOTPAttempt(ctx, user.UserID, deps)
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

// releaseTOTPAttempt gives back the attempt claimed before a code was
// evaluated when the code turned out right but the request still fails (a
// replayed code, a provider error): that was not a wrong guess.
func releaseTOTPAttempt(ctx context.Context, userID string, deps TOTPDeps) {
	if deps.ReleaseTOTPLimiter != nil {
		deps.ReleaseTOTPLimiter(ctx, userID)
	}
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
