package goAuth

import (
	"context"
	"errors"
	"time"
)

// GenerateTOTPSetup describes the generatetotpsetup operation and its observable behavior.
//
// GenerateTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// GenerateTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) GenerateTOTPSetup(ctx context.Context, userID string) (*TOTPSetup, error) {
	if !e.config.TOTP.Enabled {
		return nil, ErrTOTPFeatureDisabled
	}
	if e.totp == nil || e.userProvider == nil {
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

	secretRaw, secretBase32, err := e.totp.GenerateSecret()
	if err != nil {
		return nil, ErrTOTPUnavailable
	}
	if err := e.userProvider.EnableTOTP(ctx, userID, secretRaw); err != nil {
		return nil, ErrTOTPUnavailable
	}

	account := user.Identifier
	if account == "" {
		account = user.UserID
	}
	out := &TOTPSetup{
		SecretBase32: secretBase32,
		QRCodeURL:    e.totp.ProvisionURI(secretBase32, account),
	}

	e.emitAudit(ctx, auditEventTOTPSetupRequested, true, user.UserID, user.TenantID, "", nil, nil)
	return out, nil
}

// ProvisionTOTP describes the provisiontotp operation and its observable behavior.
//
// ProvisionTOTP may return an error when input validation, dependency calls, or security checks fail.
// ProvisionTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ProvisionTOTP(ctx context.Context, userID string) (*TOTPProvision, error) {
	setup, err := e.GenerateTOTPSetup(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &TOTPProvision{
		Secret: setup.SecretBase32,
		URI:    setup.QRCodeURL,
	}, nil
}

// ConfirmTOTPSetup describes the confirmtotpsetup operation and its observable behavior.
//
// ConfirmTOTPSetup may return an error when input validation, dependency calls, or security checks fail.
// ConfirmTOTPSetup does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) ConfirmTOTPSetup(ctx context.Context, userID, code string) error {
	if !e.config.TOTP.Enabled {
		return ErrTOTPFeatureDisabled
	}
	if e.userProvider == nil || e.totp == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}

	before, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	record, err := e.userProvider.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || len(record.Secret) == 0 {
		return ErrTOTPNotConfigured
	}

	if code == "" {
		e.metricInc(MetricTOTPRequired)
		e.emitAudit(ctx, auditEventTOTPFailure, false, before.UserID, before.TenantID, "", ErrTOTPRequired, nil)
		return ErrTOTPRequired
	}

	ok, counter, err := e.totp.VerifyCode(record.Secret, code, time.Now())
	if err != nil {
		e.metricInc(MetricTOTPFailure)
		e.emitAudit(ctx, auditEventTOTPFailure, false, before.UserID, before.TenantID, "", ErrTOTPUnavailable, nil)
		return ErrTOTPUnavailable
	}
	if !ok {
		e.metricInc(MetricTOTPFailure)
		e.emitAudit(ctx, auditEventTOTPFailure, false, before.UserID, before.TenantID, "", ErrTOTPInvalid, nil)
		return ErrTOTPInvalid
	}

	if e.config.TOTP.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			e.metricInc(MetricTOTPFailure)
			e.emitAudit(ctx, auditEventTOTPFailure, false, before.UserID, before.TenantID, "", ErrTOTPInvalid, nil)
			return ErrTOTPInvalid
		}
		if err := e.userProvider.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			e.metricInc(MetricTOTPFailure)
			e.emitAudit(ctx, auditEventTOTPFailure, false, before.UserID, before.TenantID, "", ErrTOTPUnavailable, nil)
			return ErrTOTPUnavailable
		}
	}

	if err := e.userProvider.MarkTOTPVerified(ctx, userID); err != nil {
		return ErrTOTPUnavailable
	}
	if err := e.userProvider.EnableTOTP(ctx, userID, record.Secret); err != nil {
		return ErrTOTPUnavailable
	}

	after, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	if after.AccountVersion <= before.AccountVersion {
		return ErrAccountVersionNotAdvanced
	}

	tenant := tenantIDFromContext(ctx)
	if after.TenantID != "" {
		tenant = after.TenantID
	}
	if err := e.LogoutAllInTenant(ctx, tenant, userID); err != nil {
		return errors.Join(ErrSessionInvalidationFailed, err)
	}

	e.metricInc(MetricTOTPSuccess)
	e.emitAudit(ctx, auditEventTOTPEnabled, true, userID, tenant, "", nil, nil)
	return nil
}

// VerifyTOTP describes the verifytotp operation and its observable behavior.
//
// VerifyTOTP may return an error when input validation, dependency calls, or security checks fail.
// VerifyTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) VerifyTOTP(ctx context.Context, userID, code string) error {
	if !e.config.TOTP.Enabled {
		return ErrTOTPFeatureDisabled
	}
	if e.userProvider == nil || e.totp == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}

	user, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	record, err := e.userProvider.GetTOTPSecret(ctx, userID)
	if err != nil || record == nil || !record.Enabled || len(record.Secret) == 0 {
		return ErrTOTPNotConfigured
	}

	if code == "" {
		return ErrTOTPRequired
	}

	ok, counter, err := e.totp.VerifyCode(record.Secret, code, time.Now())
	if err != nil {
		return ErrTOTPUnavailable
	}
	if !ok {
		return ErrTOTPInvalid
	}

	if e.config.TOTP.EnforceReplayProtection {
		if counter <= record.LastUsedCounter {
			return ErrTOTPInvalid
		}
		if err := e.userProvider.UpdateTOTPLastUsedCounter(ctx, userID, counter); err != nil {
			return ErrTOTPUnavailable
		}
	}

	e.metricInc(MetricTOTPSuccess)
	e.emitAudit(ctx, auditEventTOTPSuccess, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

// DisableTOTP describes the disabletotp operation and its observable behavior.
//
// DisableTOTP may return an error when input validation, dependency calls, or security checks fail.
// DisableTOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) DisableTOTP(ctx context.Context, userID string) error {
	if !e.config.TOTP.Enabled {
		return ErrTOTPFeatureDisabled
	}
	if e.userProvider == nil || e.totpLimiter == nil {
		return ErrEngineNotReady
	}
	if userID == "" {
		return ErrUserNotFound
	}

	before, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	if err := e.userProvider.DisableTOTP(ctx, userID); err != nil {
		return ErrTOTPUnavailable
	}

	after, err := e.userProvider.GetUserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	if after.AccountVersion <= before.AccountVersion {
		return ErrAccountVersionNotAdvanced
	}

	tenant := tenantIDFromContext(ctx)
	if after.TenantID != "" {
		tenant = after.TenantID
	}
	if err := e.LogoutAllInTenant(ctx, tenant, userID); err != nil {
		return errors.Join(ErrSessionInvalidationFailed, err)
	}
	_ = e.totpLimiter.Reset(ctx, userID)

	e.emitAudit(ctx, auditEventTOTPDisabled, true, userID, tenant, "", nil, nil)
	return nil
}

func (e *Engine) verifyTOTPForUser(ctx context.Context, user UserRecord, code string) error {
	if e == nil || e.userProvider == nil || e.totp == nil || e.totpLimiter == nil {
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
	if code == "" {
		e.metricInc(MetricTOTPRequired)
		e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPRequired, nil)
		return ErrTOTPRequired
	}

	ok, counter, err := e.totp.VerifyCode(record.Secret, code, time.Now())
	if err != nil || !ok {
		e.metricInc(MetricTOTPFailure)
		recErr := e.totpLimiter.RecordFailure(ctx, user.UserID)
		if recErr != nil && errors.Is(recErr, errTOTPRateLimited) {
			e.emitAudit(ctx, auditEventTOTPFailure, false, user.UserID, user.TenantID, "", ErrTOTPRateLimited, nil)
			return ErrTOTPRateLimited
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

	_ = e.totpLimiter.Reset(ctx, user.UserID)
	e.metricInc(MetricTOTPSuccess)
	e.emitAudit(ctx, auditEventTOTPSuccess, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}
