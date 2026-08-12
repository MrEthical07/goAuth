package flows

import (
	"context"
	"errors"
	"time"
)

type EmailVerificationUser struct {
	UserID   string
	TenantID string
	Status   uint8
}

type EmailVerificationStoreRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   int
}

type EmailVerificationMetrics struct {
	EmailVerificationRequest          int
	EmailVerificationSuccess          int
	EmailVerificationFailure          int
	EmailVerificationAttemptsExceeded int
}

type EmailVerificationEvents struct {
	EmailVerificationRequest string
	EmailVerificationConfirm string
}

type EmailVerificationErrors struct {
	EngineNotReady               error
	EmailVerificationDisabled    error
	EmailVerificationInvalid     error
	EmailVerificationRateLimited error
	EmailVerificationUnavailable error
	EmailVerificationAttempts    error
	UserNotFound                 error
}

type EmailVerificationDeps struct {
	Enabled         bool
	Strategy        int
	OTPDigits       int
	VerificationTTL time.Duration
	MaxAttempts     int
	ActiveStatus    uint8

	TenantIDFromContext func(context.Context) string
	AccountStatusError  func(uint8) error
	Now                 func() time.Time

	CheckRequestLimiter func(context.Context, string, string) error
	CheckConfirmLimiter func(context.Context, string, string) error
	MapLimiterError     func(error) error
	MapStoreError       func(error) error

	// EnforceTenantMatch requires a resolved user's TenantID to equal the
	// request's tenant. Set only when multi-tenancy is enabled.
	EnforceTenantMatch bool

	Warn func(string, ...any)

	// GetUserByIdentifier takes a context so the engine can scope the
	// lookup to the request's tenant when multi-tenancy is on.
	GetUserByIdentifier func(context.Context, string) (EmailVerificationUser, error)

	// GetUserByIDInTenant scopes the lookup to an explicitly supplied
	// tenant rather than the request context's. Confirm paths pass the
	// tenant the verification record was loaded under, which for
	// token/UUID challenges comes from the challenge itself and is
	// authoritative — the context tenant may be absent or different.
	GetUserByIDInTenant func(ctx context.Context, tenantID, userID string) (EmailVerificationUser, error)

	// WithTenant returns ctx carrying tenantID as the request tenant. The
	// confirm paths use it to propagate the challenge's authoritative
	// tenant into downstream operations that read the tenant from context.
	WithTenant func(ctx context.Context, tenantID string) context.Context

	UpdateStatusAndInvalidate func(context.Context, string, uint8) error

	SaveVerificationRecord    func(context.Context, string, string, EmailVerificationStoreRecord, time.Duration) error
	ConsumeVerificationRecord func(context.Context, string, string, [32]byte, int, int) (EmailVerificationStoreRecord, error)

	GenerateChallenge     func(int, int, string) (string, string, [32]byte, error)
	ParseChallenge        func(int, string, int) (string, string, [32]byte, error)
	ParseChallengeCode    func(int, string, string, int) ([32]byte, error)
	SleepEnumerationDelay func(context.Context) error

	MetricInc     func(int)
	EmitAudit     func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit func(context.Context, string, string, func() map[string]string)

	Metrics EmailVerificationMetrics
	Events  EmailVerificationEvents
	Errors  EmailVerificationErrors
}

func RunRequestEmailVerification(ctx context.Context, identifier string, deps EmailVerificationDeps) (string, error) {
	normalizeEmailVerificationDeps(&deps)

	if !deps.Enabled {
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationDisabled, nil)
		return "", deps.Errors.EmailVerificationDisabled
	}
	if deps.SaveVerificationRecord == nil || deps.CheckRequestLimiter == nil || deps.GetUserByIdentifier == nil || deps.GenerateChallenge == nil {
		return "", deps.Errors.EngineNotReady
	}
	if identifier == "" {
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return "", deps.Errors.EmailVerificationInvalid
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if err := deps.CheckRequestLimiter(ctx, tenantID, identifier); err != nil {
		mapped := deps.MapLimiterError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		if errors.Is(mapped, deps.Errors.EmailVerificationRateLimited) {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
			deps.EmitRateLimit(ctx, "email_verification_request", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		} else {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		}
		return "", mapped
	}

	user, err := deps.GetUserByIdentifier(ctx, identifier)
	if err == nil && deps.EnforceTenantMatch && tenantID != "" && user.TenantID != tenantID {
		// Defence in depth against a provider that ignores the tenant
		// argument. Fall into the enumeration-safe branch below so an
		// account that exists only in another tenant is indistinguishable
		// from one that does not exist.
		deps.Warn("goAuth: tenant-scoped lookup returned a user from another tenant; check the TenantAwareUserProvider implementation")
		user = EmailVerificationUser{}
		err = errTenantMismatch
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		if err := deps.SleepEnumerationDelay(ctx); err != nil {
			return "", err
		}
		_, fakeChallenge, _, genErr := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits, tenantID)
		if genErr != nil {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", tenantID, "", deps.Errors.EmailVerificationUnavailable, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "fake_generation_failed",
				}
			})
			return "", deps.Errors.EmailVerificationUnavailable
		}
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, true, "", tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier":       identifier,
				"enumeration_safe": "true",
			}
		})
		deps.MetricInc(deps.Metrics.EmailVerificationRequest)
		return fakeChallenge, nil
	}

	if user.Status == deps.ActiveStatus {
		_, fakeChallenge, _, genErr := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits, tenantID)
		if genErr != nil {
			return "", deps.Errors.EmailVerificationUnavailable
		}
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, true, user.UserID, tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
				"noop":       "already_active",
			}
		})
		deps.MetricInc(deps.Metrics.EmailVerificationRequest)
		return fakeChallenge, nil
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		_, fakeChallenge, _, genErr := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits, tenantID)
		if genErr != nil {
			return "", deps.Errors.EmailVerificationUnavailable
		}
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, true, user.UserID, tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
				"noop":       "non_verifiable_status",
			}
		})
		deps.MetricInc(deps.Metrics.EmailVerificationRequest)
		return fakeChallenge, nil
	}

	// When multi-tenancy is enabled the record is always stored under the
	// tenant the request was made in. Deriving it from the resolved user
	// instead would let a request made in one tenant write a redeemable
	// record into another tenant's keyspace.
	//
	// With multi-tenancy disabled the legacy behaviour is preserved: the
	// user's own tenant wins. Single-tenant deployments rely on that to
	// bind records to a user-carried tenant value the context does not set.
	effectiveTenant := tenantID
	if !deps.EnforceTenantMatch && user.TenantID != "" {
		effectiveTenant = user.TenantID
	}

	verificationID, challenge, secretHash, err := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits, effectiveTenant)
	if err != nil {
		return "", deps.Errors.EmailVerificationUnavailable
	}

	record := EmailVerificationStoreRecord{
		UserID:     user.UserID,
		SecretHash: secretHash,
		ExpiresAt:  deps.Now().Add(deps.VerificationTTL).Unix(),
		Attempts:   0,
		Strategy:   deps.Strategy,
	}

	if err := deps.SaveVerificationRecord(ctx, effectiveTenant, verificationID, record, deps.VerificationTTL); err != nil {
		mapped := deps.MapStoreError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, user.UserID, effectiveTenant, "", mapped, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
			}
		})
		return "", mapped
	}

	deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, true, user.UserID, effectiveTenant, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": identifier,
		}
	})
	deps.MetricInc(deps.Metrics.EmailVerificationRequest)
	return challenge, nil
}

func RunConfirmEmailVerification(ctx context.Context, challenge string, deps EmailVerificationDeps) error {
	normalizeEmailVerificationDeps(&deps)

	if !deps.Enabled {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationDisabled, nil)
		return deps.Errors.EmailVerificationDisabled
	}
	if deps.ConsumeVerificationRecord == nil || deps.CheckConfirmLimiter == nil || deps.GetUserByIDInTenant == nil || deps.UpdateStatusAndInvalidate == nil || deps.ParseChallenge == nil {
		return deps.Errors.EngineNotReady
	}
	if challenge == "" {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_challenge",
			}
		})
		return deps.Errors.EmailVerificationInvalid
	}

	parsedTenant, verificationID, providedHash, err := deps.ParseChallenge(deps.Strategy, challenge, deps.OTPDigits)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "parse_failed",
			}
		})
		return deps.Errors.EmailVerificationInvalid
	}

	tenantID := parsedTenant
	if tenantID == "" {
		tenantID = deps.TenantIDFromContext(ctx)
	}
	if err := deps.CheckConfirmLimiter(ctx, tenantID, verificationID); err != nil {
		mapped := deps.MapLimiterError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		if errors.Is(mapped, deps.Errors.EmailVerificationRateLimited) {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
			deps.EmitRateLimit(ctx, "email_verification_confirm", tenantID, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		} else {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		}
		return mapped
	}

	record, err := deps.ConsumeVerificationRecord(ctx, tenantID, verificationID, providedHash, deps.Strategy, deps.MaxAttempts)
	if err != nil {
		mapped := deps.MapStoreError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		if errors.Is(mapped, deps.Errors.EmailVerificationAttempts) {
			deps.MetricInc(deps.Metrics.EmailVerificationAttemptsExceeded)
		}
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
			return map[string]string{
				"verification_id": verificationID,
			}
		})
		return mapped
	}

	user, err := deps.GetUserByIDInTenant(ctx, tenantID, record.UserID)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, record.UserID, tenantID, "", deps.Errors.UserNotFound, nil)
		return deps.Errors.UserNotFound
	}
	if user.Status == deps.ActiveStatus {
		deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, func() map[string]string {
			return map[string]string{
				"noop": "already_active",
			}
		})
		return nil
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	// Downstream status/session work reads the tenant from context, so hand
	// it the tenant this record was actually loaded under rather than the
	// caller's, which may be absent or different for a tenant-carrying
	// challenge.
	if err := deps.UpdateStatusAndInvalidate(deps.WithTenant(ctx, tenantID), record.UserID, deps.ActiveStatus); err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "status_transition_failed",
			}
		})
		return err
	}

	deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
	deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

func RunConfirmEmailVerificationCode(ctx context.Context, verificationID, code string, deps EmailVerificationDeps) error {
	normalizeEmailVerificationDeps(&deps)

	if !deps.Enabled {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationDisabled, nil)
		return deps.Errors.EmailVerificationDisabled
	}
	if deps.ConsumeVerificationRecord == nil || deps.CheckConfirmLimiter == nil || deps.GetUserByIDInTenant == nil || deps.UpdateStatusAndInvalidate == nil || deps.ParseChallengeCode == nil {
		return deps.Errors.EngineNotReady
	}
	if verificationID == "" || code == "" {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_verification_id_or_code",
			}
		})
		return deps.Errors.EmailVerificationInvalid
	}

	providedHash, err := deps.ParseChallengeCode(deps.Strategy, verificationID, code, deps.OTPDigits)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "parse_code_failed",
			}
		})
		return deps.Errors.EmailVerificationInvalid
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if err := deps.CheckConfirmLimiter(ctx, tenantID, verificationID); err != nil {
		mapped := deps.MapLimiterError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		if errors.Is(mapped, deps.Errors.EmailVerificationRateLimited) {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
			deps.EmitRateLimit(ctx, "email_verification_confirm", tenantID, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		} else {
			deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"verification_id": verificationID,
				}
			})
		}
		return mapped
	}

	record, err := deps.ConsumeVerificationRecord(ctx, tenantID, verificationID, providedHash, deps.Strategy, deps.MaxAttempts)
	if err != nil {
		mapped := deps.MapStoreError(err)
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		if errors.Is(mapped, deps.Errors.EmailVerificationAttempts) {
			deps.MetricInc(deps.Metrics.EmailVerificationAttemptsExceeded)
		}
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, "", tenantID, "", mapped, func() map[string]string {
			return map[string]string{
				"verification_id": verificationID,
			}
		})
		return mapped
	}

	user, err := deps.GetUserByIDInTenant(ctx, tenantID, record.UserID)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, record.UserID, tenantID, "", deps.Errors.UserNotFound, nil)
		return deps.Errors.UserNotFound
	}
	if user.Status == deps.ActiveStatus {
		deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, func() map[string]string {
			return map[string]string{
				"noop": "already_active",
			}
		})
		return nil
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	// Downstream status/session work reads the tenant from context, so hand
	// it the tenant this record was actually loaded under rather than the
	// caller's, which may be absent or different for a tenant-carrying
	// challenge.
	if err := deps.UpdateStatusAndInvalidate(deps.WithTenant(ctx, tenantID), record.UserID, deps.ActiveStatus); err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "status_transition_failed",
			}
		})
		return err
	}

	deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
	deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, nil)
	return nil
}

func normalizeEmailVerificationDeps(deps *EmailVerificationDeps) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.SleepEnumerationDelay == nil {
		deps.SleepEnumerationDelay = func(context.Context) error { return nil }
	}
	if deps.WithTenant == nil {
		deps.WithTenant = func(ctx context.Context, _ string) context.Context { return ctx }
	}
	if deps.Warn == nil {
		deps.Warn = func(string, ...any) {}
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.EmitRateLimit == nil {
		deps.EmitRateLimit = func(context.Context, string, string, func() map[string]string) {}
	}
	if deps.MapLimiterError == nil {
		deps.MapLimiterError = func(error) error { return deps.Errors.EmailVerificationUnavailable }
	}
	if deps.MapStoreError == nil {
		deps.MapStoreError = func(error) error { return deps.Errors.EmailVerificationUnavailable }
	}
}
