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
	Enabled                  bool
	Strategy                 int
	OTPDigits                int
	VerificationTTL          time.Duration
	MaxAttempts              int
	ActiveStatus             uint8

	TenantIDFromContext      func(context.Context) string
	ClientIPFromContext      func(context.Context) string
	AccountStatusError       func(uint8) error
	Now                      func() time.Time

	CheckRequestLimiter      func(context.Context, string, string, string) error
	CheckConfirmLimiter      func(context.Context, string, string, string) error
	MapLimiterError          func(error) error
	MapStoreError            func(error) error

	GetUserByIdentifier      func(string) (EmailVerificationUser, error)
	GetUserByID              func(string) (EmailVerificationUser, error)
	UpdateStatusAndInvalidate func(context.Context, string, uint8) error

	SaveVerificationRecord   func(context.Context, string, string, EmailVerificationStoreRecord, time.Duration) error
	ConsumeVerificationRecord func(context.Context, string, string, [32]byte, int, int) (EmailVerificationStoreRecord, error)

	GenerateChallenge        func(int, int, string) (string, string, [32]byte, error)
	ParseChallenge           func(int, string, int) (string, string, [32]byte, error)
	ParseChallengeCode       func(int, string, string, int) ([32]byte, error)
	SleepEnumerationDelay    func(context.Context) error

	MetricInc                func(int)
	EmitAudit                func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit            func(context.Context, string, string, func() map[string]string)

	Metrics                  EmailVerificationMetrics
	Events                   EmailVerificationEvents
	Errors                   EmailVerificationErrors
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
	if err := deps.CheckRequestLimiter(ctx, tenantID, identifier, deps.ClientIPFromContext(ctx)); err != nil {
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

	user, err := deps.GetUserByIdentifier(identifier)
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

	effectiveTenant := tenantID
	if user.TenantID != "" {
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
	if deps.ConsumeVerificationRecord == nil || deps.CheckConfirmLimiter == nil || deps.GetUserByID == nil || deps.UpdateStatusAndInvalidate == nil || deps.ParseChallenge == nil {
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
	if err := deps.CheckConfirmLimiter(ctx, tenantID, verificationID, deps.ClientIPFromContext(ctx)); err != nil {
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

	user, err := deps.GetUserByID(record.UserID)
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

	if err := deps.UpdateStatusAndInvalidate(ctx, record.UserID, deps.ActiveStatus); err != nil {
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
	if deps.ConsumeVerificationRecord == nil || deps.CheckConfirmLimiter == nil || deps.GetUserByID == nil || deps.UpdateStatusAndInvalidate == nil || deps.ParseChallengeCode == nil {
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
	if err := deps.CheckConfirmLimiter(ctx, tenantID, verificationID, deps.ClientIPFromContext(ctx)); err != nil {
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

	user, err := deps.GetUserByID(record.UserID)
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

	if err := deps.UpdateStatusAndInvalidate(ctx, record.UserID, deps.ActiveStatus); err != nil {
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
	if deps.ClientIPFromContext == nil {
		deps.ClientIPFromContext = func(context.Context) string { return "" }
	}
	if deps.SleepEnumerationDelay == nil {
		deps.SleepEnumerationDelay = func(context.Context) error { return nil }
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
