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
	// PendingStatus is the status an account has until its address is verified;
	// it is the only one verification moves to ActiveStatus.
	PendingStatus uint8

	TenantIDFromContext func(context.Context) string
	AccountStatusError  func(uint8) error
	Now                 func() time.Time

	// CheckRequestUserLimiter counts a request against the resolved account,
	// whatever spelling of its identifier was used. Optional.
	CheckRequestUserLimiter func(ctx context.Context, tenantID, userID string) error
	CheckRequestLimiter     func(context.Context, string, string) error
	CheckConfirmLimiter     func(context.Context, string, string) error
	MapLimiterError         func(error) error
	MapStoreError           func(error) error

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

	// UpdateStatusIf and InvalidateSessions, when both are set, replace
	// UpdateStatusAndInvalidate for the pending-to-active transition: the
	// status is written only if it is still the expected one, and the user's
	// sessions are ended after a write that applied.
	UpdateStatusIf     func(ctx context.Context, tenantID, userID string, expected, next uint8) (bool, error)
	InvalidateSessions func(ctx context.Context, tenantID, userID string) error

	SaveVerificationRecord    func(context.Context, string, string, EmailVerificationStoreRecord, time.Duration) error
	ConsumeVerificationRecord func(context.Context, string, string, [32]byte, int, int) (EmailVerificationStoreRecord, error)

	GenerateChallenge  func(int, int, string) (string, string, [32]byte, error)
	ParseChallenge     func(int, string, int) (string, string, [32]byte, error)
	ParseChallengeCode func(int, string, string, int) ([32]byte, error)
	// EnumerationFloor draws the minimum time a request that answers with a
	// challenge takes, whether the identifier is registered, unverified,
	// verified or unknown; nil means no floor. SleepFor waits for a duration
	// (nil: a context-aware sleep).
	EnumerationFloor func() time.Duration
	SleepFor         func(context.Context, time.Duration) error

	MetricInc     func(int)
	EmitAudit     func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit func(context.Context, string, string, func() map[string]string)

	Metrics EmailVerificationMetrics
	Events  EmailVerificationEvents
	Errors  EmailVerificationErrors
}

func RunRequestEmailVerification(ctx context.Context, identifier string, deps EmailVerificationDeps) (string, error) {
	normalizeEmailVerificationDeps(&deps)
	floor := startEnumerationFloor(deps.Now, deps.EnumerationFloor, deps.SleepFor)

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

	if identifierTooLong(identifier) {
		deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.EmailVerificationInvalid, func() map[string]string {
			return map[string]string{
				"identifier": auditIdentifier(identifier),
				"reason":     "identifier_too_long",
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
		return floor.finish(ctx, fakeChallenge)
	}

	// The account's own budget (shared by every spelling of its identifier).
	// A request over it is answered with the rate-limit error rather than a
	// fake challenge, because the error is what stops the host from sending
	// mail; with a provider that matches identifiers case-insensitively that
	// lets a caller trying spellings tell that the account exists. Exact-match
	// providers never see it, and docs/rate_limiting.md says so.
	if deps.CheckRequestUserLimiter != nil {
		if err := deps.CheckRequestUserLimiter(ctx, tenantID, user.UserID); err != nil {
			mapped := deps.MapLimiterError(err)
			deps.MetricInc(deps.Metrics.EmailVerificationFailure)
			deps.EmitAudit(ctx, deps.Events.EmailVerificationRequest, false, user.UserID, tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"scope":      "account",
				}
			})
			if errors.Is(mapped, deps.Errors.EmailVerificationRateLimited) {
				deps.EmitRateLimit(ctx, "email_verification_request", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": identifier,
						"scope":      "account",
					}
				})
			}
			return "", mapped
		}
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
		return floor.finish(ctx, fakeChallenge)
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
		return floor.finish(ctx, fakeChallenge)
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
	return floor.finish(ctx, challenge)
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

	outcome, err := activatePendingAccount(ctx, tenantID, user, deps)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "status_transition_failed",
			}
		})
		return err
	}

	deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
	var meta func() map[string]string
	if outcome == activationAlreadyActive {
		meta = func() map[string]string { return map[string]string{"noop": "already_active"} }
	}
	deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, meta)
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

	outcome, err := activatePendingAccount(ctx, tenantID, user, deps)
	if err != nil {
		deps.MetricInc(deps.Metrics.EmailVerificationFailure)
		deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, false, user.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "status_transition_failed",
			}
		})
		return err
	}

	deps.MetricInc(deps.Metrics.EmailVerificationSuccess)
	var meta func() map[string]string
	if outcome == activationAlreadyActive {
		meta = func() map[string]string { return map[string]string{"noop": "already_active"} }
	}
	deps.EmitAudit(ctx, deps.Events.EmailVerificationConfirm, true, user.UserID, user.TenantID, "", nil, meta)
	return nil
}

type activationOutcome int

const (
	activationDone activationOutcome = iota
	// activationAlreadyActive: the account was found Active when it was about
	// to be activated; nothing was written.
	activationAlreadyActive
)

// activatePendingAccount moves the account from pending verification to
// active, and only from pending: a disable, lock or delete that landed after
// the account was read must not be undone by the verification that was in
// flight.
//
// With a provider that implements compare-and-set the write is exact. Without
// one the account is read again immediately before the write and the status is
// re-checked, which narrows the window to the gap between that read and the
// write but cannot close it.
//
// Downstream status and session work reads the tenant from the context, so it
// is handed the tenant the verification record was loaded under rather than
// the caller's, which may be absent or different for a tenant-carrying
// challenge.
func activatePendingAccount(ctx context.Context, tenantID string, user EmailVerificationUser, deps EmailVerificationDeps) (activationOutcome, error) {
	scoped := deps.WithTenant(ctx, tenantID)

	if deps.UpdateStatusIf != nil && deps.InvalidateSessions != nil {
		applied, err := deps.UpdateStatusIf(scoped, tenantID, user.UserID, deps.PendingStatus, deps.ActiveStatus)
		if err != nil {
			return activationDone, err
		}
		if applied {
			return activationDone, deps.InvalidateSessions(scoped, tenantID, user.UserID)
		}
		// Refused: the status is no longer pending. Say why.
		return judgeStatusBeforeActivation(ctx, tenantID, user.UserID, deps)
	}

	if outcome, err := judgeStatusBeforeActivation(ctx, tenantID, user.UserID, deps); err != nil || outcome == activationAlreadyActive {
		return outcome, err
	}
	return activationDone, deps.UpdateStatusAndInvalidate(scoped, user.UserID, deps.ActiveStatus)
}

// judgeStatusBeforeActivation reads the account and reports whether it can
// still be activated: nil with activationDone when it is pending,
// activationAlreadyActive when it is active, the status error when it is
// blocking.
func judgeStatusBeforeActivation(ctx context.Context, tenantID, userID string, deps EmailVerificationDeps) (activationOutcome, error) {
	fresh, err := deps.GetUserByIDInTenant(ctx, tenantID, userID)
	if err != nil {
		return activationDone, deps.Errors.UserNotFound
	}
	if fresh.Status == deps.ActiveStatus {
		return activationAlreadyActive, nil
	}
	if statusErr := deps.AccountStatusError(fresh.Status); statusErr != nil {
		return activationDone, statusErr
	}
	if fresh.Status != deps.PendingStatus {
		return activationDone, deps.Errors.EmailVerificationUnavailable
	}
	return activationDone, nil
}

func normalizeEmailVerificationDeps(deps *EmailVerificationDeps) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.SleepFor == nil {
		deps.SleepFor = sleepContext
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
