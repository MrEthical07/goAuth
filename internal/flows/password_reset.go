package flows

import (
	"context"
	"errors"
	"strings"
	"time"
)

type PasswordResetUser struct {
	UserID   string
	TenantID string
	Status   uint8
	// Identifier is the address the account had when it was resolved. It is
	// only read by RecheckIdentifier.
	Identifier string
}

type PasswordResetStoreRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   int
}

type PasswordResetMetrics struct {
	PasswordResetRequest          int
	PasswordResetConfirmSuccess   int
	PasswordResetConfirmFailure   int
	PasswordResetAttemptsExceeded int
}

type PasswordResetEvents struct {
	PasswordResetRequest string
	PasswordResetConfirm string
	PasswordResetReplay  string
}

type PasswordResetErrors struct {
	EngineNotReady            error
	PasswordResetDisabled     error
	PasswordResetInvalid      error
	PasswordResetRateLimited  error
	PasswordResetUnavailable  error
	PasswordResetAttempts     error
	PasswordPolicy            error
	UserNotFound              error
	SessionInvalidationFailed error
	TOTPInvalid               error
}

type PasswordResetDeps struct {
	Enabled     bool
	Strategy    int
	OTPDigits   int
	ResetTTL    time.Duration
	MaxAttempts int
	RequireMFA  bool

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
	IsStoreNotFound         func(error) bool

	// EnforceTenantMatch requires a resolved user's TenantID to equal the
	// request's tenant. Set only when multi-tenancy is enabled.
	EnforceTenantMatch bool

	Warn func(string, ...any)

	// GetUserByIdentifier and GetUserByID take a context so the engine can
	// scope the lookup to the request's tenant when multi-tenancy is on.
	GetUserByIdentifier func(context.Context, string) (PasswordResetUser, error)
	GetUserByID         func(context.Context, string) (PasswordResetUser, error)
	HashPassword        func(string) (string, error)
	UpdatePasswordHash  func(string, string) error
	// UpdatePasswordHashInTenant, when set, replaces UpdatePasswordHash. The
	// engine sets it only when multi-tenancy is enabled and the provider can
	// scope the write to a tenant.
	UpdatePasswordHashInTenant func(context.Context, string, string, string) error
	LogoutAllInTenant          func(context.Context, string, string) error

	// SupersedeResets makes resetID the user's only valid reset record, so a
	// new request cancels the codes of earlier ones; it runs before the record
	// is saved. InvalidateResets does the same for every record when a reset
	// completed. Both are optional, and a failure of the second is audited, not
	// returned: the password has already changed.
	SupersedeResets func(ctx context.Context, tenantID, userID, resetID string, ttl time.Duration) error
	// RecheckIdentifier, when set, runs after SupersedeResets and reports
	// whether the account still has the identifier it was resolved with. An
	// email change that committed while the request was in flight would
	// otherwise leave a valid code for the old address. Nil skips the check.
	RecheckIdentifier func(ctx context.Context, tenantID, userID, identifier string) (bool, error)
	InvalidateResets  func(ctx context.Context, tenantID, userID string, ttl time.Duration) error

	SaveResetRecord    func(context.Context, string, string, PasswordResetStoreRecord, time.Duration) error
	GetResetRecord     func(context.Context, string, string) (PasswordResetStoreRecord, error)
	ConsumeResetRecord func(context.Context, string, string, [32]byte, int, int) (PasswordResetStoreRecord, error)

	GenerateChallenge func(int, int) (string, string, [32]byte, error)
	ParseChallenge    func(int, string, int) (string, [32]byte, error)
	// EnumerationFloor draws the minimum time a request that answers with a
	// challenge takes, whether the identifier is registered or not; nil means
	// no floor. SleepFor waits for a duration (nil: a context-aware sleep).
	EnumerationFloor func() time.Duration
	SleepFor         func(context.Context, time.Duration) error
	// FloorNow is the time source the floor measures its elapsed time with.
	// The floor is a real-time defence against timing measurement, so an
	// engine with an injected test clock passes the wall clock here; nil falls
	// back to Now.
	FloorNow func() time.Time

	VerifyTOTPForUser        func(context.Context, PasswordResetUser, string) error
	VerifyBackupCodeInTenant func(context.Context, string, string, string) error

	MetricInc     func(int)
	EmitAudit     func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit func(context.Context, string, string, func() map[string]string)

	Metrics PasswordResetMetrics
	Events  PasswordResetEvents
	Errors  PasswordResetErrors
}

func RunRequestPasswordReset(ctx context.Context, identifier string, deps PasswordResetDeps) (string, error) {
	normalizePasswordResetDeps(&deps)
	floor := startEnumerationFloor(floorClock(deps.FloorNow, deps.Now), deps.EnumerationFloor, deps.SleepFor)

	if !deps.Enabled {
		deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordResetDisabled, nil)
		return "", deps.Errors.PasswordResetDisabled
	}
	if deps.HashPassword == nil || deps.SaveResetRecord == nil || deps.CheckRequestLimiter == nil || deps.GetUserByIdentifier == nil || deps.GenerateChallenge == nil {
		return "", deps.Errors.EngineNotReady
	}
	if identifier == "" {
		deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordResetInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return "", deps.Errors.PasswordResetInvalid
	}

	if identifierTooLong(identifier) {
		deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordResetInvalid, func() map[string]string {
			return map[string]string{
				"identifier": auditIdentifier(identifier),
				"reason":     "identifier_too_long",
			}
		})
		return "", deps.Errors.PasswordResetInvalid
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if err := deps.CheckRequestLimiter(ctx, tenantID, identifier); err != nil {
		mapped := deps.MapLimiterError(err)
		if errors.Is(mapped, deps.Errors.PasswordResetRateLimited) {
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
			deps.EmitRateLimit(ctx, "password_reset_request", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		} else {
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
				}
			})
		}
		return "", mapped
	}

	user, err := deps.GetUserByIdentifier(ctx, identifier)
	if err == nil && deps.EnforceTenantMatch && tenantID != "" && user.TenantID != tenantID {
		// Defence in depth: the lookup is already tenant-scoped, so this
		// only fires if a provider ignores the tenant argument. Fall into
		// the enumeration-safe branch below rather than rejecting loudly —
		// an account that exists only in another tenant must look exactly
		// like one that does not exist.
		deps.Warn("goAuth: tenant-scoped lookup returned a user from another tenant; check the TenantAwareUserProvider implementation")
		user = PasswordResetUser{}
		err = errTenantMismatch
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		_, challenge, _, genErr := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits)
		if genErr != nil {
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, "", tenantID, "", deps.Errors.PasswordResetUnavailable, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "fake_generation_failed",
				}
			})
			return "", deps.Errors.PasswordResetUnavailable
		}
		deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, true, "", tenantID, "", nil, func() map[string]string {
			return map[string]string{
				"identifier":       identifier,
				"enumeration_safe": "true",
			}
		})
		deps.MetricInc(deps.Metrics.PasswordResetRequest)
		return floor.finish(ctx, challenge)
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
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, user.UserID, tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"scope":      "account",
				}
			})
			if errors.Is(mapped, deps.Errors.PasswordResetRateLimited) {
				deps.EmitRateLimit(ctx, "password_reset_request", tenantID, func() map[string]string {
					return map[string]string{
						"identifier": identifier,
						"scope":      "account",
					}
				})
			}
			return "", mapped
		}
	}

	// When multi-tenancy is enabled the record is always stored under the
	// tenant the request was made in. Deriving it from the resolved user
	// instead would let a request made in one tenant write a redeemable
	// record into another tenant's keyspace.
	//
	// With multi-tenancy disabled the legacy behaviour is preserved: the
	// user's own tenant wins.
	effectiveTenant := tenantID
	if !deps.EnforceTenantMatch && user.TenantID != "" {
		effectiveTenant = user.TenantID
	}

	resetID, challenge, secretHash, err := deps.GenerateChallenge(deps.Strategy, deps.OTPDigits)
	if err != nil {
		return "", deps.Errors.PasswordResetUnavailable
	}

	expiresAt := deps.Now().Add(deps.ResetTTL).Unix()
	record := PasswordResetStoreRecord{
		UserID:     user.UserID,
		SecretHash: secretHash,
		ExpiresAt:  expiresAt,
		Attempts:   0,
		Strategy:   deps.Strategy,
	}

	if err := deps.SaveResetRecord(ctx, effectiveTenant, resetID, record, deps.ResetTTL); err != nil {
		mapped := deps.MapStoreError(err)
		deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, user.UserID, effectiveTenant, "", mapped, func() map[string]string {
			return map[string]string{
				"identifier": identifier,
			}
		})
		return "", mapped
	}

	// The record exists; only now does it cancel the earlier ones, so a request
	// that fails to store its record does not cost the user the code they hold.
	// Until this returns the new code has not been mailed either.
	if deps.SupersedeResets != nil {
		if err := deps.SupersedeResets(ctx, effectiveTenant, user.UserID, resetID, deps.ResetTTL); err != nil {
			mapped := deps.MapStoreError(err)
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, user.UserID, effectiveTenant, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "supersede_failed",
				}
			})
			return "", mapped
		}
	}

	// An email change that committed after the account was read tombstones the
	// pointer before this request's pointer write lands on top of it, which
	// would leave a valid code for the old address. The change commits before it
	// tombstones, so if the address is still the one we resolved, any later
	// change's tombstone lands after our pointer and supersedes it.
	if deps.RecheckIdentifier != nil {
		same, recheckErr := deps.RecheckIdentifier(ctx, effectiveTenant, user.UserID, user.Identifier)
		if recheckErr != nil || !same {
			deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, false, user.UserID, effectiveTenant, "", deps.Errors.PasswordResetUnavailable, func() map[string]string {
				return map[string]string{
					"identifier": identifier,
					"reason":     "identifier_changed",
				}
			})
			return "", deps.Errors.PasswordResetUnavailable
		}
	}

	deps.EmitAudit(ctx, deps.Events.PasswordResetRequest, true, user.UserID, effectiveTenant, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": identifier,
		}
	})
	deps.MetricInc(deps.Metrics.PasswordResetRequest)
	return floor.finish(ctx, challenge)
}

func RunConfirmPasswordResetWithMFA(ctx context.Context, challenge, newPassword, mfaType, mfaCode string, deps PasswordResetDeps) error {
	normalizePasswordResetDeps(&deps)

	if !deps.Enabled {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordResetDisabled, nil)
		return deps.Errors.PasswordResetDisabled
	}
	if deps.HashPassword == nil ||
		deps.ConsumeResetRecord == nil ||
		deps.CheckConfirmLimiter == nil ||
		deps.ParseChallenge == nil ||
		deps.GetUserByID == nil ||
		deps.UpdatePasswordHash == nil ||
		deps.LogoutAllInTenant == nil ||
		deps.AccountStatusError == nil {
		return deps.Errors.EngineNotReady
	}
	if challenge == "" || newPassword == "" {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "invalid_input",
			}
		})
		return deps.Errors.PasswordPolicy
	}

	resetID, providedHash, err := deps.ParseChallenge(deps.Strategy, challenge, deps.OTPDigits)
	if err != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.PasswordResetInvalid, func() map[string]string {
			return map[string]string{
				"reason": "parse_failed",
			}
		})
		return deps.Errors.PasswordResetInvalid
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if err := deps.CheckConfirmLimiter(ctx, tenantID, resetID); err != nil {
		mapped := deps.MapLimiterError(err)
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		if errors.Is(mapped, deps.Errors.PasswordResetRateLimited) {
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
			deps.EmitRateLimit(ctx, "password_reset_confirm", tenantID, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		} else {
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		}
		return mapped
	}

	if deps.RequireMFA {
		peek, err := deps.GetResetRecord(ctx, tenantID, resetID)
		if err != nil {
			mapped := deps.MapStoreError(err)
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
			return mapped
		}
		user, err := deps.GetUserByID(ctx, peek.UserID)
		if err != nil {
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, peek.UserID, tenantID, "", deps.Errors.UserNotFound, nil)
			return deps.Errors.UserNotFound
		}

		var mfaErr error
		switch strings.ToLower(strings.TrimSpace(mfaType)) {
		case "", "totp":
			mfaErr = deps.VerifyTOTPForUser(ctx, user, mfaCode)
		case "backup":
			mfaErr = deps.VerifyBackupCodeInTenant(ctx, user.TenantID, user.UserID, mfaCode)
		default:
			mfaErr = deps.Errors.TOTPInvalid
		}
		if mfaErr != nil {
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, peek.UserID, user.TenantID, "", mfaErr, func() map[string]string {
				return map[string]string{
					"reason": "totp_required_for_reset",
				}
			})
			return mfaErr
		}
	}

	record, err := deps.ConsumeResetRecord(ctx, tenantID, resetID, providedHash, deps.Strategy, deps.MaxAttempts)
	if err != nil {
		mapped := deps.MapStoreError(err)
		if deps.IsStoreNotFound(err) {
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetReplay, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		} else if errors.Is(mapped, deps.Errors.PasswordResetAttempts) {
			deps.MetricInc(deps.Metrics.PasswordResetAttemptsExceeded)
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
					"reason":   "attempts_exceeded",
				}
			})
		} else {
			deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"reset_id": resetID,
				}
			})
		}
		return mapped
	}

	user, err := deps.GetUserByID(ctx, record.UserID)
	if err != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, tenantID, "", deps.Errors.UserNotFound, nil)
		return deps.Errors.UserNotFound
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, user.TenantID, "", statusErr, func() map[string]string {
			return map[string]string{
				"reason": "account_status",
			}
		})
		return statusErr
	}

	newHash, err := deps.HashPassword(newPassword)
	if err != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, user.TenantID, "", deps.Errors.PasswordPolicy, func() map[string]string {
			return map[string]string{
				"reason": "hash_policy",
			}
		})
		return deps.Errors.PasswordPolicy
	}

	var updateErr error
	if deps.UpdatePasswordHashInTenant != nil {
		updateErr = deps.UpdatePasswordHashInTenant(ctx, tenantID, record.UserID, newHash)
	} else {
		updateErr = deps.UpdatePasswordHash(record.UserID, newHash)
	}
	if err := updateErr; err != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, user.TenantID, "", err, func() map[string]string {
			return map[string]string{
				"reason": "update_hash_failed",
			}
		})
		return err
	}

	// The reset is done: every other code issued for the account before now is
	// dead, whoever holds it.
	if deps.InvalidateResets != nil {
		if err := deps.InvalidateResets(ctx, tenantID, record.UserID, deps.ResetTTL); err != nil {
			deps.Warn("goAuth: outstanding password reset codes could not be invalidated")
			deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, tenantID, "", deps.Errors.PasswordResetUnavailable, func() map[string]string {
				return map[string]string{
					"reason": "reset_invalidation_failed",
				}
			})
		}
	}

	invalidateTenant := tenantID
	if user.TenantID != "" {
		invalidateTenant = user.TenantID
	}
	if err := deps.LogoutAllInTenant(ctx, invalidateTenant, record.UserID); err != nil {
		deps.MetricInc(deps.Metrics.PasswordResetConfirmFailure)
		deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, false, record.UserID, invalidateTenant, "", deps.Errors.SessionInvalidationFailed, func() map[string]string {
			return map[string]string{
				"reason": "session_invalidation_failed",
			}
		})
		return errors.Join(deps.Errors.SessionInvalidationFailed, err)
	}

	deps.MetricInc(deps.Metrics.PasswordResetConfirmSuccess)
	deps.EmitAudit(ctx, deps.Events.PasswordResetConfirm, true, record.UserID, invalidateTenant, "", nil, nil)
	return nil
}

func normalizePasswordResetDeps(deps *PasswordResetDeps) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.SleepFor == nil {
		deps.SleepFor = sleepContext
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
		deps.MapLimiterError = func(error) error { return deps.Errors.PasswordResetUnavailable }
	}
	if deps.MapStoreError == nil {
		deps.MapStoreError = func(error) error { return deps.Errors.PasswordResetUnavailable }
	}
	if deps.IsStoreNotFound == nil {
		deps.IsStoreNotFound = func(error) bool { return false }
	}
	if deps.VerifyTOTPForUser == nil {
		deps.VerifyTOTPForUser = func(context.Context, PasswordResetUser, string) error { return deps.Errors.EngineNotReady }
	}
	if deps.VerifyBackupCodeInTenant == nil {
		deps.VerifyBackupCodeInTenant = func(context.Context, string, string, string) error { return deps.Errors.EngineNotReady }
	}
}
