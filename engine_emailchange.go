package goAuth

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/redis/go-redis/v9"
)

const (
	auditEventEmailChangeRequested = "email_change_requested"
	auditEventEmailChangeConfirmed = "email_change_confirmed"
	auditEventEmailChangeFailure   = "email_change_failure"
	// auditEventEmailChangeCancelled is emitted when a pending change was
	// dropped because the account's sessions were revoked (recovery).
	auditEventEmailChangeCancelled = "email_change_cancelled"

	auditErrEmailChangeDisabled    AuditErrorCode = "email_change_disabled"
	auditErrEmailChangeInvalid     AuditErrorCode = "email_change_invalid"
	auditErrEmailChangeStale       AuditErrorCode = "email_change_stale"
	auditErrEmailInUse             AuditErrorCode = "email_in_use"
	auditErrEmailChangeRateLimited AuditErrorCode = "email_change_rate_limited"
)

// Reasons carried by email_change_failure events, with the stage ("request" or
// "confirm") they happened in.
const (
	emailChangeReasonDisabled    = "disabled"
	emailChangeReasonUserMissing = "user_not_found"
	emailChangeReasonStatus      = "status"
	emailChangeReasonBadEmail    = "invalid_email"
	emailChangeReasonSameEmail   = "same_email"
	emailChangeReasonRateLimited = "rate_limited"
	emailChangeReasonInvalid     = "invalid"
	emailChangeReasonExpired     = "expired"
	emailChangeReasonAttempts    = "attempts"
	emailChangeReasonStale       = "stale"
	emailChangeReasonInUse       = "in_use"
	emailChangeReasonUnavailable = "unavailable"
	emailChangeReasonRecovery    = "recovery"

	maxEmailLength = 254
)

func (e *Engine) emailChangeEnabled() bool {
	return e != nil && e.config.EmailChange.Enabled &&
		e.emailChangeProvider != nil && e.emailChangeStore != nil && e.emailChangeLimiter != nil
}

// maskEmail keeps the first character of the local part and the domain, so an
// audit trail can tell addresses apart without storing them: "j***@example.com".
func maskEmail(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return "***"
	}
	first := []rune(addr[:at])[0]
	return string(first) + "***" + addr[at:]
}

// normalizeNewEmail trims raw and accepts it only as a bare address: no display
// name, angle brackets, whitespace or control characters, at most 254 bytes.
// It is deliberately stricter than account creation, which only requires a
// non-empty identifier: a code is about to be mailed to it.
func normalizeNewEmail(raw string) (string, bool) {
	addr := strings.TrimSpace(raw)
	if addr == "" || len(addr) > maxEmailLength {
		return "", false
	}
	for _, r := range addr {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", false
		}
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil || parsed.Address != addr {
		return "", false
	}
	return addr, true
}

func (e *Engine) emailChangeFail(ctx context.Context, tenantID, userID, stage, reason string, err error) error {
	e.emitAudit(ctx, auditEventEmailChangeFailure, false, userID, tenantID, "", err, func() map[string]string {
		return map[string]string{"stage": stage, "reason": reason}
	})
	return err
}

// emailChangeTenant is the tenant a challenge is stored under and the provider
// is called with: the request tenant when multi-tenancy is on; otherwise the
// user's own tenant when it has one, as the other challenge flows do.
func (e *Engine) emailChangeTenant(ctx context.Context, user UserRecord) string {
	if !e.tenantScopedLookup() && user.TenantID != "" {
		return user.TenantID
	}
	return tenantIDFromContext(ctx)
}

// emailChangeSessionTenant is the tenant the user's sessions live under.
func (e *Engine) emailChangeSessionTenant(ctx context.Context, challengeTenant string) string {
	if e.tenantScopedLookup() {
		return challengeTenant
	}
	return tenantIDFromContext(ctx)
}

// lookupEmailChangeUser resolves the user in tenant with the record-tenant
// backstop. Only [ErrUserNotFound] means the user is gone; anything else is an
// outage.
func (e *Engine) lookupEmailChangeUser(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	if userID == "" {
		return UserRecord{}, ErrUserNotFound
	}
	user, err := e.lookupUserByIDInTenant(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return UserRecord{}, ErrUserNotFound
		}
		return UserRecord{}, WrapAuthError(ErrSystemUnavailable, err)
	}
	return user, nil
}

// reserveEmailChangeRequest claims one request slot for the user. A denial is
// [ErrEmailChangeRateLimited]; a limiter outage is decided by limiterOutage.
func (e *Engine) reserveEmailChangeRequest(ctx context.Context, tenantID, userID string) error {
	e.metricInc(MetricLimiterCheck)
	err := e.emailChangeLimiter.Reserve(ctx, tenantID, userID)
	if err == nil {
		return nil
	}
	if errors.Is(err, limiters.ErrEmailChangeRateLimited) {
		e.emitRateLimit(ctx, "email_change", tenantID, nil)
		return ErrEmailChangeRateLimited
	}
	return e.limiterOutage(ctx, "email_change", tenantID, err)
}

// RequestEmailChange starts a change of userID's email address to newEmail.
// It stores a challenge bound to this user, the current address, the new
// address and the account's current version, and returns the VerificationID and
// Code the application must deliver: send Code to the NEW address (it proves
// the user controls it) and keep VerificationID for [Engine.ConfirmEmailChange].
// One change is pending per user; a new request replaces the old challenge.
//
// userID must come from the session, never from the request. goAuth does not
// ask the user to prove themselves again: have the application require a
// step-up first (VerifyPassword, or for a password-less account a second
// factor or a fresh external sign-in; see docs/email_change.md).
//
// The account must be Active. newEmail is trimmed and must be a bare address
// that differs (case-insensitively) from the current one. Whether newEmail is
// already taken is NOT checked here, so the call cannot be used to find out
// which addresses have accounts; uniqueness is enforced at confirm. Requests
// are rate limited per user (EmailChange.RequestMaxAttempts per
// RequestCooldown).
//
//	Flow:        Request Email Change
//	Docs:        docs/email_change.md
//	Security:    uniqueness not revealed; rate-limited; the code never reaches the audit trail.
func (e *Engine) RequestEmailChange(ctx context.Context, userID, newEmail string) (*EmailChangeRequest, error) {
	req, err := e.requestEmailChange(ctx, userID, newEmail)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return req, nil
}

func (e *Engine) requestEmailChange(ctx context.Context, userID, newEmail string) (*EmailChangeRequest, error) {
	const stage = "request"
	ctxTenant := tenantIDFromContext(ctx)
	if !e.emailChangeEnabled() {
		return nil, e.emailChangeFail(ctx, ctxTenant, userID, stage, emailChangeReasonDisabled, ErrEmailChangeDisabled)
	}
	if userID == "" {
		return nil, e.emailChangeFail(ctx, ctxTenant, userID, stage, emailChangeReasonUserMissing, ErrUserNotFound)
	}

	// Reserved before any lookup so a stolen session cannot make the provider
	// or the mailer work for free.
	if err := e.reserveEmailChangeRequest(ctx, ctxTenant, userID); err != nil {
		reason := emailChangeReasonRateLimited
		if errors.Is(err, ErrSystemUnavailable) {
			reason = emailChangeReasonUnavailable
		}
		return nil, e.emailChangeFail(ctx, ctxTenant, userID, stage, reason, err)
	}

	user, err := e.lookupEmailChangeUser(ctx, ctxTenant, userID)
	if err != nil {
		reason := emailChangeReasonUserMissing
		if errors.Is(err, ErrSystemUnavailable) {
			reason = emailChangeReasonUnavailable
		}
		return nil, e.emailChangeFail(ctx, ctxTenant, userID, stage, reason, err)
	}
	tenantID := e.emailChangeTenant(ctx, user)

	if statusErr := emailChangeStatusError(user.Status); statusErr != nil {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonStatus, statusErr)
	}
	newAddr, ok := normalizeNewEmail(newEmail)
	if !ok {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonBadEmail, ErrEmailChangeInvalid)
	}
	if strings.EqualFold(newAddr, user.Identifier) {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonSameEmail, ErrEmailChangeInvalid)
	}

	cfg := e.config.EmailChange.resolved()
	rawID, challenge, secretHash, err := generateEmailVerificationChallenge(cfg.Strategy, cfg.OTPDigits, tenantID)
	if err != nil {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err))
	}
	parts := strings.SplitN(challenge, ":", 3)
	if len(parts) != 3 {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonUnavailable, ErrSystemUnavailable)
	}

	record := &stores.EmailChangeRecord{
		UserID:         user.UserID,
		OldIdentifier:  user.Identifier,
		NewIdentifier:  newAddr,
		AccountVersion: user.AccountVersion,
		SecretHash:     secretHash,
		ExpiresAt:      e.now().Add(cfg.VerificationTTL).Unix(),
		Strategy:       int(cfg.Strategy),
	}
	if err := e.emailChangeStore.Save(ctx, tenantID, rawID, record, cfg.VerificationTTL); err != nil {
		return nil, e.emailChangeFail(ctx, tenantID, userID, stage, emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err))
	}

	e.emitAudit(ctx, auditEventEmailChangeRequested, true, user.UserID, tenantID, "", nil, func() map[string]string {
		return map[string]string{
			"old_email": maskEmail(user.Identifier),
			"new_email": maskEmail(newAddr),
		}
	})
	return &EmailChangeRequest{VerificationID: tenantID + ":" + rawID, Code: parts[2]}, nil
}

// emailChangeStatusError is the error for an account that may not change its
// email: only an Active account may.
func emailChangeStatusError(status AccountStatus) error {
	if status == AccountActive {
		return nil
	}
	if status == AccountPendingVerification {
		return ErrAccountUnverified
	}
	if err := accountStatusToError(status); err != nil {
		return err
	}
	return ErrUnauthorized
}

// ConfirmEmailChange completes a change started by [Engine.RequestEmailChange]:
// code is the value the user received at the new address and verificationID the
// one the request returned. It may be called with or without a session.
//
// The code is compared in constant time and each wrong attempt is counted; the
// challenge is deleted when MaxAttempts run out, on success and on any failure
// after a correct code, so a new request is needed after those. The account is
// loaded again and must still be Active, at the version the request saw, with
// the address the request replaced ([ErrEmailChangeStale] otherwise). The
// provider then installs the new address with a compare-and-set;
// [ErrEmailInUse] means another account in the tenant holds it, which is safe
// to say because the caller has just proved they own that address.
//
// Unless Config.EmailChange.KeepOtherSessions, every session of the user is then
// revoked except opts.KeepSessionID, when that is a live session of the same
// user and tenant (otherwise everything is revoked). If the change succeeded but
// the sessions could not be revoked, both the result and
// [ErrSessionInvalidationFailed] are returned.
//
// The result carries the old address: the application SHOULD notify it. External
// identity links are not touched. Password-reset and email-verification
// challenges issued before the change stop working.
//
//	Flow:        Confirm Email Change
//	Docs:        docs/email_change.md
//	Security:    constant-time compare; attempts counted; one use; tenant carried by the id.
func (e *Engine) ConfirmEmailChange(ctx context.Context, verificationID, code string, opts ConfirmEmailChangeOptions) (*EmailChangeResult, error) {
	res, err := e.confirmEmailChange(ctx, verificationID, code, opts)
	if err != nil {
		return res, mapToAuthError(err)
	}
	return res, nil
}

func (e *Engine) confirmEmailChange(ctx context.Context, verificationID, code string, opts ConfirmEmailChangeOptions) (*EmailChangeResult, error) {
	const stage = "confirm"
	ctxTenant := tenantIDFromContext(ctx)
	if !e.emailChangeEnabled() {
		return nil, e.emailChangeFail(ctx, ctxTenant, "", stage, emailChangeReasonDisabled, ErrEmailChangeDisabled)
	}
	cfg := e.config.EmailChange.resolved()

	tenantID, rawID, ok := strings.Cut(verificationID, ":")
	if !ok || tenantID == "" || rawID == "" || code == "" {
		return nil, e.emailChangeFail(ctx, ctxTenant, "", stage, emailChangeReasonInvalid, ErrEmailChangeInvalid)
	}
	if e.tenantScopedLookup() {
		// A challenge belongs to the tenant it carries: a caller who says it is
		// in another tenant cannot use it.
		if t, explicit := tenantIDFromContextExplicit(ctx); explicit && t != tenantID {
			return nil, e.emailChangeFail(ctx, ctxTenant, "", stage, emailChangeReasonInvalid, ErrEmailChangeInvalid)
		}
	}
	providedHash, err := parseEmailVerificationChallengeCode(cfg.Strategy, rawID, code, cfg.OTPDigits)
	if err != nil {
		return nil, e.emailChangeFail(ctx, tenantID, "", stage, emailChangeReasonInvalid, ErrEmailChangeInvalid)
	}

	record, err := e.emailChangeStore.Consume(ctx, tenantID, rawID, providedHash, int(cfg.Strategy), cfg.MaxAttempts)
	if err != nil {
		reason, public := emailChangeConsumeFailure(err)
		return nil, e.emailChangeFail(ctx, tenantID, "", stage, reason, public)
	}

	user, err := e.lookupEmailChangeUser(ctx, tenantID, record.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, emailChangeReasonInvalid, ErrEmailChangeInvalid)
		}
		return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, emailChangeReasonUnavailable, err)
	}
	if statusErr := emailChangeStatusError(user.Status); statusErr != nil {
		return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, emailChangeReasonStatus, statusErr)
	}
	if user.AccountVersion != record.AccountVersion || user.Identifier != record.OldIdentifier {
		return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, emailChangeReasonStale, ErrEmailChangeStale)
	}

	// Challenges for the old address issued before this moment stop working.
	// Written before the change so a failure here aborts it: the other order
	// could leave an old reset code redeemable.
	if err := e.supersedeChallengesForEmailChange(ctx, tenantID, user.TenantID, record.UserID); err != nil {
		return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err))
	}
	if err := e.emailChangeProvider.UpdateIdentifier(ctx, tenantID, record.UserID, record.OldIdentifier, record.NewIdentifier); err != nil {
		reason, public := emailChangeProviderFailure(err)
		return nil, e.emailChangeFail(ctx, tenantID, record.UserID, stage, reason, public)
	}
	// Supersede again now that the change is committed: a code requested for the
	// old address while the provider call was running was issued after the first
	// write and would otherwise slip past it. The change is done, so a failure
	// here is logged, not returned.
	if err := e.supersedeChallengesForEmailChange(ctx, tenantID, user.TenantID, record.UserID); err != nil {
		e.warn("goAuth: email change committed but outstanding reset and verification codes could not be superseded; codes requested for the old address during the change are not refused")
	}

	result := &EmailChangeResult{UserID: record.UserID, OldEmail: record.OldIdentifier, NewEmail: record.NewIdentifier}
	var revokeErr error
	if !cfg.KeepOtherSessions {
		revokeErr = e.revokeSessionsAfterEmailChange(ctx, tenantID, user.TenantID, record.UserID, opts.KeepSessionID)
		result.SessionsRevoked = revokeErr == nil
	}
	e.emitAudit(ctx, auditEventEmailChangeConfirmed, true, record.UserID, tenantID, "", nil, func() map[string]string {
		return map[string]string{
			"old_email":        maskEmail(record.OldIdentifier),
			"new_email":        maskEmail(record.NewIdentifier),
			"sessions_revoked": boolString(result.SessionsRevoked),
		}
	})
	if revokeErr != nil {
		return result, errors.Join(ErrSessionInvalidationFailed, revokeErr)
	}
	return result, nil
}

// emailChangeConsumeFailure maps a store error to the audit reason and the
// public error.
func emailChangeConsumeFailure(err error) (string, error) {
	switch {
	case errors.Is(err, stores.ErrEmailChangeNotFound), errors.Is(err, redis.Nil):
		return emailChangeReasonInvalid, ErrEmailChangeInvalid
	case errors.Is(err, stores.ErrEmailChangeExpired):
		return emailChangeReasonExpired, ErrEmailChangeInvalid
	case errors.Is(err, stores.ErrEmailChangeSecretMismatch):
		return emailChangeReasonInvalid, ErrEmailChangeInvalid
	case errors.Is(err, stores.ErrEmailChangeAttemptsExceeded):
		return emailChangeReasonAttempts, ErrEmailChangeInvalid
	default:
		return emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err)
	}
}

// emailChangeProviderFailure maps an UpdateIdentifier error.
func emailChangeProviderFailure(err error) (string, error) {
	switch {
	case errors.Is(err, ErrProviderDuplicateIdentifier):
		return emailChangeReasonInUse, ErrEmailInUse
	case errors.Is(err, ErrEmailChangeStale):
		return emailChangeReasonStale, ErrEmailChangeStale
	case errors.Is(err, ErrUserNotFound):
		return emailChangeReasonInvalid, ErrEmailChangeInvalid
	default:
		return emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err)
	}
}

// revokeSessionsAfterEmailChange revokes every session of the user except
// keepSessionID, which counts only when it is a live session of this user.
func (e *Engine) revokeSessionsAfterEmailChange(ctx context.Context, challengeTenant, recordTenant, userID, keepSessionID string) error {
	// Sessions live under the context tenant, or under the account's own when
	// the provider's record carries a different one; every one of them is
	// revoked.
	tenants := sessionRevocationTenants(ctx, e.emailChangeSessionTenant(ctx, challengeTenant))
	if recordTenant != "" {
		known := false
		for _, t := range tenants {
			known = known || tenantIDFromToken(t) == tenantIDFromToken(recordTenant)
		}
		if !known {
			tenants = append(tenants, recordTenant)
		}
	}
	var errs []error
	for _, tenant := range tenants {
		keep := ""
		if keepSessionID != "" {
			if sess, err := e.sessionStore.Peek(ctx, tenant, keepSessionID); err == nil &&
				sess.UserID == userID && sess.ExpiresAt > e.now().Unix() {
				keep = keepSessionID
			}
		}
		if _, err := e.sessionStore.DeleteAllForUserExcept(ctx, tenant, userID, keep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// supersedeChallengesForEmailChange kills every password-reset and
// email-verification code the user holds: they were mailed to the old address.
// It tombstones the user's newest-record pointers (by write order, so a code
// requested afterwards, for the new address, is valid whatever the clock says)
// and also writes the time-based identifier-change marker, which is only the
// fallback for records whose owner has no pointer (see consumeResetRecord).
func (e *Engine) supersedeChallengesForEmailChange(ctx context.Context, challengeTenant, recordTenant, userID string) error {
	tenants := []string{challengeTenant}
	if recordTenant != "" && tenantIDFromToken(recordTenant) != tenantIDFromToken(challengeTenant) {
		tenants = append(tenants, recordTenant)
	}
	var errs []error
	if err := e.emailChangeStore.MarkIdentifierChanged(ctx, challengeTenant, userID, e.now(), e.emailChangeMarkerTTL()); err != nil {
		errs = append(errs, err)
	}
	for _, tenant := range tenants {
		if err := e.supersedeResetCodes(ctx, tenant, userID); err != nil {
			errs = append(errs, err)
		}
		if err := e.supersedeVerificationCodes(ctx, tenant, userID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// emailChangeMarkerTTL outlives the longest challenge an old address could be
// holding: the longer of the verification and reset TTLs, plus an hour.
func (e *Engine) emailChangeMarkerTTL() time.Duration {
	ttl := e.config.EmailVerification.VerificationTTL
	if reset := e.config.PasswordReset.ResetTTL; reset > ttl {
		ttl = reset
	}
	if ttl < emailChangeDefaultTTL {
		ttl = emailChangeDefaultTTL
	}
	return ttl + time.Hour
}

// issuedBeforeEmailChange reports whether a challenge (a reset or verification
// record, which carry only their expiry) was issued at or before the user's
// last email change, and so was addressed to the old email. It reads one key
// and only runs while EmailChange is enabled. A marker that cannot be read is an
// error: the caller refuses the challenge rather than guess.
func (e *Engine) issuedBeforeEmailChange(ctx context.Context, tenantID, userID string, expiresAt int64, ttl time.Duration) (bool, error) {
	if !e.emailChangeEnabled() {
		return false, nil
	}
	changedAt, err := e.emailChangeStore.IdentifierChangedAt(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	if changedAt == 0 {
		return false, nil
	}
	issuedAt := expiresAt - int64(ttl/time.Second)
	return issuedAt <= changedAt, nil
}

// cancelEmailChangeAfterRecovery drops the user's pending email change after a
// revocation of all their sessions (password reset or change, LogoutAll, and
// the other flows that end with one). A staged change was requested from a
// session that may be the reason for the recovery: it must not survive it. It
// never fails the operation that called it: a failure is logged and audited.
func (e *Engine) cancelEmailChangeAfterRecovery(ctx context.Context, tenantID, userID string) {
	if !e.emailChangeEnabled() || userID == "" {
		return
	}
	tenants := sessionRevocationTenants(ctx, tenantID)
	if !e.tenantScopedLookup() {
		// Without tenant-scoped lookups the challenge was stored under the
		// user's own tenant, which neither the request's context nor the caller
		// of a bare LogoutAll(userID) necessarily names (see cancelEmailChange).
		switch user, err := e.lookupEmailChangeUser(ctx, tenantIDFromContext(ctx), userID); {
		case err == nil:
			owner := e.emailChangeTenant(ctx, user)
			known := false
			for _, t := range tenants {
				known = known || tenantIDFromToken(t) == tenantIDFromToken(owner)
			}
			if !known {
				tenants = append(tenants, owner)
			}
		case errors.Is(err, ErrUserNotFound):
		default:
			e.warn("goAuth: pending email change could not be located after a recovery")
			_ = e.emailChangeFail(ctx, tenantID, userID, "cancel", emailChangeReasonRecovery, WrapAuthError(ErrSystemUnavailable, err))
		}
	}
	for _, tenant := range tenants {
		cancelled, err := e.emailChangeStore.CancelPending(ctx, tenant, userID)
		if err != nil {
			e.warn("goAuth: pending email change could not be cancelled after a recovery")
			_ = e.emailChangeFail(ctx, tenant, userID, "cancel", emailChangeReasonRecovery, WrapAuthError(ErrSystemUnavailable, err))
			continue
		}
		if cancelled {
			e.emitAudit(ctx, auditEventEmailChangeCancelled, true, userID, tenant, "", nil, func() map[string]string {
				return map[string]string{"reason": emailChangeReasonRecovery}
			})
		}
	}
}

// CancelEmailChange deletes userID's pending email-change challenge, if any.
// It is idempotent. userID must come from the session.
//
//	Flow:        Cancel Email Change
//	Docs:        docs/email_change.md
func (e *Engine) CancelEmailChange(ctx context.Context, userID string) error {
	if err := e.cancelEmailChange(ctx, userID); err != nil {
		return mapToAuthError(err)
	}
	return nil
}

func (e *Engine) cancelEmailChange(ctx context.Context, userID string) error {
	tenantID := tenantIDFromContext(ctx)
	if !e.emailChangeEnabled() {
		return e.emailChangeFail(ctx, tenantID, userID, "cancel", emailChangeReasonDisabled, ErrEmailChangeDisabled)
	}
	if userID == "" {
		return nil
	}
	// The challenge is stored under the tenant of the request that made it, which
	// for a single-tenant deployment may be the user's own; look the user up to
	// find it. A lookup that fails must not fall back to the context tenant: that
	// would delete the wrong pointer and report a cancellation that did not happen.
	if !e.tenantScopedLookup() {
		user, err := e.lookupEmailChangeUser(ctx, tenantID, userID)
		switch {
		case err == nil:
			tenantID = e.emailChangeTenant(ctx, user)
		case errors.Is(err, ErrUserNotFound):
			// No such user: nothing can be confirmed, so nothing is pending.
			return nil
		default:
			return e.emailChangeFail(ctx, tenantID, userID, "cancel", emailChangeReasonUnavailable, err)
		}
	}
	if err := e.emailChangeStore.Cancel(ctx, tenantID, userID); err != nil {
		return e.emailChangeFail(ctx, tenantID, userID, "cancel", emailChangeReasonUnavailable, WrapAuthError(ErrSystemUnavailable, err))
	}
	return nil
}
