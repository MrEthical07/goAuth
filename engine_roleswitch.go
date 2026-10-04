package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

const (
	auditEventRoleSwitched     = "role_switched"
	auditEventRoleSwitchFailed = "role_switch_failed"
)

// role_switch_failed metadata.reason values.
const (
	roleSwitchReasonDisabled      = "disabled"
	roleSwitchReasonInvalid       = "invalid_session"
	roleSwitchReasonReuse         = "reuse_detected"
	roleSwitchReasonSameRole      = "same_role"
	roleSwitchReasonNotAllowed    = "not_allowed"
	roleSwitchReasonStepUp        = "step_up_required"
	roleSwitchReasonRateLimited   = "rate_limited"
	roleSwitchReasonAccountStatus = "account_status"
	roleSwitchReasonUnavailable   = "unavailable"
)

// SwitchRole replaces the session identified by refreshToken with a new one
// that carries targetRole, and returns that session's token pair. The
// presented refresh token is spent, so a switch is single-use: always store
// the returned tokens and discard the old pair.
//
// The session is identified by the refresh token (the same proof
// [Engine.Refresh] uses) and the tenant comes from the request context. The
// new session keeps the old one's CreatedAt and ExpiresAt, so switching can
// never extend a session's absolute lifetime; other sessions of the same
// user are untouched.
//
// SwitchRole returns [ErrRoleSwitchDisabled] unless Config.RoleSwitch.Enabled
// is set. The result is non-nil only on success or alongside
// [ErrStepUpRequired], in which case it lists the accepted inline factors.
// Decode, not-found, expired and reuse outcomes are exactly the errors
// Refresh returns for them: [ErrRefreshInvalid], [ErrSessionNotFound] and
// [ErrRefreshReuse] (which, as in Refresh, revokes the session).
//
// Role switching is only safe on routes validated in [ModeStrict]: a
// pre-switch access token remains valid on ModeHybrid and ModeJWTOnly routes
// until it expires. See docs/role_switching.md for the per-mode table and the
// race semantics between SwitchRole and Refresh.
//
//	Flow:        Switch Role
//	Docs:        docs/role_switching.md
//	Performance: 1 Redis GET + 1 provider call + 1 Lua EVALSHA (plus the attempt limiter).
//	Security:    attempt-limited per session; single-use refresh proof; atomic swap.
func (e *Engine) SwitchRole(ctx context.Context, refreshToken, targetRole string, opts RoleSwitchOptions) (*RoleSwitchResult, error) {
	e.ensureFlowDeps()
	if !e.roleSwitchActive() {
		e.auditRoleSwitchFailure(ctx, internalflows.RoleSwitchResult{TenantID: tenantIDFromContext(ctx), ToRole: targetRole}, roleSwitchReasonDisabled, ErrRoleSwitchDisabled)
		return nil, mapToAuthError(ErrRoleSwitchDisabled)
	}

	result := e.flows.SwitchRole(ctx, refreshToken, targetRole, internalflows.RoleSwitchOptions{
		MFAType:  opts.MFAType,
		MFACode:  opts.MFACode,
		Password: opts.Password,
	})
	if result.Failure != internalflows.RoleSwitchFailureNone {
		return e.roleSwitchFailure(ctx, result)
	}

	e.emitAudit(ctx, auditEventRoleSwitched, true, result.UserID, result.TenantID, result.NewSessionID, nil, func() map[string]string {
		meta := map[string]string{
			"from_role":      result.FromRole,
			"to_role":        result.ToRole,
			"old_session_id": result.SessionID,
			"new_session_id": result.NewSessionID,
		}
		if result.StepUpMethod != "" {
			meta["step_up"] = result.StepUpMethod
		}
		return meta
	})
	return &RoleSwitchResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		Role:         result.ToRole,
	}, nil
}

// roleSwitchActive reports whether role switching is enabled and fully wired.
func (e *Engine) roleSwitchActive() bool {
	return e != nil &&
		e.config.RoleSwitch.Enabled &&
		e.roleSwitchProvider != nil &&
		e.roleSwitchLimiter != nil &&
		e.sessionStore != nil
}

// roleSwitchFailure books a failed switch (audit, plus the reuse handling
// shared with Refresh) and returns the public error. Only a step-up failure
// carries a result.
func (e *Engine) roleSwitchFailure(ctx context.Context, result internalflows.RoleSwitchResult) (*RoleSwitchResult, error) {
	var (
		err    error
		reason string
	)
	switch result.Failure {
	case internalflows.RoleSwitchFailureDecode:
		err, reason = ErrRefreshInvalid, roleSwitchReasonInvalid
	case internalflows.RoleSwitchFailureRateLimited:
		e.emitRateLimit(ctx, "role_switch", result.TenantID, nil)
		err, reason = ErrRoleSwitchRateLimited, roleSwitchReasonRateLimited
	case internalflows.RoleSwitchFailureSessionNotFound:
		err, reason = ErrSessionNotFound, roleSwitchReasonInvalid
	case internalflows.RoleSwitchFailureReuse:
		e.recordRefreshReuse(ctx, result.TenantID, result.SessionID)
		err, reason = ErrRefreshReuse, roleSwitchReasonReuse
	case internalflows.RoleSwitchFailureDeviceBinding:
		err, reason = result.Err, roleSwitchReasonInvalid
	case internalflows.RoleSwitchFailureSameRole:
		err, reason = ErrRoleSwitchSameRole, roleSwitchReasonSameRole
	case internalflows.RoleSwitchFailureRoleNotAllowed:
		err, reason = ErrRoleNotAllowed, roleSwitchReasonNotAllowed
	case internalflows.RoleSwitchFailureAccountStatus:
		e.metricInc(MetricSessionInvalidated)
		err, reason = result.Err, roleSwitchReasonAccountStatus
	case internalflows.RoleSwitchFailureUnverified:
		e.metricInc(MetricSessionInvalidated)
		err, reason = ErrAccountUnverified, roleSwitchReasonAccountStatus
	case internalflows.RoleSwitchFailureStepUpRequired:
		err, reason = ErrStepUpRequired, roleSwitchReasonStepUp
	case internalflows.RoleSwitchFailureStepUpFailed:
		err, reason = result.Err, roleSwitchReasonStepUp
	default:
		err, reason = roleSwitchUnavailableError(result.Err), roleSwitchReasonUnavailable
	}

	e.auditRoleSwitchFailure(ctx, result, reason, err)
	if result.Failure == internalflows.RoleSwitchFailureStepUpRequired {
		factors := result.StepUpFactors
		if factors == nil {
			factors = []string{}
		}
		return &RoleSwitchResult{StepUpRequired: true, StepUpFactors: factors}, mapToAuthError(err)
	}
	return nil, mapToAuthError(err)
}

// roleSwitchUnavailableError picks the public error for an infrastructure
// failure: a corrupt session blob is an invalid token, as in Refresh; every
// other backend or provider failure is "unavailable", never a raw error.
func roleSwitchUnavailableError(err error) error {
	if errors.Is(err, session.ErrRefreshSessionCorrupt) {
		return ErrRefreshInvalid
	}
	return ErrSystemUnavailable
}

func (e *Engine) auditRoleSwitchFailure(ctx context.Context, result internalflows.RoleSwitchResult, reason string, err error) {
	e.emitAudit(ctx, auditEventRoleSwitchFailed, false, result.UserID, result.TenantID, result.SessionID, err, func() map[string]string {
		meta := map[string]string{"reason": reason}
		if result.FromRole != "" {
			meta["from_role"] = result.FromRole
		}
		if result.ToRole != "" {
			meta["to_role"] = result.ToRole
		}
		return meta
	})
}

func (e *Engine) roleSwitchFlowDeps() internalflows.RoleSwitchDeps {
	if !e.roleSwitchActive() {
		return internalflows.RoleSwitchDeps{}
	}

	deps := internalflows.RoleSwitchDeps{
		TenantIDFromContext: tenantIDFromContext,
		Now:                 time.Now,
		DecodeRefreshToken:  internal.DecodeRefreshToken,
		NewRefreshSecret:    internal.NewRefreshSecret,
		HashRefreshSecret:   internal.HashRefreshSecret,
		EncodeRefreshToken:  internal.EncodeRefreshToken,
		NewSessionID: func() (string, error) {
			sid, err := internal.NewSessionID()
			if err != nil {
				return "", err
			}
			return sid.String(), nil
		},
		IssueAccessToken:          e.issueAccessToken,
		GetRoleMask:               e.roleManager.GetMask,
		AccountStatusError:        func(status uint8) error { return accountStatusToError(AccountStatus(status)) },
		ShouldRequireVerified:     e.shouldRequireVerified,
		PendingVerificationStatus: uint8(AccountPendingVerification),
		ValidateDeviceBinding:     e.validateDeviceBinding,
		EnableReplayTracking:      e.config.SessionHardening.EnableReplayTracking,
		SessionLifetime:           e.maxSessionLifetime,
		Warn:                      e.warn,
		ReserveAttempt:            e.reserveRoleSwitchAttempt,
		ResetAttempts:             e.resetRoleSwitchAttempts,
		LookupUser:                e.lookupRoleSwitchUser,
		CanAssumeRole:             e.roleSwitchProvider.CanAssumeRole,
		VerifyMFA:                 e.verifyRoleSwitchMFA,
		VerifyPassword:            e.VerifyPassword,
		StepUpFactors:             e.roleSwitchStepUpFactors,
		SessionStore:              e.sessionStore,
		RedisNil:                  redis.Nil,
	}
	if len(e.config.RoleSwitch.StepUp) > 0 {
		deps.StepUp = make(map[string]internalflows.RoleStepUpPolicy, len(e.config.RoleSwitch.StepUp))
		for role, policy := range e.config.RoleSwitch.StepUp {
			deps.StepUp[role] = internalflows.RoleStepUpPolicy{RequireMFA: policy.RequireMFA, MaxAge: policy.MaxAge}
		}
	}
	return deps
}

// reserveRoleSwitchAttempt claims one switch attempt. It fails open on
// limiter backend errors, like every other limiter: an explicit denial
// always blocks, an outage never does.
func (e *Engine) reserveRoleSwitchAttempt(ctx context.Context, tenantID, sessionID string) bool {
	e.metricInc(MetricLimiterCheck)
	err := e.roleSwitchLimiter.Reserve(ctx, tenantID, sessionID)
	if err == nil {
		return true
	}
	if errors.Is(err, limiters.ErrRoleSwitchRateLimited) {
		return false
	}
	e.emitLimiterFailOpen(ctx, "role_switch", tenantID, err)
	return true
}

func (e *Engine) resetRoleSwitchAttempts(ctx context.Context, tenantID, sessionID string) {
	if err := e.roleSwitchLimiter.Reset(ctx, tenantID, sessionID); err != nil {
		e.emitLimiterFailOpen(ctx, "role_switch", tenantID, err)
	}
}

// lookupRoleSwitchUser resolves the account in the session's own tenant,
// never one taken from the caller.
func (e *Engine) lookupRoleSwitchUser(ctx context.Context, tenantID, userID string) (internalflows.RoleSwitchUser, error) {
	user, err := e.lookupUserByIDInTenant(ctx, tenantID, userID)
	if err != nil {
		return internalflows.RoleSwitchUser{}, err
	}
	return internalflows.RoleSwitchUser{
		UserID:            user.UserID,
		TenantID:          tenantID,
		Status:            uint8(user.Status),
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}, nil
}

// verifyRoleSwitchMFA verifies an inline second-factor proof. A user who has
// no such factor never passes: the shared TOTP verifier treats "TOTP not
// enabled" as "nothing to verify" for sensitive-action prompts, which would
// make any code a valid proof here.
func (e *Engine) verifyRoleSwitchMFA(ctx context.Context, user internalflows.RoleSwitchUser, mfaType, code string) error {
	switch mfaType {
	case internalflows.StepUpMethodTOTP:
		if !e.config.TOTP.Enabled {
			return ErrTOTPFeatureDisabled
		}
		record, err := e.userProvider.GetTOTPSecret(ctx, user.UserID)
		if err != nil {
			return ErrTOTPUnavailable
		}
		if record == nil || !record.Enabled || len(record.Secret) == 0 {
			return ErrTOTPNotConfigured
		}
		return e.flows.VerifyTOTPForUser(ctx, internalflows.TOTPUser{
			UserID:         user.UserID,
			TenantID:       user.TenantID,
			Status:         user.Status,
			AccountVersion: user.AccountVersion,
		}, code)
	case internalflows.StepUpMethodBackupCode:
		return e.VerifyBackupCodeInTenant(ctx, user.TenantID, user.UserID, code)
	}
	return ErrStepUpRequired
}

// roleSwitchStepUpFactors lists the inline factors the user can supply for
// an unsatisfied policy, limited to those the user actually has.
func (e *Engine) roleSwitchStepUpFactors(ctx context.Context, user internalflows.RoleSwitchUser, policy internalflows.RoleStepUpPolicy) []string {
	factors := []string{}
	if !policy.RequireMFA {
		return append(factors, internalflows.StepUpMethodPassword)
	}
	if !e.config.TOTP.Enabled {
		return factors
	}
	record, err := e.userProvider.GetTOTPSecret(ctx, user.UserID)
	if err != nil || record == nil || !record.Enabled {
		return factors
	}
	factors = append(factors, internalflows.StepUpMethodTOTP)
	if codes, err := e.userProvider.GetBackupCodes(ctx, user.UserID); err == nil && len(codes) > 0 {
		factors = append(factors, internalflows.StepUpMethodBackupCode)
	}
	return factors
}

// roleSwitchRecordsAssurance reports whether sessions issued after a second
// factor must carry an assurance: only while role switching is active and at
// least one step-up policy exists. Otherwise no assurance key is ever
// written and login behaves exactly as without the feature.
func (e *Engine) roleSwitchRecordsAssurance() bool {
	return e.roleSwitchActive() && len(e.config.RoleSwitch.StepUp) > 0
}

func (e *Engine) configureLoginAssuranceDeps(deps *internalflows.LoginDeps) {
	if e.roleSwitchRecordsAssurance() {
		deps.RecordAssurance = e.recordLoginAssurance
	}
}

// recordLoginAssurance stores the assurance of a session issued after a
// successful second factor. It is best effort: a failure only means a later
// step-up policy asks for the factor again.
func (e *Engine) recordLoginAssurance(ctx context.Context, tenantID, refreshToken, method string, rememberMe bool) {
	sessionID, _, err := internal.DecodeRefreshToken(refreshToken)
	if err != nil {
		e.warn("goAuth: session assurance skipped; refresh token undecodable")
		return
	}
	now := time.Now().Unix()
	assurance := session.Assurance{MFAAt: now, MFAMethod: method, AuthAt: now}
	if err := e.sessionStore.SaveAssurance(ctx, tenantID, sessionID, assurance, e.sessionLifetimeFor(rememberMe)); err != nil {
		e.warn("goAuth: session assurance write failed")
	}
}
