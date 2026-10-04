package flows

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// RoleSwitchFailureKind classifies role-switch failures for root-level mapping.
type RoleSwitchFailureKind int

const (
	RoleSwitchFailureNone RoleSwitchFailureKind = iota
	RoleSwitchFailureDecode
	RoleSwitchFailureRateLimited
	RoleSwitchFailureSessionNotFound
	RoleSwitchFailureReuse
	RoleSwitchFailureDeviceBinding
	RoleSwitchFailureSameRole
	RoleSwitchFailureRoleNotAllowed
	RoleSwitchFailureAccountStatus
	RoleSwitchFailureUnverified
	RoleSwitchFailureStepUpRequired
	RoleSwitchFailureStepUpFailed
	RoleSwitchFailureUnavailable
)

// RoleSwitchOptions is the flow-local inline step-up proof.
type RoleSwitchOptions struct {
	MFAType  string
	MFACode  string
	Password string
}

// Inline step-up method names, shared with the assurance record.
const (
	StepUpMethodTOTP       = "totp"
	StepUpMethodBackupCode = "backup_code"
	StepUpMethodPassword   = "password"
	// StepUpMethodAssurance marks a policy satisfied by the assurance the
	// session already held, with no inline proof.
	StepUpMethodAssurance = "session_assurance"
)

// RoleStepUpPolicy is the flow-local copy of the per-role step-up policy.
type RoleStepUpPolicy struct {
	RequireMFA bool
	MaxAge     time.Duration
}

// RoleSwitchUser is the freshly resolved account the new session is built from.
type RoleSwitchUser struct {
	UserID            string
	TenantID          string
	Status            uint8
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

// RoleSwitchResult carries either the issued tokens or failure metadata.
type RoleSwitchResult struct {
	Failure RoleSwitchFailureKind
	Err     error

	TenantID     string
	SessionID    string // the presented (old) session
	NewSessionID string
	UserID       string
	FromRole     string
	ToRole       string

	// StepUpMethod is how the target role's policy was satisfied, when it
	// had one.
	StepUpMethod  string
	StepUpFactors []string

	AccessToken  string
	RefreshToken string
}

// RoleSwitchSessionStore is the session persistence a switch needs.
type RoleSwitchSessionStore interface {
	Peek(ctx context.Context, tenantID, sessionID string) (*session.Session, error)
	GetAssurance(ctx context.Context, tenantID, sessionID string) (*session.Assurance, error)
	RotateRefreshHash(
		ctx context.Context,
		tenantID, sessionID string,
		providedHash [32]byte,
		nextHash [32]byte,
	) (*session.Session, error)
	SwapSession(
		ctx context.Context,
		tenantID, oldSessionID string,
		providedHash [32]byte,
		next *session.Session,
		assurance *session.Assurance,
	) error
	TrackReplayAnomaly(ctx context.Context, sessionID string, ttl time.Duration) error
	Delete(ctx context.Context, tenantID, sessionID string) error
}

// RoleSwitchDeps captures role-switch flow dependencies.
type RoleSwitchDeps struct {
	TenantIDFromContext func(context.Context) string
	Now                 func() time.Time

	DecodeRefreshToken func(string) (string, [32]byte, error)
	NewRefreshSecret   func() ([32]byte, error)
	HashRefreshSecret  func([32]byte) [32]byte
	EncodeRefreshToken func(string, [32]byte) (string, error)
	NewSessionID       func() (string, error)
	IssueAccessToken   func(*session.Session) (string, error)
	GetRoleMask        func(string) (interface{}, bool)

	AccountStatusError        func(uint8) error
	ShouldRequireVerified     func() bool
	PendingVerificationStatus uint8
	ValidateDeviceBinding     func(context.Context, *session.Session) error

	EnableReplayTracking bool
	SessionLifetime      func() time.Duration
	Warn                 func(string, ...any)

	// ReserveAttempt claims one switch attempt for (tenant, session) and
	// reports whether the caller may proceed. It fails open on backend
	// errors, so false always means an explicit rate-limit denial.
	ReserveAttempt func(ctx context.Context, tenantID, sessionID string) bool
	ResetAttempts  func(ctx context.Context, tenantID, sessionID string)

	// LookupUser resolves the account in the session's tenant. A missing
	// account (including the tenant-mismatch backstop) must satisfy
	// errors.Is(err, UserNotFound); any other error is a provider failure.
	LookupUser    func(ctx context.Context, tenantID, userID string) (RoleSwitchUser, error)
	UserNotFound  error
	CanAssumeRole func(ctx context.Context, tenantID, userID, role string) (bool, error)

	// StepUp holds the per-target-role policies. Nil when none configured.
	StepUp map[string]RoleStepUpPolicy
	// VerifyMFA verifies an inline "totp" or "backup_code" proof and must
	// never accept a user who has no such factor.
	VerifyMFA      func(ctx context.Context, user RoleSwitchUser, mfaType, code string) error
	VerifyPassword func(ctx context.Context, userID, password string) error
	// StepUpFactors lists the inline factors the user can actually use.
	StepUpFactors func(ctx context.Context, user RoleSwitchUser, policy RoleStepUpPolicy) []string

	SessionStore RoleSwitchSessionStore
	RedisNil     error
}

// RunSwitchRole executes the role-switch algorithm: it spends the presented
// refresh token, swaps the session for one carrying targetRole, and issues a
// fresh token pair. Every failure leaves the old session untouched except
// where noted (refresh-token reuse and a dead account delete it, exactly as
// Refresh does).
func RunSwitchRole(
	ctx context.Context,
	refreshToken, targetRole string,
	opts RoleSwitchOptions,
	deps RoleSwitchDeps,
) RoleSwitchResult {
	tenantID := deps.TenantIDFromContext(ctx)

	sessionID, presentedSecret, err := deps.DecodeRefreshToken(refreshToken)
	if err != nil {
		return RoleSwitchResult{Failure: RoleSwitchFailureDecode, Err: err, TenantID: tenantID}
	}
	base := RoleSwitchResult{TenantID: tenantID, SessionID: sessionID}

	// Reserved before any session, provider or Argon2 work, keyed by the
	// request tenant and the decoded session ID, so wrong-tenant and unknown
	// sessions consume attempts too.
	if !deps.ReserveAttempt(ctx, tenantID, sessionID) {
		return failRoleSwitch(base, RoleSwitchFailureRateLimited, nil)
	}

	nextSecret, err := deps.NewRefreshSecret()
	if err != nil {
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	}
	newSessionID, err := deps.NewSessionID()
	if err != nil {
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	}
	providedHash := deps.HashRefreshSecret(presentedSecret)
	nextHash := deps.HashRefreshSecret(nextSecret)

	sess, err := deps.SessionStore.Peek(ctx, tenantID, sessionID)
	if err != nil {
		kind := classifyPeekError(err, deps)
		if kind == RoleSwitchFailureUnavailable && !errors.Is(err, session.ErrRedisUnavailable) {
			// The store answered but the blob would not decode: the same
			// "corrupt session" Refresh reports for an undecodable blob.
			err = errors.Join(session.ErrRefreshSessionCorrupt, err)
		}
		return failRoleSwitch(base, kind, err)
	}
	base.UserID = sess.UserID
	base.FromRole = sess.Role
	base.ToRole = targetRole

	if sess.ExpiresAt <= deps.Now().Unix() {
		// Same handling as Refresh's expired case: let the rotate script
		// delete the expired session and report it as not found.
		return revokeViaRotate(ctx, base, providedHash, nextHash, deps)
	}
	if subtle.ConstantTimeCompare(sess.RefreshHash[:], providedHash[:]) != 1 {
		// The presented token is not the session's current one. Do not
		// invent new handling: the existing rotate script atomically
		// detects the mismatch and deletes the session.
		return revokeViaRotate(ctx, base, providedHash, nextHash, deps)
	}

	if err := deps.ValidateDeviceBinding(ctx, sess); err != nil {
		return failRoleSwitch(base, RoleSwitchFailureDeviceBinding, err)
	}

	if targetRole == sess.Role {
		return failRoleSwitch(base, RoleSwitchFailureSameRole, nil)
	}
	mask, ok := deps.GetRoleMask(targetRole)
	if !ok {
		// Not a registered role: no provider call, and nothing about
		// which roles exist is revealed.
		return failRoleSwitch(base, RoleSwitchFailureRoleNotAllowed, nil)
	}

	user, err := deps.LookupUser(ctx, sess.TenantID, sess.UserID)
	switch {
	case err != nil && deps.UserNotFound != nil && errors.Is(err, deps.UserNotFound):
		return failRoleSwitch(base, RoleSwitchFailureSessionNotFound, err)
	case err != nil:
		// A provider or database failure says nothing about the session:
		// it stays untouched and the same refresh token works on retry.
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	case user.UserID != sess.UserID:
		return failRoleSwitch(base, RoleSwitchFailureSessionNotFound, nil)
	}
	if statusErr := deps.AccountStatusError(user.Status); statusErr != nil {
		_ = deps.SessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		return failRoleSwitch(base, RoleSwitchFailureAccountStatus, statusErr)
	}
	if deps.ShouldRequireVerified != nil &&
		deps.ShouldRequireVerified() &&
		user.Status == deps.PendingVerificationStatus {
		_ = deps.SessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		return failRoleSwitch(base, RoleSwitchFailureUnverified, nil)
	}

	allowed, err := deps.CanAssumeRole(ctx, sess.TenantID, sess.UserID, targetRole)
	if err != nil {
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	}
	if !allowed {
		return failRoleSwitch(base, RoleSwitchFailureRoleNotAllowed, nil)
	}

	var newAssurance *session.Assurance
	if policy, hasPolicy := deps.StepUp[targetRole]; hasPolicy {
		outcome := runStepUp(ctx, policy, sess, user, opts, deps)
		if outcome.failure != RoleSwitchFailureNone {
			base.StepUpFactors = outcome.factors
			return failRoleSwitch(base, outcome.failure, outcome.err)
		}
		newAssurance = outcome.assurance
		base.StepUpMethod = outcome.method
	}

	accountVersion := user.AccountVersion
	if accountVersion == 0 {
		accountVersion = 1
	}
	next := &session.Session{
		SessionID:         newSessionID,
		UserID:            sess.UserID,
		TenantID:          sess.TenantID,
		Role:              targetRole,
		Mask:              mask,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    accountVersion,
		Status:            user.Status,
		RefreshHash:       nextHash,
		IPHash:            sess.IPHash,
		UserAgentHash:     sess.UserAgentHash,
		// Copied, never reset: repeated switches must not stretch a session
		// past its absolute lifetime or MaxSessionDuration.
		CreatedAt: sess.CreatedAt,
		ExpiresAt: sess.ExpiresAt,
	}

	// Tokens are built before the swap so a failure here cannot strand the
	// caller with the old session gone and no new tokens.
	access, err := deps.IssueAccessToken(next)
	if err != nil {
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	}
	refresh, err := deps.EncodeRefreshToken(newSessionID, nextSecret)
	if err != nil {
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, err)
	}

	err = deps.SessionStore.SwapSession(ctx, sess.TenantID, sess.SessionID, providedHash, next, newAssurance)
	if err != nil {
		return failRoleSwitch(base, classifyRotateError(err, deps), err)
	}

	deps.ResetAttempts(ctx, tenantID, sessionID)

	base.NewSessionID = newSessionID
	base.AccessToken = access
	base.RefreshToken = refresh
	return base
}

func failRoleSwitch(base RoleSwitchResult, kind RoleSwitchFailureKind, err error) RoleSwitchResult {
	base.Failure = kind
	base.Err = err
	return base
}

// classifyPeekError maps a failed session read to a failure kind. A missing
// session is not-found; anything else the store could not read is
// unavailable.
func classifyPeekError(err error, deps RoleSwitchDeps) RoleSwitchFailureKind {
	if deps.RedisNil != nil && errors.Is(err, deps.RedisNil) {
		return RoleSwitchFailureSessionNotFound
	}
	return RoleSwitchFailureUnavailable
}

// classifyRotateError maps the outcome of a destructive store call
// (rotate or swap) to a failure kind.
func classifyRotateError(err error, deps RoleSwitchDeps) RoleSwitchFailureKind {
	switch {
	case errors.Is(err, session.ErrRefreshHashMismatch):
		return RoleSwitchFailureReuse
	case deps.RedisNil != nil && errors.Is(err, deps.RedisNil):
		return RoleSwitchFailureSessionNotFound
	default:
		return RoleSwitchFailureUnavailable
	}
}

// revokeViaRotate hands an expired or mismatching session to the existing
// refresh-rotation script, which deletes it atomically, so a switch revokes
// exactly the way a refresh does.
func revokeViaRotate(
	ctx context.Context,
	base RoleSwitchResult,
	providedHash, nextHash [32]byte,
	deps RoleSwitchDeps,
) RoleSwitchResult {
	_, err := deps.SessionStore.RotateRefreshHash(ctx, base.TenantID, base.SessionID, providedHash, nextHash)
	if err == nil {
		// The session matched after all, which the pre-read said it did
		// not. Nothing was issued, so report the infrastructure failure
		// instead of pretending a switch happened.
		return failRoleSwitch(base, RoleSwitchFailureUnavailable, errors.New("role switch: unexpected rotation"))
	}
	kind := classifyRotateError(err, deps)
	if kind == RoleSwitchFailureReuse {
		trackRefreshReuse(ctx, deps.SessionStore, deps.EnableReplayTracking, base.SessionID, deps.SessionLifetime, deps.Warn)
	}
	return failRoleSwitch(base, kind, err)
}

type stepUpOutcome struct {
	failure   RoleSwitchFailureKind
	err       error
	factors   []string
	method    string
	assurance *session.Assurance
}

// runStepUp checks the target role's policy against the session's
// assurance and, when it is not already satisfied, against the inline
// proof. It never switches anything; it only decides.
func runStepUp(
	ctx context.Context,
	policy RoleStepUpPolicy,
	sess *session.Session,
	user RoleSwitchUser,
	opts RoleSwitchOptions,
	deps RoleSwitchDeps,
) stepUpOutcome {
	now := deps.Now()
	held, err := deps.SessionStore.GetAssurance(ctx, sess.TenantID, sess.SessionID)
	if err != nil {
		return stepUpOutcome{failure: RoleSwitchFailureUnavailable, err: err}
	}
	if policySatisfied(policy, sess, held, now) {
		return stepUpOutcome{method: StepUpMethodAssurance}
	}

	proof := session.Assurance{}
	if held != nil {
		proof = *held
	}

	switch {
	case opts.MFACode != "" && isInlineMFAType(opts.MFAType):
		if err := deps.VerifyMFA(ctx, user, opts.MFAType, opts.MFACode); err != nil {
			return stepUpOutcome{failure: RoleSwitchFailureStepUpFailed, err: err}
		}
		proof.MFAAt = now.Unix()
		proof.MFAMethod = opts.MFAType
		proof.AuthAt = now.Unix()
		return stepUpOutcome{method: opts.MFAType, assurance: &proof}

	case opts.Password != "" && !policy.RequireMFA && policy.MaxAge > 0:
		if err := deps.VerifyPassword(ctx, user.UserID, opts.Password); err != nil {
			return stepUpOutcome{failure: RoleSwitchFailureStepUpFailed, err: err}
		}
		proof.AuthAt = now.Unix()
		return stepUpOutcome{method: StepUpMethodPassword, assurance: &proof}
	}

	return stepUpOutcome{
		failure: RoleSwitchFailureStepUpRequired,
		factors: deps.StepUpFactors(ctx, user, policy),
	}
}

func isInlineMFAType(mfaType string) bool {
	return mfaType == StepUpMethodTOTP || mfaType == StepUpMethodBackupCode
}

// policySatisfied reports whether the session's own history already meets
// the policy. With RequireMFA only a second-factor assurance counts. Without
// it the policy is "recent authentication": the newest of the session's
// creation time and any recorded proof must be within MaxAge.
func policySatisfied(policy RoleStepUpPolicy, sess *session.Session, held *session.Assurance, now time.Time) bool {
	if policy.RequireMFA {
		if held == nil || held.MFAAt == 0 {
			return false
		}
		return policy.MaxAge <= 0 || now.Sub(time.Unix(held.MFAAt, 0)) <= policy.MaxAge
	}
	if policy.MaxAge <= 0 {
		return true
	}
	latest := sess.CreatedAt
	if held != nil {
		if held.MFAAt > latest {
			latest = held.MFAAt
		}
		if held.AuthAt > latest {
			latest = held.AuthAt
		}
	}
	return now.Sub(time.Unix(latest, 0)) <= policy.MaxAge
}
