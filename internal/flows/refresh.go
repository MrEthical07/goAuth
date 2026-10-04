package flows

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// RefreshFailureKind classifies refresh flow failures for root-level mapping.
type RefreshFailureKind int

const (
	RefreshFailureNone RefreshFailureKind = iota
	RefreshFailureDecode
	RefreshFailureNextSecret
	RefreshFailureReuse
	RefreshFailureSessionNotFound
	RefreshFailureRotate
	RefreshFailureAccountStatus
	RefreshFailureUnverified
	RefreshFailureIssueAccess
	RefreshFailureEncode
	// RefreshFailureRoleRevoked: the role-switch re-check found that the
	// session's role is no longer held. The session was deleted.
	RefreshFailureRoleRevoked
	// RefreshFailureRoleCheck: the re-check could not reach the provider.
	// Nothing was rotated or deleted.
	RefreshFailureRoleCheck
)

// RefreshResult carries either the issued token pair or failure metadata.
type RefreshResult struct {
	Failure      RefreshFailureKind
	Err          error
	TenantID     string
	SessionID    string
	UserID       string
	Session      *session.Session
	AccessToken  string
	RefreshToken string
}

type RefreshSessionStore interface {
	RotateRefreshHash(
		ctx context.Context,
		tenantID, sessionID string,
		providedHash [32]byte,
		nextHash [32]byte,
	) (*session.Session, error)
	TrackReplayAnomaly(ctx context.Context, sessionID string, ttl time.Duration) error
	Delete(ctx context.Context, tenantID, sessionID string) error
}

// RefreshRoleRecheck is the optional pre-rotation check that the session's
// current role is still held. It is wired only while role switching is
// enabled; a nil RefreshDeps.RoleRecheck leaves refresh exactly as it was.
type RefreshRoleRecheck struct {
	Peek          func(ctx context.Context, tenantID, sessionID string) (*session.Session, error)
	CanAssumeRole func(ctx context.Context, tenantID, userID, role string) (bool, error)
	Now           func() time.Time
}

// RefreshDeps captures refresh flow dependencies.
type RefreshDeps struct {
	TenantIDFromContext       func(context.Context) string
	DecodeRefreshToken        func(string) (string, [32]byte, error)
	NewRefreshSecret          func() ([32]byte, error)
	HashRefreshSecret         func([32]byte) [32]byte
	EncodeRefreshToken        func(string, [32]byte) (string, error)
	IssueAccessToken          func(*session.Session) (string, error)
	AccountStatusError        func(uint8) error
	ShouldRequireVerified     func() bool
	PendingVerificationStatus uint8
	SessionLifetime           func() time.Duration
	EnableReplayTracking      bool
	Warn                      func(string, ...any)
	SessionStore              RefreshSessionStore
	RefreshHashMismatch       error
	RedisNil                  error

	// RoleRecheck, when non-nil, confirms the session's role is still held
	// before the refresh token is rotated.
	RoleRecheck *RefreshRoleRecheck
}

type replayTracker interface {
	TrackReplayAnomaly(ctx context.Context, sessionID string, ttl time.Duration) error
}

// trackRefreshReuse records a replay anomaly for a reused refresh token when
// replay tracking is on. Refresh and role switching share it so both treat
// reuse identically.
func trackRefreshReuse(
	ctx context.Context,
	store replayTracker,
	enabled bool,
	sessionID string,
	lifetime func() time.Duration,
	warn func(string, ...any),
) {
	if !enabled {
		return
	}
	if err := store.TrackReplayAnomaly(ctx, sessionID, lifetime()); err != nil && warn != nil {
		warn("goAuth: replay anomaly tracking failed")
	}
}

// runRefreshRoleRecheck reads the session without mutating it and, only if
// it exists, is unexpired and the presented token matches its current
// secret, asks the provider whether the session's role is still held. Every
// other case reports "no decision" so the normal rotation runs unchanged and
// reuse detection and deletion behave exactly as without the re-check.
func runRefreshRoleRecheck(
	ctx context.Context,
	tenantID, sessionID string,
	providedHash [32]byte,
	deps RefreshDeps,
) (RefreshResult, bool) {
	rc := deps.RoleRecheck
	sess, err := rc.Peek(ctx, tenantID, sessionID)
	if err != nil || sess == nil {
		return RefreshResult{}, false
	}
	if sess.ExpiresAt <= rc.Now().Unix() {
		return RefreshResult{}, false
	}
	if subtle.ConstantTimeCompare(sess.RefreshHash[:], providedHash[:]) != 1 {
		return RefreshResult{}, false
	}

	held, err := rc.CanAssumeRole(ctx, sess.TenantID, sess.UserID, sess.Role)
	if err != nil {
		return RefreshResult{
			Failure:   RefreshFailureRoleCheck,
			Err:       err,
			TenantID:  sess.TenantID,
			SessionID: sessionID,
			UserID:    sess.UserID,
			Session:   sess,
		}, true
	}
	if held {
		return RefreshResult{}, false
	}
	_ = deps.SessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
	return RefreshResult{
		Failure:   RefreshFailureRoleRevoked,
		TenantID:  sess.TenantID,
		SessionID: sessionID,
		UserID:    sess.UserID,
		Session:   sess,
	}, true
}

// RunRefresh executes refresh rotation and issuance logic without root package dependencies.
func RunRefresh(ctx context.Context, refreshToken string, deps RefreshDeps) RefreshResult {
	tenantID := deps.TenantIDFromContext(ctx)
	sessionID, providedSecret, err := deps.DecodeRefreshToken(refreshToken)
	if err != nil {
		return RefreshResult{
			Failure:  RefreshFailureDecode,
			Err:      err,
			TenantID: tenantID,
		}
	}

	if deps.RoleRecheck != nil {
		if result, decided := runRefreshRoleRecheck(ctx, tenantID, sessionID, deps.HashRefreshSecret(providedSecret), deps); decided {
			return result
		}
	}

	nextSecret, err := deps.NewRefreshSecret()
	if err != nil {
		return RefreshResult{
			Failure:   RefreshFailureNextSecret,
			Err:       err,
			TenantID:  tenantID,
			SessionID: sessionID,
		}
	}

	sess, err := deps.SessionStore.RotateRefreshHash(
		ctx,
		tenantID,
		sessionID,
		deps.HashRefreshSecret(providedSecret),
		deps.HashRefreshSecret(nextSecret),
	)
	if err != nil {
		switch {
		case deps.RefreshHashMismatch != nil && errors.Is(err, deps.RefreshHashMismatch):
			trackRefreshReuse(ctx, deps.SessionStore, deps.EnableReplayTracking, sessionID, deps.SessionLifetime, deps.Warn)
			return RefreshResult{
				Failure:   RefreshFailureReuse,
				Err:       err,
				TenantID:  tenantID,
				SessionID: sessionID,
			}
		case deps.RedisNil != nil && errors.Is(err, deps.RedisNil):
			return RefreshResult{
				Failure:   RefreshFailureSessionNotFound,
				Err:       err,
				TenantID:  tenantID,
				SessionID: sessionID,
			}
		default:
			return RefreshResult{
				Failure:   RefreshFailureRotate,
				Err:       err,
				TenantID:  tenantID,
				SessionID: sessionID,
			}
		}
	}

	if statusErr := deps.AccountStatusError(sess.Status); statusErr != nil {
		_ = deps.SessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		return RefreshResult{
			Failure:   RefreshFailureAccountStatus,
			Err:       statusErr,
			TenantID:  sess.TenantID,
			SessionID: sess.SessionID,
			UserID:    sess.UserID,
			Session:   sess,
		}
	}
	if deps.ShouldRequireVerified != nil &&
		deps.ShouldRequireVerified() &&
		sess.Status == deps.PendingVerificationStatus {
		_ = deps.SessionStore.Delete(ctx, sess.TenantID, sess.SessionID)
		return RefreshResult{
			Failure:   RefreshFailureUnverified,
			Err:       errors.New("pending_verification"),
			TenantID:  sess.TenantID,
			SessionID: sess.SessionID,
			UserID:    sess.UserID,
			Session:   sess,
		}
	}

	access, err := deps.IssueAccessToken(sess)
	if err != nil {
		return RefreshResult{
			Failure:   RefreshFailureIssueAccess,
			Err:       err,
			TenantID:  sess.TenantID,
			SessionID: sess.SessionID,
			UserID:    sess.UserID,
			Session:   sess,
		}
	}

	refresh, err := deps.EncodeRefreshToken(sess.SessionID, nextSecret)
	if err != nil {
		return RefreshResult{
			Failure:   RefreshFailureEncode,
			Err:       err,
			TenantID:  sess.TenantID,
			SessionID: sess.SessionID,
			UserID:    sess.UserID,
			Session:   sess,
		}
	}

	return RefreshResult{
		Failure:      RefreshFailureNone,
		TenantID:     sess.TenantID,
		SessionID:    sess.SessionID,
		UserID:       sess.UserID,
		Session:      sess,
		AccessToken:  access,
		RefreshToken: refresh,
	}
}
