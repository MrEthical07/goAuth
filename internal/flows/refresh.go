package flows

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// RefreshFailureKind classifies refresh flow failures for root-level mapping.
type RefreshFailureKind int

const (
	RefreshFailureNone RefreshFailureKind = iota
	RefreshFailureDecode
	RefreshFailureRateLimited
	RefreshFailureNextSecret
	RefreshFailureReuse
	RefreshFailureSessionNotFound
	RefreshFailureRotate
	RefreshFailureAccountStatus
	RefreshFailureUnverified
	RefreshFailureIssueAccess
	RefreshFailureEncode
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

type RefreshRateLimiter interface {
	CheckRefresh(ctx context.Context, sessionID string) error
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
	RateLimiter               RefreshRateLimiter
	SessionStore              RefreshSessionStore
	RefreshHashMismatch       error
	RedisNil                  error
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

	if deps.RateLimiter != nil {
		if err := deps.RateLimiter.CheckRefresh(ctx, sessionID); err != nil {
			return RefreshResult{
				Failure:   RefreshFailureRateLimited,
				Err:       err,
				TenantID:  tenantID,
				SessionID: sessionID,
			}
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
			if deps.EnableReplayTracking {
				if trackErr := deps.SessionStore.TrackReplayAnomaly(ctx, sessionID, deps.SessionLifetime()); trackErr != nil && deps.Warn != nil {
					deps.Warn("goAuth: replay anomaly tracking failed")
				}
			}
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
