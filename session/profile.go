package session

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// UnboundedExpiresAt is the ExpiresAt stored for a session whose profile has
// no absolute ceiling (31 Dec 9999 23:59:59 UTC). It is a sentinel, not a
// date: such a session ends by inactivity, logout or revocation. It is far
// enough away that no expiry comparison ever trips on it, yet small enough
// that millisecond arithmetic on it stays exact.
const UnboundedExpiresAt int64 = 253402300799

// ErrProfileUnknown reports that a session names a profile the current
// configuration no longer defines. The session has been deleted.
var ErrProfileUnknown = errors.New("session profile unknown")

// profileEndError is the concrete error behind [ErrProfileUnknown] and
// [ErrSessionExpired]: it carries the profile of the session that ended, for
// the audit trail.
type profileEndError struct {
	name   string
	reason error
}

func (e *profileEndError) Error() string { return e.reason.Error() + ": " + e.name }

// Is makes errors.Is(err, ErrProfileUnknown) and errors.Is(err,
// ErrSessionExpired) hold for the errors that report those outcomes.
func (e *profileEndError) Is(target error) bool { return target == e.reason }

// EndedProfileName returns the profile of the session that ended with err
// (an unknown profile or a passed ceiling), or "" when err reports neither.
func EndedProfileName(err error) string {
	var end *profileEndError
	if errors.As(err, &end) {
		return end.name
	}
	return ""
}

// ErrSessionExpired reports that a profile session reached its effective
// ceiling. The session has been deleted. It is always joined with
// redis.Nil, so callers that only test for "not found" are unaffected.
var ErrSessionExpired = errors.New("session expired")

// ProfilePolicy is the store's view of a session profile: how long a session
// may sit idle and how long it may live in all.
type ProfilePolicy struct {
	// IdleTimeout > 0 makes the profile renewing: a refresh, a role switch
	// or (with RenewOnUse) a strict read restarts this window. Zero means a
	// fixed profile, whose key lifetime never moves.
	IdleTimeout time.Duration
	// AbsoluteLifetime is the ceiling measured from CreatedAt. Zero means the
	// profile is unbounded; ExpiresAt is then UnboundedExpiresAt.
	AbsoluteLifetime time.Duration
	// RenewOnUse also renews the idle window on strict reads.
	RenewOnUse bool
}

// Renewing reports whether the profile has an idle window.
func (p ProfilePolicy) Renewing() bool { return p.IdleTimeout > 0 }

// ceilingMs is the effective ceiling of sess in unix milliseconds: the lower
// of the ceiling stored at creation and CreatedAt plus the profile's
// current AbsoluteLifetime. Shortening a profile therefore shortens sessions
// already issued; lengthening it can never push a stored ExpiresAt out.
func (p ProfilePolicy) ceilingMs(createdAt, expiresAt int64) int64 {
	ceiling := expiresAt * 1000
	if abs := p.AbsoluteLifetime.Milliseconds(); abs > 0 {
		if limit := createdAt*1000 + abs; limit < ceiling {
			ceiling = limit
		}
	}
	return ceiling
}

// clampIdle returns the key lifetime for a renewing profile: the idle window
// plus jitter, never longer than what is left before the ceiling and never
// shorter than a second (or than what is left, if that is less). Lua repeats
// this arithmetic in rotateRefreshScript and swapSessionScript.
func clampIdle(idle, jitter time.Duration, remaining time.Duration, bounded bool) time.Duration {
	ttl := idle + jitter
	if bounded && ttl > remaining {
		ttl = remaining
	}
	floor := minSlidingTTL
	if bounded && remaining < floor {
		floor = remaining
	}
	if ttl < floor {
		ttl = floor
	}
	return ttl
}

// profileTable is the immutable set of profile policies a store resolves
// against, with its encoding for the Lua scripts computed once.
type profileTable struct {
	byName map[string]ProfilePolicy
	arg    string
}

// policy looks a profile up; a store without a table knows none.
func (s *Store) policy(name string) (ProfilePolicy, bool) {
	if s.profiles == nil {
		return ProfilePolicy{}, false
	}
	p, ok := s.profiles.byName[name]
	return p, ok
}

// profileArg is the table's ARGV encoding, empty when no profiles are set.
func (s *Store) profileArg() string {
	if s.profiles == nil {
		return ""
	}
	return s.profiles.arg
}

// WithProfiles installs the profile table. It must be called before the store
// is shared; the table is copied, so later changes to profiles have no effect.
// A store without a table treats every profile session as belonging to an
// unknown profile.
func (s *Store) WithProfiles(profiles map[string]ProfilePolicy) *Store {
	if len(profiles) == 0 {
		s.profiles = nil
		return s
	}
	table := &profileTable{byName: make(map[string]ProfilePolicy, len(profiles))}
	for name, p := range profiles {
		table.byName[name] = p
	}
	table.arg = encodeProfileTable(table.byName)
	s.profiles = table
	return s
}

// HasProfiles reports whether a profile table is installed.
func (s *Store) HasProfiles() bool { return s.profiles != nil }

// Profile returns the policy of a named profile.
func (s *Store) Profile(name string) (ProfilePolicy, bool) {
	return s.policy(name)
}

// encodeProfileTable renders the profile table as the ARGV string the Lua
// scripts parse: entries separated by ';', each name:idle_ms:abs_ms:renew
// (renew is 0 or 1; abs_ms is 0 for an unbounded profile). Names are limited
// to [a-z0-9_-], so neither separator can occur in one. Entries are sorted so
// the encoding is deterministic.
func encodeProfileTable(profiles map[string]ProfilePolicy) string {
	if len(profiles) == 0 {
		return ""
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for i, name := range names {
		p := profiles[name]
		renew := 0
		if p.RenewOnUse {
			renew = 1
		}
		if i > 0 {
			b.WriteByte(';')
		}
		fmt.Fprintf(&b, "%s:%d:%d:%d", name, p.IdleTimeout.Milliseconds(), p.AbsoluteLifetime.Milliseconds(), renew)
	}
	return b.String()
}

// jitter returns the random offset to apply to an idle window, or zero when
// jitter is off. It is computed here and handed to Lua so the scripts stay
// deterministic.
func (s *Store) jitter() (time.Duration, error) {
	if s.jitterEnabled && s.jitterRange > 0 {
		return randomJitter(s.jitterRange)
	}
	return 0, nil
}

// NewSessionLifetime returns what a session created now under the named
// profile receives: the ExpiresAt to record and the TTL to store the key
// with. A fixed profile's key lives exactly AbsoluteLifetime; a renewing
// profile's lives one idle window (with jitter), never past the ceiling.
// It returns [ErrProfileUnknown] for a name the store does not define.
func (s *Store) NewSessionLifetime(name string, now time.Time) (expiresAt int64, ttl time.Duration, err error) {
	p, ok := s.policy(name)
	if !ok {
		return 0, 0, ErrProfileUnknown
	}

	bounded := p.AbsoluteLifetime > 0
	expiresAt = UnboundedExpiresAt
	if bounded {
		expiresAt = now.Add(p.AbsoluteLifetime).Unix()
	}
	if !p.Renewing() {
		return expiresAt, p.AbsoluteLifetime, nil
	}

	jitter, err := s.jitter()
	if err != nil {
		return 0, 0, err
	}
	return expiresAt, clampIdle(p.IdleTimeout, jitter, p.AbsoluteLifetime, bounded), nil
}

// getProfiled is the strict-read path for a v6 session. It never applies the
// legacy "TTL = remaining absolute lifetime" reset, which would cancel the
// idle window: a fixed or non-RenewOnUse session keeps its key lifetime
// untouched, and a RenewOnUse session gets a fresh idle window.
func (s *Store) getProfiled(ctx context.Context, key string, sess *Session, now time.Time) (*Session, error) {
	policy, ok := s.policy(sess.Profile)
	if !ok {
		if err := s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sess.SessionID); err != nil {
			return nil, err
		}
		return nil, errors.Join(redis.Nil, &profileEndError{name: sess.Profile, reason: ErrProfileUnknown})
	}

	remainingMs := policy.ceilingMs(sess.CreatedAt, sess.ExpiresAt) - now.UnixMilli()
	if remainingMs <= 0 {
		if err := s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sess.SessionID); err != nil {
			return nil, err
		}
		return nil, errors.Join(redis.Nil, &profileEndError{name: sess.Profile, reason: ErrSessionExpired})
	}

	if policy.RenewOnUse && policy.Renewing() {
		jitter, err := s.jitter()
		if err != nil {
			return nil, err
		}
		remaining := time.Duration(remainingMs) * time.Millisecond
		bounded := policy.AbsoluteLifetime > 0
		ttl := clampIdle(policy.IdleTimeout, jitter, remaining, bounded)
		if err := s.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}
	return sess, nil
}

// profileLive reports whether a profile session would still be accepted:
// its profile is defined and its effective ceiling has not passed. It is the
// read-only counterpart of getProfiled and changes nothing.
func (s *Store) profileLive(sess *Session, now time.Time) (ProfilePolicy, bool) {
	policy, ok := s.policy(sess.Profile)
	if !ok {
		return ProfilePolicy{}, false
	}
	return policy, policy.ceilingMs(sess.CreatedAt, sess.ExpiresAt) > now.UnixMilli()
}

// idleExpiry converts a key's remaining lifetime into the unix time a
// renewing session lapses, or zero when it has none.
func idleExpiry(now time.Time, pttl time.Duration) int64 {
	if pttl <= 0 {
		return 0
	}
	return now.Add(pttl).Unix()
}

// fillIdleExpiry sets sess.IdleExpiresAt from the key's PTTL when sess is a
// renewing profile session.
func (s *Store) fillIdleExpiry(ctx context.Context, key string, sess *Session, policy ProfilePolicy, now time.Time) error {
	if !policy.Renewing() {
		return nil
	}
	pttl, err := s.redis.PTTL(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	sess.IdleExpiresAt = idleExpiry(now, pttl)
	return nil
}

// profileScriptArgs returns the extra script arguments that carry the
// profile table, a fresh jitter and the millisecond clock to the Lua
// scripts, or nil when no profiles are configured (the arguments, and so the
// commands sent to Redis, are then exactly the legacy ones).
func (s *Store) profileScriptArgs(now time.Time) ([]interface{}, error) {
	arg := s.profileArg()
	if arg == "" {
		return nil, nil
	}
	jitter, err := s.jitter()
	if err != nil {
		return nil, err
	}
	return []interface{}{arg, strconv.FormatInt(jitter.Milliseconds(), 10), now.UnixMilli()}, nil
}
