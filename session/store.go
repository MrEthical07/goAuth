package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrRefreshHashMismatch is an exported constant or variable used by the authentication engine.
var ErrRefreshHashMismatch = errors.New("refresh hash mismatch")

// ErrRedisUnavailable is an exported constant or variable used by the authentication engine.
var ErrRedisUnavailable = errors.New("redis unavailable")

const minSlidingTTL = time.Second

// Store defines a public type used by goAuth APIs.
//
// Store instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Store struct {
	redis         *redis.Client
	prefix        string
	sliding       bool
	jitterEnabled bool
	jitterRange   time.Duration
}

// NewStore describes the newstore operation and its observable behavior.
//
// NewStore may return an error when input validation, dependency calls, or security checks fail.
// NewStore does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewStore(
	redis *redis.Client,
	prefix string,
	sliding bool,
	jitterEnabled bool,
	jitterRange time.Duration,
) *Store {
	return &Store{
		redis:         redis,
		prefix:        prefix,
		sliding:       sliding,
		jitterEnabled: jitterEnabled,
		jitterRange:   jitterRange,
	}
}

func (s *Store) key(tenantID, sessionID string) string {
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":" + sessionID
}

func (s *Store) userKey(tenantID, userID string) string {
	return "au:" + normalizeTenantID(tenantID) + ":" + userID
}

func (s *Store) tenantCountKey(tenantID string) string {
	return "ast:" + normalizeTenantID(tenantID) + ":count"
}

func (s *Store) replayKey(sessionID string) string {
	return "arp:" + sessionID
}

func (s *Store) deviceAnomalyKey(sessionID, kind string) string {
	return "ada:" + sessionID + ":" + kind
}

func normalizeTenantID(tenantID string) string {
	if tenantID == "" {
		return "0"
	}
	return tenantID
}

// Save describes the save operation and its observable behavior.
//
// Save may return an error when input validation, dependency calls, or security checks fail.
// Save does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *Store) Save(ctx context.Context, sess *Session, ttl time.Duration) error {
	data, err := Encode(sess)
	if err != nil {
		return err
	}

	sessionKey := s.key(sess.TenantID, sess.SessionID)
	userKey := s.userKey(sess.TenantID, sess.UserID)
	countKey := s.tenantCountKey(sess.TenantID)

	_, err = s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, sessionKey, data, ttl)
		pipe.SAdd(ctx, userKey, sess.SessionID)
		pipe.Incr(ctx, countKey)
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// Get describes the get operation and its observable behavior.
//
// Get may return an error when input validation, dependency calls, or security checks fail.
// Get does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *Store) Get(ctx context.Context, tenantID, sessionID string, ttl time.Duration) (*Session, error) {
	key := s.key(tenantID, sessionID)

	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return nil, err
	}
	sess.SessionID = sessionID

	now := time.Now()
	remainingAbsolute := s.remainingAbsoluteTTL(sess, ttl, now)
	if remainingAbsolute <= 0 {
		if err := s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sessionID); err != nil {
			return nil, err
		}
		return nil, redis.Nil
	}

	if s.sliding {
		nextTTL, err := s.nextSlidingTTL(remainingAbsolute)
		if err != nil {
			return nil, err
		}

		if err := s.redis.Expire(ctx, key, nextTTL).Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}

	return sess, nil
}

// Delete describes the delete operation and its observable behavior.
//
// Delete may return an error when input validation, dependency calls, or security checks fail.
// Delete does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *Store) Delete(ctx context.Context, tenantID, sessionID string) error {
	key := s.key(tenantID, sessionID)

	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return err
	}

	return s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sessionID)
}

// DeleteAllForUser describes the deleteallforuser operation and its observable behavior.
//
// DeleteAllForUser may return an error when input validation, dependency calls, or security checks fail.
// DeleteAllForUser does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *Store) DeleteAllForUser(ctx context.Context, tenantID, userID string) error {
	userKey := s.userKey(tenantID, userID)
	countKey := s.tenantCountKey(tenantID)

	sessionIDs, err := s.redis.SMembers(ctx, userKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sessionKeys := make([]string, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		sessionKeys = append(sessionKeys, s.key(tenantID, sessionID))
	}

	currentCount, err := s.TenantSessionCount(ctx, tenantID)
	if err != nil {
		return err
	}

	var existing int
	if len(sessionKeys) > 0 {
		pipe := s.redis.Pipeline()
		existsCmds := make([]*redis.IntCmd, len(sessionKeys))
		for i, sessionKey := range sessionKeys {
			existsCmds[i] = pipe.Exists(ctx, sessionKey)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		for _, cmd := range existsCmds {
			v, cmdErr := cmd.Result()
			if cmdErr != nil {
				return fmt.Errorf("%w: %v", ErrRedisUnavailable, cmdErr)
			}
			existing += int(v)
		}
	}

	decrement := existing
	if decrement > currentCount {
		decrement = currentCount
	}

	_, err = s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		if len(sessionKeys) > 0 {
			pipe.Del(ctx, sessionKeys...)
		}
		pipe.Del(ctx, userKey)
		if decrement > 0 {
			pipe.DecrBy(ctx, countKey, int64(decrement))
		}
		if decrement == currentCount && currentCount > 0 {
			pipe.Del(ctx, countKey)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// TenantSessionCount returns the tracked tenant-wide session counter.
func (s *Store) TenantSessionCount(ctx context.Context, tenantID string) (int, error) {
	count, err := s.redis.Get(ctx, s.tenantCountKey(tenantID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count < 0 {
		return 0, nil
	}
	return int(count), nil
}

// SetTenantSessionCount sets (or clears) the tracked tenant session counter.
func (s *Store) SetTenantSessionCount(ctx context.Context, tenantID string, count int) error {
	key := s.tenantCountKey(tenantID)
	if count <= 0 {
		if err := s.redis.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		return nil
	}

	if err := s.redis.Set(ctx, key, count, 0).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

// ActiveSessionCount returns the number of tracked session IDs for a user in a tenant.
func (s *Store) ActiveSessionCount(ctx context.Context, tenantID, userID string) (int, error) {
	count, err := s.redis.SCard(ctx, s.userKey(tenantID, userID)).Result()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return int(count), nil
}

// ActiveSessionIDs returns tracked session IDs for a user in a tenant.
func (s *Store) ActiveSessionIDs(ctx context.Context, tenantID, userID string) ([]string, error) {
	ids, err := s.redis.SMembers(ctx, s.userKey(tenantID, userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return ids, nil
}

// GetReadOnly fetches a session without mutating TTL, index, or any Redis state.
func (s *Store) GetReadOnly(ctx context.Context, tenantID, sessionID string) (*Session, error) {
	data, err := s.redis.Get(ctx, s.key(tenantID, sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return nil, err
	}
	sess.SessionID = sessionID
	if time.Now().Unix() > sess.ExpiresAt {
		return nil, redis.Nil
	}

	return sess, nil
}

// GetManyReadOnly fetches multiple sessions without mutating Redis state.
func (s *Store) GetManyReadOnly(ctx context.Context, tenantID string, sessionIDs []string) ([]*Session, error) {
	if len(sessionIDs) == 0 {
		return []*Session{}, nil
	}

	pipe := s.redis.Pipeline()
	cmds := make([]*redis.StringCmd, len(sessionIDs))
	for i, sid := range sessionIDs {
		cmds[i] = pipe.Get(ctx, s.key(tenantID, sid))
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sessions := make([]*Session, 0, len(sessionIDs))
	nowUnix := time.Now().Unix()
	for i, cmd := range cmds {
		data, cmdErr := cmd.Bytes()
		if cmdErr != nil {
			if errors.Is(cmdErr, redis.Nil) {
				continue
			}
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, cmdErr)
		}

		sess, decErr := Decode(data)
		if decErr != nil {
			return nil, decErr
		}
		sess.SessionID = sessionIDs[i]
		if nowUnix > sess.ExpiresAt {
			continue
		}

		sessions = append(sessions, sess)
	}

	return sessions, nil
}

// EstimateActiveSessions scans tenant session keys and counts matches.
// This is an admin-only O(n) operation and must not be used in request hot paths.
func (s *Store) EstimateActiveSessions(ctx context.Context, tenantID string) (int, error) {
	pattern := s.prefix + ":" + normalizeTenantID(tenantID) + ":*"
	var (
		cursor uint64
		total  int
	)

	for {
		keys, next, err := s.redis.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		total += len(keys)
		cursor = next
		if cursor == 0 {
			break
		}
	}

	return total, nil
}

// Ping returns a point-in-time Redis availability check and latency.
func (s *Store) Ping(ctx context.Context) (time.Duration, error) {
	opts := *s.redis.Options()
	opts.MaxRetries = 0
	opts.MinRetryBackoff = -1
	opts.MaxRetryBackoff = -1
	opts.PoolSize = 1
	opts.MinIdleConns = 0

	probe := redis.NewClient(&opts)
	defer probe.Close()

	start := time.Now()
	if err := probe.Ping(ctx).Err(); err != nil {
		return time.Since(start), fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return time.Since(start), nil
}

// TrackReplayAnomaly increments replay anomaly counter for a session ID.
func (s *Store) TrackReplayAnomaly(ctx context.Context, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	key := s.replayKey(sessionID)
	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}
	return nil
}

// ShouldEmitDeviceAnomaly returns true only for the first anomaly in the window per session/kind.
func (s *Store) ShouldEmitDeviceAnomaly(ctx context.Context, sessionID, kind string, window time.Duration) (bool, error) {
	if window <= 0 {
		window = time.Minute
	}
	key := s.deviceAnomalyKey(sessionID, kind)

	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, key, window).Err(); err != nil {
			return false, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		return true, nil
	}

	return false, nil
}

func (s *Store) remainingAbsoluteTTL(sess *Session, absoluteLifetime time.Duration, now time.Time) time.Duration {
	storedExpiry := time.Unix(sess.ExpiresAt, 0)
	if absoluteLifetime <= 0 {
		return storedExpiry.Sub(now)
	}

	configCap := time.Unix(sess.CreatedAt, 0).Add(absoluteLifetime)
	if configCap.Before(storedExpiry) {
		return configCap.Sub(now)
	}

	return storedExpiry.Sub(now)
}

func (s *Store) nextSlidingTTL(remainingAbsolute time.Duration) (time.Duration, error) {
	nextTTL := remainingAbsolute

	if s.jitterEnabled && s.jitterRange > 0 {
		jitter, err := randomJitter(s.jitterRange)
		if err != nil {
			return 0, err
		}
		nextTTL += jitter
	}

	if nextTTL > remainingAbsolute {
		nextTTL = remainingAbsolute
	}

	minTTL := minSlidingTTL
	if remainingAbsolute < minTTL {
		minTTL = remainingAbsolute
	}
	if nextTTL < minTTL {
		nextTTL = minTTL
	}

	return nextTTL, nil
}

func randomJitter(jitterRange time.Duration) (time.Duration, error) {
	if jitterRange <= 0 {
		return 0, nil
	}

	max := jitterRange.Nanoseconds()
	if max > (math.MaxInt64-1)/2 {
		return 0, errors.New("jitter range too large")
	}
	span := max*2 + 1

	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, err
	}

	return time.Duration(n.Int64() - max), nil
}

// RotateRefreshHash describes the rotaterefreshhash operation and its observable behavior.
//
// RotateRefreshHash may return an error when input validation, dependency calls, or security checks fail.
// RotateRefreshHash does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *Store) RotateRefreshHash(
	ctx context.Context,
	tenantID, sessionID string,
	providedHash [32]byte,
	nextHash [32]byte,
) (*Session, error) {
	key := s.key(tenantID, sessionID)
	var updated *Session

	err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, key).Bytes()
		if err != nil {
			return err
		}

		sess, err := Decode(data)
		if err != nil {
			return err
		}
		sess.SessionID = sessionID

		userKey := s.userKey(sess.TenantID, sess.UserID)

		if time.Now().Unix() > sess.ExpiresAt {
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, key)
				pipe.SRem(ctx, userKey, sessionID)
				pipe.Decr(ctx, s.tenantCountKey(sess.TenantID))
				return nil
			})
			if err != nil {
				return err
			}
			return redis.Nil
		}

		if subtle.ConstantTimeCompare(sess.RefreshHash[:], providedHash[:]) != 1 {
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, key)
				pipe.SRem(ctx, userKey, sessionID)
				pipe.Decr(ctx, s.tenantCountKey(sess.TenantID))
				return nil
			})
			if err != nil {
				return err
			}
			return ErrRefreshHashMismatch
		}

		sess.RefreshHash = nextHash
		ttl := time.Until(time.Unix(sess.ExpiresAt, 0))
		if ttl <= 0 {
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, key)
				pipe.SRem(ctx, userKey, sessionID)
				pipe.Decr(ctx, s.tenantCountKey(sess.TenantID))
				return nil
			})
			if err != nil {
				return err
			}
			return redis.Nil
		}

		encoded, err := Encode(sess)
		if err != nil {
			return err
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, encoded, ttl)
			pipe.SAdd(ctx, userKey, sessionID)
			return nil
		})
		if err != nil {
			return err
		}

		updated = sess
		return nil
	}, key)

	if err != nil {
		if errors.Is(err, redis.Nil) || errors.Is(err, ErrRefreshHashMismatch) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return updated, nil
}

func (s *Store) deleteSessionAndIndex(ctx context.Context, tenantID, userID, sessionID string) error {
	key := s.key(tenantID, sessionID)
	userKey := s.userKey(tenantID, userID)
	countKey := s.tenantCountKey(tenantID)

	_, err := s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, key)
		pipe.SRem(ctx, userKey, sessionID)
		pipe.Decr(ctx, countKey)
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}
