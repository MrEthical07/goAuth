// Package window provides the shared rate-limit window primitive used by
// every limiter domain (internal/rate and internal/limiters). It implements
// two counting algorithms behind one interface:
//
//   - Fixed: classic fixed-window counter. INCR plus a first-hit PEXPIRE,
//     executed as a single Lua script so a crash between the two commands can
//     never leave an orphaned counter without a TTL.
//   - Sliding: weighted two-bucket sliding-window approximation. Counts are
//     kept in per-bucket keys (bucket length = the window) and the effective
//     count is curr + floor(prev * (window-elapsed)/window), removing the
//     fixed-window 2x boundary-burst weakness with O(1) memory per key.
//
// Bucket indexes are computed from the client clock (injectable for tests);
// hosts are expected to be NTP-synced. Sliding bucket keys are hash-tagged
// ("{base}:s:<bucket>") so both buckets always share a Redis Cluster slot.
package window

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Mode selects the window-counting algorithm. The zero value is Fixed so
// existing call sites keep their behavior.
type Mode int

const (
	// Fixed is the classic fixed-window counter (default).
	Fixed Mode = iota
	// Sliding is the weighted two-bucket sliding-window approximation.
	Sliding
)

// fixedIncrScript atomically increments a fixed-window counter and pins its
// TTL on the first hit of the window.
var fixedIncrScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// slidingScript increments (ARGV[2] == "1") or reads the two-bucket sliding
// counter and returns the weighted count. KEYS[1] = current bucket,
// KEYS[2] = previous bucket, ARGV[1] = window ms, ARGV[3] = elapsed ms into
// the current bucket.
var slidingScript = redis.NewScript(`
local window = tonumber(ARGV[1])
local curr
if ARGV[2] == '1' then
  curr = redis.call('INCR', KEYS[1])
  if curr == 1 then
    redis.call('PEXPIRE', KEYS[1], window * 2)
  end
else
  curr = tonumber(redis.call('GET', KEYS[1])) or 0
end
local prev = tonumber(redis.call('GET', KEYS[2])) or 0
local elapsed = tonumber(ARGV[3])
return curr + math.floor(prev * (window - elapsed) / window)
`)

// fixedReserveScript claims one slot of a fixed-window counter only while the
// counter is below the limit. KEYS[1] = counter, ARGV[1] = limit, ARGV[2] =
// window ms (0 = no expiry). It returns {1, count} when the slot was claimed
// and {0, count} when the counter was already at the limit; a refused claim
// leaves the counter untouched, so a flood of refused attempts never extends
// or grows the state.
var fixedReserveScript = redis.NewScript(`
local c = tonumber(redis.call('GET', KEYS[1])) or 0
if c >= tonumber(ARGV[1]) then
  return {0, c}
end
c = redis.call('INCR', KEYS[1])
if c == 1 and tonumber(ARGV[2]) > 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return {1, c}
`)

// slidingReserveScript is fixedReserveScript for the two-bucket sliding
// counter. KEYS[1] = current bucket, KEYS[2] = previous bucket, ARGV[1] =
// window ms, ARGV[2] = limit, ARGV[3] = elapsed ms into the current bucket.
// The returned count is the weighted count after the claim (or the weighted
// count that caused the refusal).
var slidingReserveScript = redis.NewScript(`
local window = tonumber(ARGV[1])
local curr = tonumber(redis.call('GET', KEYS[1])) or 0
local prev = tonumber(redis.call('GET', KEYS[2])) or 0
local elapsed = tonumber(ARGV[3])
local weighted = curr + math.floor(prev * (window - elapsed) / window)
if weighted >= tonumber(ARGV[2]) then
  return {0, weighted}
end
curr = redis.call('INCR', KEYS[1])
if curr == 1 then
  redis.call('PEXPIRE', KEYS[1], window * 2)
end
return {1, weighted + 1}
`)

// releaseScript gives back one claimed slot of a counter without ever taking
// it below zero. It leaves the TTL alone.
var releaseScript = redis.NewScript(`
local c = tonumber(redis.call('GET', KEYS[1])) or 0
if c > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
`)

// Window counts events per key using the configured algorithm.
type Window struct {
	redis redis.UniversalClient
	mode  Mode
	now   func() time.Time
}

// New creates a window counter over the given Redis client.
func New(rdb redis.UniversalClient, mode Mode) *Window {
	return &Window{redis: rdb, mode: mode, now: time.Now}
}

// NewWithClock is New with a time source for the sliding window's bucket
// arithmetic; a nil now is the wall clock. Counter key lifetimes are always
// Redis's own time.
func NewWithClock(rdb redis.UniversalClient, mode Mode, now func() time.Time) *Window {
	w := New(rdb, mode)
	if now != nil {
		w.now = now
	}
	return w
}

// Incr records one event for key and returns the effective count within the
// window. A non-positive window means "no expiry": a plain INCR regardless of
// mode (used by the lockout limiter's manual-unlock configuration).
func (w *Window) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	if window <= 0 {
		return w.redis.Incr(ctx, key).Result()
	}
	if w.mode == Sliding {
		return w.runSliding(ctx, key, window, true)
	}
	return fixedIncrScript.Run(ctx, w.redis, []string{key}, window.Milliseconds()).Int64()
}

// Reserve atomically claims one slot for key before the guarded work runs:
// it succeeds (ok == true) only while the effective count is below limit, and
// a refused claim changes nothing. A check-then-record sequence lets every
// concurrent caller observe a count below the limit before any of them
// records an attempt; claiming the slot first in one script bounds the work
// that can run per window to limit, whatever the concurrency. The returned
// count is the effective count after the claim (or the count that caused the
// refusal). A non-positive window means "no expiry", as for Incr.
func (w *Window) Reserve(ctx context.Context, key string, window time.Duration, limit int64) (count int64, ok bool, err error) {
	var res []int64
	if w.mode == Sliding && window > 0 {
		windowMs := window.Milliseconds()
		nowMs := w.now().UnixMilli()
		curr, prev := slidingBucketKeys(key, nowMs/windowMs)
		res, err = slidingReserveScript.Run(ctx, w.redis,
			[]string{curr, prev},
			windowMs, limit, nowMs%windowMs,
		).Int64Slice()
	} else {
		res, err = fixedReserveScript.Run(ctx, w.redis, []string{key}, limit, window.Milliseconds()).Int64Slice()
	}
	if err != nil {
		return 0, false, err
	}
	if len(res) != 2 {
		return 0, false, errors.New("window: malformed reserve reply")
	}
	return res[1], res[0] == 1, nil
}

// Release gives back one slot claimed with Reserve, for an attempt that
// turned out not to be a guess (the work was refused for another reason, or it
// succeeded and the state is being unwound). It never takes a counter below
// zero and does not touch its TTL.
func (w *Window) Release(ctx context.Context, key string, window time.Duration) error {
	if w.mode == Sliding && window > 0 {
		curr, _ := w.bucketKeys(key, window)
		return releaseScript.Run(ctx, w.redis, []string{curr}).Err()
	}
	return releaseScript.Run(ctx, w.redis, []string{key}).Err()
}

// Count returns the current effective count for key without incrementing.
// Missing keys count as zero.
func (w *Window) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	if w.mode == Sliding && window > 0 {
		return w.runSliding(ctx, key, window, false)
	}
	count, err := w.redis.Get(ctx, key).Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

// Reset clears all window state for key.
func (w *Window) Reset(ctx context.Context, key string, window time.Duration) error {
	if w.mode == Sliding && window > 0 {
		curr, prev := w.bucketKeys(key, window)
		return w.redis.Del(ctx, curr, prev).Err()
	}
	return w.redis.Del(ctx, key).Err()
}

func (w *Window) runSliding(ctx context.Context, key string, window time.Duration, incr bool) (int64, error) {
	// Read the clock once so the bucket keys and the elapsed offset always
	// describe the same instant.
	windowMs := window.Milliseconds()
	nowMs := w.now().UnixMilli()
	curr, prev := slidingBucketKeys(key, nowMs/windowMs)
	incrArg := "0"
	if incr {
		incrArg = "1"
	}
	return slidingScript.Run(ctx, w.redis,
		[]string{curr, prev},
		windowMs, incrArg, nowMs%windowMs,
	).Int64()
}

func (w *Window) bucketKeys(key string, window time.Duration) (curr, prev string) {
	return slidingBucketKeys(key, w.now().UnixMilli()/window.Milliseconds())
}

func slidingBucketKeys(key string, bucket int64) (curr, prev string) {
	base := "{" + key + "}:s:"
	return base + strconv.FormatInt(bucket, 10), base + strconv.FormatInt(bucket-1, 10)
}
