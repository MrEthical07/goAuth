# Testing against goAuth: the test clock

Session lifetimes, idle windows, profile ceilings and the expiry of every
challenge are decided with the time the engine reads. `Builder.WithClock` lets an
application's own tests move that time, so a session can be walked to its idle
limit or its absolute ceiling without waiting for it.

```go
type Clock interface{ Now() time.Time }

func (b *Builder) WithClock(c Clock) *Builder // nil = the system clock (default)
```

The clock belongs to one engine. Two engines in one process with different clocks
do not affect each other, and an engine built without `WithClock` behaves exactly
as it always did.

## What the clock controls

Everything the engine itself decides by the time of day:

- session creation (`CreatedAt`, `ExpiresAt`), the idle window, a profile's
  absolute ceiling and the renew-on-use rule, and the `now` handed to the Lua
  scripts that rotate, swap and read sessions;
- JWT issue (`iat`, `exp`) and validation (`exp`, `nbf`, the `iat` future bound);
- the expiry of password-reset, email-verification, email-change, MFA and
  external sign-up challenges;
- the external ID-token checks (`exp`, `iat`, `nbf`) and the replay TTLs derived
  from them;
- the bucket arithmetic of the sliding-window limiters;
- the TOTP time step, credential `CreatedAt` stamps, the role-switch assurance
  times and the `Timestamp` of every audit event.

## What it does not control

- **Redis key lifetimes.** `SET ... PX`, `EXPIRE` and friends are Redis's own
  time. Moving the clock does not expire a key.
- **Latency measurements** (metrics histograms and the Redis ping) read the
  wall clock, because they measure a duration, not a moment.
- **The anti-enumeration response floor** of `RequestPasswordReset` and
  `RequestEmailVerification` (20-40 ms) is a real sleep and stays real.
- **Libraries that read the time themselves.** The WebAuthn ceremony timeout is
  enforced by the go-webauthn library with the wall clock.

## Pair it with miniredis

Because Redis keeps its own time, a test that moves the engine's clock must move
Redis by the same amount. With [miniredis](https://github.com/alicebob/miniredis)
that is `SetTime` once and `FastForward` for every step:

```go
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *manualClock) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

mr, _ := miniredis.Run()
clk := &manualClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
mr.SetTime(clk.Now())

engine, _ := goAuth.New().
	WithConfig(cfg).
	WithRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()})).
	// ...
	WithClock(clk).
	Build()

advance := func(d time.Duration) { // both, always together
	clk.advance(d)
	mr.SetTime(clk.Now())
	mr.FastForward(d)
}
```

**A real Redis cannot be time-travelled.** Against one, `WithClock` can still
fix the clock at a moment (useful for deterministic timestamps) or move it
forward, but the keys' own lifetimes keep running in real time, so the two
disagree as soon as you advance. Use miniredis, or a Redis you can restart with
a fake time library, for tests that walk a session through months.

## Example: a mobile session to its ceiling

`test/clock_session_profiles_test.go` is the reference. The `mobile` profile has
a 90-day idle window, a 365-day ceiling and renews on use:

1. log in as `mobile`;
2. every 60 days: `advance(60 * day)`, then `Refresh`. The refresh at day 360
   succeeds;
3. shortly before day 365 a last refresh still works and returns an access token
   that outlives the ceiling;
4. after day 365 `Refresh` returns `ErrSessionNotFound` and a strict `Validate`
   of that token is refused, although the token itself has not expired: only the
   session ended it.

A second test lets a session go 91 days without a refresh and sees it ended by
the idle window.

## Not for production, unless the clock is trustworthy

`WithClock` exists for tests. It is safe in production only with a clock that
is monotonic and tracks real time: a clock that jumps backwards makes tokens
and sessions outlive their lifetimes, one that jumps forwards expires them
early, and a clock that differs between your instances makes them disagree about
every token and challenge. If you do not need to move time, do not set it.

See also: [config.md](config.md),
[session.md](session.md), [api-reference.md](api-reference.md).
