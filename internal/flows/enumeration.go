package flows

import (
	"context"
	"time"
)

// enumerationFloor holds a request to a randomized minimum duration measured
// from its entry. Every branch that answers "here is your challenge" -- the
// identifier is registered, unknown, inactive or already verified -- finishes
// through it, so the time an unauthenticated caller can measure does not tell
// which branch ran: the branches differ by a lookup and a Redis write, a few
// hundred microseconds, and the floor is tens of milliseconds. A zero floor
// (no draw function) waits for nothing.
type enumerationFloor struct {
	start time.Time
	floor time.Duration
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// floorClock picks the time source of an enumeration floor: floorNow when set,
// otherwise now.
func floorClock(floorNow, now func() time.Time) func() time.Time {
	if floorNow != nil {
		return floorNow
	}
	return now
}

// startEnumerationFloor draws the floor and starts the clock.
func startEnumerationFloor(
	now func() time.Time,
	draw func() time.Duration,
	sleep func(context.Context, time.Duration) error,
) enumerationFloor {
	f := enumerationFloor{now: now, sleep: sleep}
	if draw != nil {
		f.floor = draw()
		f.start = now()
	}
	return f
}

// finish waits out the rest of the floor and returns the challenge.
func (f enumerationFloor) finish(ctx context.Context, challenge string) (string, error) {
	if f.floor > 0 {
		if remaining := f.floor - f.now().Sub(f.start); remaining > 0 {
			if err := f.sleep(ctx, remaining); err != nil {
				return "", err
			}
		}
	}
	return challenge, nil
}

// sleepContext sleeps for d or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
