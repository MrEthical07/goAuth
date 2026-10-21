// Package clock is the time source for session creation and expiry.
//
// Production code never replaces it: Now is time.Now. Tests install a
// controllable clock with Set to walk a session through days or months of
// refreshes without sleeping. Only the session store and the code that stamps
// a session's CreatedAt and ExpiresAt read it; token signing and validation
// keep using the wall clock.
package clock

import (
	"sync"
	"sync/atomic"
	"time"
)

var override atomic.Pointer[func() time.Time]

// Now returns the current time: the installed test clock if there is one,
// otherwise the wall clock.
func Now() time.Time {
	if f := override.Load(); f != nil {
		return (*f)()
	}
	return time.Now()
}

// Set installs f as the clock and returns a function restoring the previous
// one. It is for tests, which must not run in parallel with other tests that
// read the clock.
func Set(f func() time.Time) (restore func()) {
	prev := override.Load()
	override.Store(&f)
	return func() { override.Store(prev) }
}

// Fake is a manually advanced clock.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake reading start.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake forward by d.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}
