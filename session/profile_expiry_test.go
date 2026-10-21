package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const day = 24 * time.Hour

// dressin is the first consumer's policy: web is a fixed 15-day session,
// mobile a 90-day inactivity window with a 365-day ceiling.
func dressin() map[string]ProfilePolicy {
	return map[string]ProfilePolicy{
		"web":    {AbsoluteLifetime: 15 * day},
		"mobile": {IdleTimeout: 90 * day, AbsoluteLifetime: 365 * day},
		"mobile-use": {
			IdleTimeout: 90 * day, AbsoluteLifetime: 365 * day, RenewOnUse: true,
		},
		"agent": {IdleTimeout: day}, // unbounded
	}
}

// profileHarness is a store over miniredis driven by a fake clock: advance
// moves the clock and the key lifetimes together, so days pass instantly.
type profileHarness struct {
	t     *testing.T
	store *Store
	rdb   *redis.Client
	mr    *miniredis.Miniredis
	clk   *clock.Fake
}

func newProfileHarness(t *testing.T, profiles map[string]ProfilePolicy, jitter time.Duration) *profileHarness {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	h := &profileHarness{
		t: t, rdb: rdb, mr: mr,
		clk: clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	h.store = NewStore(rdb, "as", true, jitter > 0, jitter).WithProfiles(profiles)
	restore := clock.Set(h.clk.Now)
	mr.SetTime(h.clk.Now())
	t.Cleanup(func() {
		restore()
		_ = rdb.Close()
		mr.Close()
	})
	return h
}

func (h *profileHarness) advance(d time.Duration) {
	h.clk.Advance(d)
	h.mr.SetTime(h.clk.Now())
	h.mr.FastForward(d)
}

// create stores a session under the named profile exactly as login does.
func (h *profileHarness) create(id, profile string) *Session {
	h.t.Helper()
	expiresAt, ttl, err := h.store.NewSessionLifetime(profile, h.clk.Now())
	if err != nil {
		h.t.Fatalf("NewSessionLifetime(%s): %v", profile, err)
	}
	mask := permission.Mask64(1)
	sess := &Session{
		SessionID: id, UserID: "u-1", TenantID: "t-1", Role: "member", Mask: &mask,
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
		RefreshHash: [32]byte{1},
		CreatedAt:   h.clk.Now().Unix(),
		ExpiresAt:   expiresAt,
		Profile:     profile,
	}
	if err := h.store.Save(context.Background(), sess, ttl); err != nil {
		h.t.Fatalf("Save: %v", err)
	}
	return sess
}

// refresh rotates the session's refresh hash, returning the new hash.
func (h *profileHarness) refresh(sess *Session) ([32]byte, error) {
	next := sess.RefreshHash
	next[0]++
	_, err := h.store.RotateRefreshHash(context.Background(), sess.TenantID, sess.SessionID, sess.RefreshHash, next)
	if err == nil {
		sess.RefreshHash = next
	}
	return next, err
}

func (h *profileHarness) ttl(sess *Session) time.Duration {
	return h.mr.TTL(h.store.key(sess.TenantID, sess.SessionID))
}

func (h *profileHarness) exists(sess *Session) bool {
	return h.mr.Exists(h.store.key(sess.TenantID, sess.SessionID))
}

func wantTTL(t *testing.T, what string, got, want time.Duration) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: TTL = %v, want %v", what, got, want)
	}
}

func isExpired(err error) bool {
	return errors.Is(err, redis.Nil) && errors.Is(err, ErrRefreshSessionExpired)
}

func isNotFound(err error) bool {
	return errors.Is(err, redis.Nil) && errors.Is(err, ErrRefreshSessionNotFound)
}

// AC1a: a fixed profile ends at its AbsoluteLifetime however often it is
// refreshed, and refresh never moves its key lifetime.
func TestProfileFixedEndsAtCeilingEvenWhenRefreshedDaily(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("web-1", "web")
	wantTTL(t, "created", h.ttl(sess), 15*day)

	for d := 1; d <= 14; d++ {
		h.advance(day)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh on day %d: %v", d, err)
		}
		wantTTL(t, fmt.Sprintf("after the day-%d refresh", d), h.ttl(sess), time.Duration(15-d)*day)
	}

	h.advance(day) // day 15: the session's life is over
	if h.exists(sess) {
		t.Fatal("the key outlived its 15-day lifetime")
	}
	if _, err := h.refresh(sess); !isNotFound(err) {
		t.Fatalf("refresh on day 15 = %v, want not found", err)
	}
}

// The Lua ceiling check, not just the key TTL, ends a fixed session: the key
// is made to outlive its ceiling the way clock skew or a shortened config
// would.
func TestProfileFixedRefreshPastCeilingDeletes(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("web-1", "web")
	h.advance(15*day - time.Second)
	if err := h.rdb.Expire(context.Background(), h.store.key(sess.TenantID, sess.SessionID), 10*time.Second).Err(); err != nil {
		t.Fatal(err)
	}
	h.advance(time.Second) // ceiling reached, key still has 9s

	_, err := h.refresh(sess)
	if !isExpired(err) {
		t.Fatalf("refresh past the ceiling = %v, want expired", err)
	}
	if errors.Is(err, ErrProfileUnknown) {
		t.Fatal("an expired ceiling must not read as an unknown profile")
	}
	if h.exists(sess) {
		t.Fatal("the session survived a refresh past its ceiling")
	}
	if ids, _ := h.store.ActiveSessionIDs(context.Background(), sess.TenantID, sess.UserID); len(ids) != 0 {
		t.Fatalf("user index still lists %v", ids)
	}
}

// AC1b: a renewing profile survives while refreshed inside the idle window,
// each refresh moving the window forward, and ends when left idle.
func TestProfileRenewingIdleWindowMovesWithRefresh(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")
	wantTTL(t, "created", h.ttl(sess), 90*day)

	h.advance(89 * day)
	wantTTL(t, "on day 89, before refreshing", h.ttl(sess), day)
	if _, err := h.refresh(sess); err != nil {
		t.Fatalf("refresh on day 89: %v", err)
	}
	// The window now runs to day 89 + 90 = day 179.
	wantTTL(t, "after the day-89 refresh", h.ttl(sess), 90*day)
	h.advance(89 * day) // day 178
	if !h.exists(sess) {
		t.Fatal("the session ended before day 179")
	}
	h.advance(day) // day 179
	if h.exists(sess) {
		t.Fatal("the session outlived its idle window")
	}
}

func TestProfileRenewingEndsAfterIdleDays(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")
	h.advance(91 * day)
	if _, err := h.refresh(sess); !isNotFound(err) {
		t.Fatalf("refresh after 91 idle days = %v, want not found", err)
	}
}

// AC1c: refreshing regularly never gets past the ceiling, and the window is
// cut short to what the ceiling leaves.
func TestProfileRenewingEndsAtCeilingEvenWhenRefreshedRegularly(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")

	for _, d := range []int{60, 120, 180, 240} {
		h.advance(60 * day)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh on day %d: %v", d, err)
		}
		wantTTL(t, fmt.Sprintf("after the day-%d refresh", d), h.ttl(sess), 90*day)
	}
	// Day 300: 65 days of ceiling are left, so the 90-day window is clamped.
	h.advance(60 * day)
	if _, err := h.refresh(sess); err != nil {
		t.Fatalf("refresh on day 300: %v", err)
	}
	wantTTL(t, "after the day-300 refresh", h.ttl(sess), 65*day)
	// Day 360: only five days remain before the ceiling.
	h.advance(60 * day)
	if _, err := h.refresh(sess); err != nil {
		t.Fatalf("refresh on day 360: %v", err)
	}
	wantTTL(t, "after the day-360 refresh", h.ttl(sess), 5*day)

	h.advance(5 * day) // day 365
	if h.exists(sess) {
		t.Fatal("the session outlived its 365-day ceiling")
	}
	if _, err := h.refresh(sess); !isNotFound(err) {
		t.Fatalf("refresh on day 365 = %v, want not found", err)
	}
}

// At the ceiling boundary the clamp, not luck, bounds the key: with a second
// left, the new TTL is that second.
func TestProfileRenewingTTLNeverPassesCeiling(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")
	for i := 0; i < 5; i++ {
		h.advance(70 * day)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	// Day 350; step to one second before the ceiling and refresh.
	h.advance(15*day - time.Second)
	if _, err := h.refresh(sess); err != nil {
		t.Fatalf("refresh one second before the ceiling: %v", err)
	}
	wantTTL(t, "one second before the ceiling", h.ttl(sess), time.Second)
	h.advance(time.Second)
	if h.exists(sess) {
		t.Fatal("the session outlived its ceiling")
	}
}

// An unbounded profile has no ceiling and a fresh idle window each refresh.
func TestProfileUnboundedRenewing(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("agent-1", "agent")
	if sess.ExpiresAt != UnboundedExpiresAt {
		t.Fatalf("ExpiresAt = %d, want the unbounded sentinel %d", sess.ExpiresAt, UnboundedExpiresAt)
	}
	for i := 0; i < 5; i++ {
		h.advance(23 * time.Hour)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		wantTTL(t, "after refresh", h.ttl(sess), day)
	}
	h.advance(day)
	if h.exists(sess) {
		t.Fatal("an idle unbounded session must still end by inactivity")
	}
}

// Jitter moves the idle window by at most its range, never past the ceiling
// and never below a second.
func TestProfileRenewingJitterBounds(t *testing.T) {
	const jitter = 30 * time.Second
	h := newProfileHarness(t, dressin(), jitter)

	sess := h.create("mob-1", "mobile")
	lo, hi := 90*day-jitter, 90*day+jitter
	if got := h.ttl(sess); got < lo || got > hi {
		t.Fatalf("created TTL %v outside [%v, %v]", got, lo, hi)
	}
	distinct := map[time.Duration]bool{}
	for i := 0; i < 40; i++ {
		h.advance(time.Hour)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		got := h.ttl(sess)
		distinct[got] = true
		if got < lo || got > hi {
			t.Fatalf("refresh TTL %v outside [%v, %v]", got, lo, hi)
		}
	}
	if len(distinct) < 5 {
		t.Fatalf("jitter looks absent: only %d distinct TTLs in 40 refreshes", len(distinct))
	}

	// Near the ceiling the jitter can never push the key past it.
	near := h.create("mob-2", "mobile")
	for i := 0; i < 5; i++ {
		h.advance(70 * day)
		if _, err := h.refresh(near); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	h.advance(15*day - 10*time.Second) // ten seconds before the ceiling
	for i := 0; i < 20; i++ {
		remaining := time.Unix(near.ExpiresAt, 0).Sub(h.clk.Now())
		if remaining <= 0 {
			break
		}
		if _, err := h.refresh(near); err != nil {
			t.Fatalf("refresh near ceiling: %v", err)
		}
		got := h.ttl(near)
		if got > remaining {
			t.Fatalf("TTL %v passes the ceiling (%v left)", got, remaining)
		}
		floor := time.Second
		if remaining < floor {
			floor = remaining
		}
		if got < floor {
			t.Fatalf("TTL %v below the floor %v", got, floor)
		}
		h.advance(time.Second)
	}
}

// An unknown profile (removed from configuration) ends the session at refresh
// exactly like expiry: deleted, de-indexed, counted, reported as expired.
func TestProfileUnknownAtRefreshDeletes(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")
	other := h.create("web-1", "web")

	// "mobile" is removed from the configuration.
	h.store.WithProfiles(map[string]ProfilePolicy{"web": {AbsoluteLifetime: 15 * day}})
	if n, _ := h.store.TenantSessionCount(context.Background(), "t-1"); n != 2 {
		t.Fatalf("tenant count = %d, want 2", n)
	}

	_, err := h.refresh(sess)
	if !isExpired(err) || !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("refresh of a removed profile = %v, want expired + ErrProfileUnknown", err)
	}
	if got := EndedProfileName(err); got != "mobile" {
		t.Fatalf("EndedProfileName = %q, want mobile", got)
	}
	if h.exists(sess) {
		t.Fatal("the session of a removed profile survived")
	}
	if n, _ := h.store.TenantSessionCount(context.Background(), "t-1"); n != 1 {
		t.Fatalf("tenant count = %d, want 1 after the removed-profile session ended", n)
	}
	// Sessions of the remaining profile are untouched.
	if _, err := h.refresh(other); err != nil {
		t.Fatalf("refresh of a surviving profile: %v", err)
	}
}

func TestProfileSessionWithoutTableIsUnknown(t *testing.T) {
	h := newProfileHarness(t, dressin(), 0)
	sess := h.create("mob-1", "mobile")
	// Profiles switched off entirely (a rollback to a config without any).
	h.store.WithProfiles(nil)
	if _, err := h.refresh(sess); !isExpired(err) || !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("refresh with no table = %v, want expired + ErrProfileUnknown", err)
	}
}

// Live configuration: shortening a profile's ceiling shortens sessions
// already issued; lengthening it never extends one.
func TestProfileLiveConfigCeiling(t *testing.T) {
	t.Run("shortened", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile")
		h.advance(40 * day)

		// The mobile ceiling drops from 365d to 60d: 20 days remain.
		short := dressin()
		short["mobile"] = ProfilePolicy{IdleTimeout: 30 * day, AbsoluteLifetime: 60 * day}
		h.store.WithProfiles(short)

		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		wantTTL(t, "clamped to the shortened ceiling", h.ttl(sess), 20*day)

		h.advance(20 * day)
		if h.exists(sess) {
			t.Fatal("the session outlived the shortened ceiling")
		}
	})

	t.Run("shortened below the age of the session", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile")
		h.advance(40 * day)
		short := dressin()
		short["mobile"] = ProfilePolicy{IdleTimeout: 10 * day, AbsoluteLifetime: 30 * day}
		h.store.WithProfiles(short)

		if _, err := h.refresh(sess); !isExpired(err) {
			t.Fatalf("refresh = %v, want expired", err)
		}
		if h.exists(sess) {
			t.Fatal("the session survived a ceiling already passed")
		}
	})

	t.Run("shortened fixed profile clamps the key", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("web-1", "web")
		h.advance(day)
		short := dressin()
		short["web"] = ProfilePolicy{AbsoluteLifetime: 5 * day}
		h.store.WithProfiles(short)
		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		wantTTL(t, "fixed key clamped", h.ttl(sess), 4*day)
	})

	t.Run("lengthened never extends", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("web-1", "web")
		h.advance(10 * day)

		long := dressin()
		long["web"] = ProfilePolicy{AbsoluteLifetime: 100 * day}
		h.store.WithProfiles(long)

		if _, err := h.refresh(sess); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		wantTTL(t, "stored ceiling still wins", h.ttl(sess), 5*day)
		got, err := h.store.Peek(context.Background(), sess.TenantID, sess.SessionID)
		if err != nil || got.ExpiresAt != sess.ExpiresAt {
			t.Fatalf("ExpiresAt moved: %v, %+v", err, got)
		}

		h.advance(5 * day)
		if h.exists(sess) {
			t.Fatal("a lengthened config revived a session past its stored ceiling")
		}
	})
}

// Strict reads: a v6 session never gets the legacy "TTL = remaining absolute"
// reset. Without RenewOnUse the key is not touched; with it the idle window
// is renewed.
func TestProfileStrictReadRenewal(t *testing.T) {
	ctx := context.Background()
	legacyTTL := 7 * day

	t.Run("without RenewOnUse the TTL is untouched", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile")
		h.advance(10 * day)
		before := h.ttl(sess)
		if _, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, legacyTTL); err != nil {
			t.Fatalf("Get: %v", err)
		}
		wantTTL(t, "after a strict read", h.ttl(sess), before)
		wantTTL(t, "idle window not renewed", h.ttl(sess), 80*day)
	})

	t.Run("a fixed profile is untouched", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("web-1", "web")
		h.advance(3 * day)
		if _, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, legacyTTL); err != nil {
			t.Fatalf("Get: %v", err)
		}
		wantTTL(t, "after a strict read", h.ttl(sess), 12*day)
	})

	t.Run("RenewOnUse renews the idle window", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile-use")
		h.advance(80 * day)
		wantTTL(t, "before the read", h.ttl(sess), 10*day)
		if _, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, legacyTTL); err != nil {
			t.Fatalf("Get: %v", err)
		}
		wantTTL(t, "after the read", h.ttl(sess), 90*day)
	})

	t.Run("RenewOnUse never passes the ceiling", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile-use")
		for i := 0; i < 5; i++ {
			h.advance(70 * day)
			if _, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, legacyTTL); err != nil {
				t.Fatalf("Get %d: %v", i, err)
			}
		}
		// Day 350: 15 days of ceiling left.
		wantTTL(t, "clamped by the ceiling", h.ttl(sess), 15*day)
	})

	t.Run("the legacy reset still applies to a legacy session", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		mask := permission.Mask64(1)
		legacy := &Session{
			SessionID: "old-1", UserID: "u-1", TenantID: "t-1", Role: "member", Mask: &mask,
			PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1, RefreshHash: [32]byte{1},
			CreatedAt: h.clk.Now().Unix(), ExpiresAt: h.clk.Now().Add(legacyTTL).Unix(),
		}
		if err := h.store.Save(ctx, legacy, 6*day); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.Get(ctx, "t-1", "old-1", legacyTTL); err != nil {
			t.Fatalf("Get: %v", err)
		}
		wantTTL(t, "legacy sliding reset", h.ttl(legacy), legacyTTL)
	})
}

func TestProfileStrictReadEndsSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown profile", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile")
		h.store.WithProfiles(map[string]ProfilePolicy{"web": {AbsoluteLifetime: 15 * day}})
		_, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, 7*day)
		if !errors.Is(err, redis.Nil) || !errors.Is(err, ErrProfileUnknown) || EndedProfileName(err) != "mobile" {
			t.Fatalf("Get = %v, want not found + ErrProfileUnknown naming mobile", err)
		}
		if h.exists(sess) {
			t.Fatal("the session of a removed profile survived a strict read")
		}
	})

	t.Run("shortened ceiling already passed", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		sess := h.create("mob-1", "mobile")
		h.advance(40 * day)
		short := dressin()
		short["mobile"] = ProfilePolicy{IdleTimeout: 10 * day, AbsoluteLifetime: 30 * day}
		h.store.WithProfiles(short)
		_, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, 7*day)
		if !errors.Is(err, redis.Nil) || !errors.Is(err, ErrSessionExpired) || EndedProfileName(err) != "mobile" {
			t.Fatalf("Get = %v, want not found + ErrSessionExpired naming mobile", err)
		}
		if h.exists(sess) {
			t.Fatal("the session survived a passed ceiling")
		}
	})
}

// Read-only views hide a session a strict read would end, without touching it.
func TestProfileReadOnlyViews(t *testing.T) {
	ctx := context.Background()
	h := newProfileHarness(t, dressin(), 0)
	mob := h.create("mob-1", "mobile")
	web := h.create("web-1", "web")
	h.advance(10 * day)

	got, err := h.store.GetReadOnly(ctx, mob.TenantID, mob.SessionID)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if want := h.clk.Now().Add(80 * day).Unix(); got.IdleExpiresAt != want {
		t.Fatalf("IdleExpiresAt = %d, want %d", got.IdleExpiresAt, want)
	}
	if got, _ := h.store.GetReadOnly(ctx, web.TenantID, web.SessionID); got == nil || got.IdleExpiresAt != 0 {
		t.Fatalf("a fixed session must report no idle expiry: %+v", got)
	}
	many, err := h.store.GetManyReadOnly(ctx, "t-1", []string{"mob-1", "web-1"})
	if err != nil || len(many) != 2 {
		t.Fatalf("GetManyReadOnly = %v, %v", many, err)
	}
	for _, s := range many {
		switch s.SessionID {
		case "mob-1":
			if s.IdleExpiresAt != h.clk.Now().Add(80*day).Unix() || s.Profile != "mobile" {
				t.Fatalf("mobile session = %+v", s)
			}
		case "web-1":
			if s.IdleExpiresAt != 0 || s.Profile != "web" {
				t.Fatalf("web session = %+v", s)
			}
		}
	}

	// A removed profile is hidden, and the read-only call deletes nothing.
	h.store.WithProfiles(map[string]ProfilePolicy{"web": {AbsoluteLifetime: 15 * day}})
	if _, err := h.store.GetReadOnly(ctx, mob.TenantID, mob.SessionID); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetReadOnly of a removed profile = %v, want not found", err)
	}
	many, _ = h.store.GetManyReadOnly(ctx, "t-1", []string{"mob-1", "web-1"})
	if len(many) != 1 || many[0].SessionID != "web-1" {
		t.Fatalf("GetManyReadOnly = %v, want only web-1", many)
	}
	if !h.exists(mob) {
		t.Fatal("a read-only view deleted a session")
	}
}

// Swap: the replacement keeps the profile, CreatedAt and ExpiresAt, a switch
// renews the idle window, and the ceiling never moves.
func TestProfileSwapSession(t *testing.T) {
	ctx := context.Background()
	swap := func(h *profileHarness, old *Session, newID string) (*Session, error) {
		next := *old
		next.SessionID = newID
		next.Role = "admin"
		next.RefreshHash = [32]byte{0xEE}
		next.SchemaVersion = 0
		return &next, h.store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, &next, nil)
	}

	t.Run("renewing profile renews the idle window", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("mob-1", "mobile")
		h.advance(80 * day)
		next, err := swap(h, old, "mob-2")
		if err != nil {
			t.Fatalf("SwapSession: %v", err)
		}
		got, err := h.store.Peek(ctx, "t-1", "mob-2")
		if err != nil || got.Profile != "mobile" || got.CreatedAt != old.CreatedAt || got.ExpiresAt != old.ExpiresAt {
			t.Fatalf("swapped session = %+v, %v", got, err)
		}
		wantTTL(t, "renewed idle window", h.ttl(next), 90*day)
		if h.exists(old) {
			t.Fatal("the old session survived the swap")
		}
	})

	t.Run("switching never extends the ceiling", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("mob-1", "mobile")
		for i := 0; i < 5; i++ {
			h.advance(70 * day)
			if _, err := h.refresh(old); err != nil {
				t.Fatalf("refresh: %v", err)
			}
		}
		// Day 350: 15 days of ceiling left, and a switch is a use.
		next, err := swap(h, old, "mob-2")
		if err != nil {
			t.Fatalf("SwapSession: %v", err)
		}
		wantTTL(t, "clamped to the ceiling", h.ttl(next), 15*day)
	})

	t.Run("fixed profile keeps what is left", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("web-1", "web")
		h.advance(4 * day)
		next, err := swap(h, old, "web-2")
		if err != nil {
			t.Fatalf("SwapSession: %v", err)
		}
		wantTTL(t, "remaining time to the ceiling", h.ttl(next), 11*day)
	})

	t.Run("assurance lives as long as the session can", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("mob-1", "mobile")
		if err := h.store.SaveAssurance(ctx, "t-1", "mob-1", Assurance{MFAAt: 1, MFAMethod: "totp", AuthAt: 1}, 365*day); err != nil {
			t.Fatal(err)
		}
		h.advance(10 * day)
		next, _ := swap(h, old, "mob-2")
		if h.mr.TTL(h.store.assuranceKey("t-1", next.SessionID)) != 355*day {
			t.Fatalf("assurance TTL = %v, want the 355 days left before the ceiling", h.mr.TTL(h.store.assuranceKey("t-1", next.SessionID)))
		}
	})

	t.Run("unknown profile ends the session", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("mob-1", "mobile")
		h.store.WithProfiles(map[string]ProfilePolicy{"web": {AbsoluteLifetime: 15 * day}})
		_, err := swap(h, old, "mob-2")
		if !isExpired(err) || !errors.Is(err, ErrProfileUnknown) {
			t.Fatalf("SwapSession = %v, want expired + ErrProfileUnknown", err)
		}
		if h.exists(old) {
			t.Fatal("the session of a removed profile survived a swap")
		}
		if h.mr.Exists(h.store.key("t-1", "mob-2")) {
			t.Fatal("a replacement was written for a removed profile")
		}
	})

	t.Run("a swap cannot change the profile", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		old := h.create("mob-1", "mobile")
		next := *old
		next.SessionID = "mob-2"
		next.Profile = "web"
		next.SchemaVersion = 0
		err := h.store.SwapSession(ctx, "t-1", "mob-1", old.RefreshHash, &next, nil)
		if !errors.Is(err, ErrRefreshSessionCorrupt) {
			t.Fatalf("SwapSession with another profile = %v, want ErrRefreshSessionCorrupt", err)
		}
		if !h.exists(old) || h.mr.Exists(h.store.key("t-1", "mob-2")) {
			t.Fatal("a rejected swap changed state")
		}
	})

	t.Run("a swap cannot turn a legacy session into a profile session", func(t *testing.T) {
		h := newProfileHarness(t, dressin(), 0)
		mask := permission.Mask64(1)
		legacy := &Session{
			SessionID: "old-1", UserID: "u-1", TenantID: "t-1", Role: "member", Mask: &mask,
			PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1, RefreshHash: [32]byte{1},
			CreatedAt: h.clk.Now().Unix(), ExpiresAt: h.clk.Now().Add(day).Unix(),
		}
		if err := h.store.Save(ctx, legacy, day); err != nil {
			t.Fatal(err)
		}
		next := *legacy
		next.SessionID = "new-1"
		next.Profile = "web"
		err := h.store.SwapSession(ctx, "t-1", "old-1", legacy.RefreshHash, &next, nil)
		if !errors.Is(err, ErrRefreshSessionCorrupt) {
			t.Fatalf("SwapSession = %v, want ErrRefreshSessionCorrupt", err)
		}
	})
}

// Reuse of a refresh token ends a profile session exactly as it ends a legacy
// one.
func TestProfileRefreshReuseDeletes(t *testing.T) {
	for _, name := range []string{"web", "mobile", "mobile-use", "agent"} {
		t.Run(name, func(t *testing.T) {
			h := newProfileHarness(t, dressin(), 0)
			sess := h.create("s-1", name)
			stale := sess.RefreshHash
			if _, err := h.refresh(sess); err != nil {
				t.Fatalf("first refresh: %v", err)
			}
			_, err := h.store.RotateRefreshHash(context.Background(), "t-1", "s-1", stale, [32]byte{9})
			if !errors.Is(err, ErrRefreshHashMismatch) {
				t.Fatalf("replayed token = %v, want ErrRefreshHashMismatch", err)
			}
			if h.exists(sess) {
				t.Fatal("reuse did not delete the session")
			}
			if n, _ := h.store.TenantSessionCount(context.Background(), "t-1"); n != 0 {
				t.Fatalf("tenant count = %d, want 0", n)
			}
		})
	}
}

// AC6 at the store: N concurrent refreshes of one session give exactly one
// winner at the idle-window boundary and at the ceiling boundary. The losers
// are what v0.7.0 reuse produces, the TTL never passes the ceiling and the
// session is never resurrected.
func TestProfileConcurrentRefreshBoundaries(t *testing.T) {
	const workers = 16
	cases := []struct {
		name    string
		profile string
		setup   func(h *profileHarness, sess *Session)
	}{
		{"idle boundary", "mobile", func(h *profileHarness, sess *Session) {
			h.advance(90*day - 2*time.Second) // two seconds of idle window left
		}},
		{"ceiling boundary", "mobile", func(h *profileHarness, sess *Session) {
			for i := 0; i < 5; i++ {
				h.advance(70 * day)
				if _, err := h.refresh(sess); err != nil {
					t.Fatalf("refresh: %v", err)
				}
			}
			h.advance(15*day - 2*time.Second) // two seconds before the ceiling
			if _, err := h.refresh(sess); err != nil {
				t.Fatalf("refresh: %v", err)
			}
			h.advance(time.Second) // one second of life left
		}},
		{"fixed ceiling boundary", "web", func(h *profileHarness, sess *Session) {
			h.advance(15*day - 2*time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newProfileHarness(t, dressin(), 0)
			sess := h.create("s-1", tc.profile)
			tc.setup(h, sess)
			if !h.exists(sess) {
				t.Fatal("setup left no session to race on")
			}
			ceiling := time.Unix(sess.ExpiresAt, 0)
			remaining := ceiling.Sub(h.clk.Now())

			var (
				wg       sync.WaitGroup
				start    = make(chan struct{})
				mu       sync.Mutex
				wins     int
				mismatch int
				nilErrs  int
				other    []error
			)
			stale := sess.RefreshHash
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					next := [32]byte{0x40, byte(i)}
					<-start
					_, err := h.store.RotateRefreshHash(context.Background(), "t-1", "s-1", stale, next)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						wins++
					case errors.Is(err, ErrRefreshHashMismatch):
						mismatch++
					case errors.Is(err, redis.Nil):
						nilErrs++
					default:
						other = append(other, err)
					}
				}(i)
			}
			close(start)
			wg.Wait()

			if wins != 1 {
				t.Fatalf("winners = %d, want exactly 1 (mismatch %d, not found %d, other %v)", wins, mismatch, nilErrs, other)
			}
			if len(other) != 0 {
				t.Fatalf("unexpected errors: %v", other)
			}
			if mismatch < 1 || mismatch+nilErrs != workers-1 {
				t.Fatalf("losers = %d mismatch + %d not found, want %d in total with at least one reuse", mismatch, nilErrs, workers-1)
			}
			// The first loser's reuse detection deleted the session; whatever
			// is in Redis now is bounded by the ceiling.
			if h.exists(sess) {
				if ttl := h.ttl(sess); ttl > remaining {
					t.Fatalf("TTL %v passes the ceiling (%v left)", ttl, remaining)
				}
			}
			h.advance(remaining + time.Second)
			if h.exists(sess) {
				t.Fatal("the session was resurrected past its ceiling")
			}
			if _, err := h.refresh(sess); !errors.Is(err, redis.Nil) {
				t.Fatalf("refresh after the ceiling = %v, want not found", err)
			}
		})
	}
}

func TestEncodeProfileTable(t *testing.T) {
	got := encodeProfileTable(map[string]ProfilePolicy{
		"web":    {AbsoluteLifetime: 15 * day},
		"mobile": {IdleTimeout: 90 * day, AbsoluteLifetime: 365 * day, RenewOnUse: true},
		"agent":  {IdleTimeout: time.Hour},
	})
	const want = "agent:3600000:0:0;mobile:7776000000:31536000000:1;web:0:1296000000:0"
	if got != want {
		t.Fatalf("profile table = %q, want %q", got, want)
	}
	if encodeProfileTable(nil) != "" {
		t.Fatal("an empty table must encode to the empty string")
	}
}

func TestNewSessionLifetime(t *testing.T) {
	store := NewStore(nil, "as", true, false, 0).WithProfiles(dressin())
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		profile string
		expires int64
		ttl     time.Duration
	}{
		{"web", now.Add(15 * day).Unix(), 15 * day},
		{"mobile", now.Add(365 * day).Unix(), 90 * day},
		{"agent", UnboundedExpiresAt, day},
	} {
		expiresAt, ttl, err := store.NewSessionLifetime(tc.profile, now)
		if err != nil || expiresAt != tc.expires || ttl != tc.ttl {
			t.Fatalf("%s: (%d, %v, %v), want (%d, %v)", tc.profile, expiresAt, ttl, err, tc.expires, tc.ttl)
		}
	}
	if _, _, err := store.NewSessionLifetime("ghost", now); !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("unknown profile = %v", err)
	}
}
