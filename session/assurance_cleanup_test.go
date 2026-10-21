package session

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// A role-switch MFA-proof key ("asa:<tenant>:<id>") must disappear in the same
// step that deletes its session, on every path that deletes one. Before this
// change each of them left the key to age out by its TTL.

func TestAssuranceKeyFormatMatchesLuaDerivation(t *testing.T) {
	// deleteSessionScript and rotateRefreshScript rebuild the key from the
	// counter key: "asa:" .. string.sub(count, 5, -7) .. ":" .. id. Pin the
	// formats they depend on.
	store, _, done := newSessionStoreTest(t)
	defer done()
	for _, tenant := range []string{"t-1", "", "a:b", "tenant-with-count"} {
		count := store.tenantCountKey(tenant)
		if len(count) < 11 || count[:4] != "ast:" || count[len(count)-6:] != ":count" {
			t.Fatalf("tenant count key %q no longer has the ast:<tenant>:count shape", count)
		}
		derived := "asa:" + count[4:len(count)-6] + ":sid"
		if want := store.assuranceKey(tenant, "sid"); derived != want {
			t.Fatalf("tenant %q: derived %q, assuranceKey %q", tenant, derived, want)
		}
	}
}

func TestAssuranceKeyRemovedWhenSessionDeleted(t *testing.T) {
	ctx := context.Background()

	t.Run("Delete (logout variants)", func(t *testing.T) {
		store, _, done := newSessionStoreTest(t)
		defer done()
		sess := testSession()
		if err := store.Save(ctx, sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		seedAssurance(t, store, sess)
		if err := store.Delete(ctx, sess.TenantID, sess.SessionID); err != nil {
			t.Fatal(err)
		}
		wantAssuranceGone(t, store, sess, "Delete")
	})

	t.Run("Get on an expired session", func(t *testing.T) {
		store, _, done := newSessionStoreTest(t)
		defer done()
		sess := testSession()
		sess.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		if err := store.Save(ctx, sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		seedAssurance(t, store, sess)
		if _, err := store.Get(ctx, sess.TenantID, sess.SessionID, 0); err == nil {
			t.Fatal("expected the expired session to be refused")
		}
		wantAssuranceGone(t, store, sess, "Get expiry")
	})

	t.Run("DeleteAllForUser", func(t *testing.T) {
		store, _, done := newSessionStoreTest(t)
		defer done()
		var all []*Session
		for i := 0; i < 3; i++ {
			s := testSession()
			s.SessionID = fmt.Sprintf("sid-%d", i)
			if err := store.Save(ctx, s, time.Hour); err != nil {
				t.Fatal(err)
			}
			seedAssurance(t, store, s)
			all = append(all, s)
		}
		if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			wantAssuranceGone(t, store, s, "DeleteAllForUser")
		}
	})

	t.Run("Delete leaves other sessions' proof keys alone", func(t *testing.T) {
		store, _, done := newSessionStoreTest(t)
		defer done()
		a, b := testSession(), testSession()
		b.SessionID = "sid-2"
		for _, s := range []*Session{a, b} {
			if err := store.Save(ctx, s, time.Hour); err != nil {
				t.Fatal(err)
			}
			seedAssurance(t, store, s)
		}
		if err := store.Delete(ctx, a.TenantID, a.SessionID); err != nil {
			t.Fatal(err)
		}
		if !hasAssurance(t, store, b) {
			t.Fatal("deleting one session removed another session's MFA-proof key")
		}
	})

	t.Run("RotateRefreshHash", func(t *testing.T) {
		for _, sc := range swapScenarios() {
			if sc.wantRotated || sc.name == "missing" || sc.name == "corrupt blob" {
				continue // no session is deleted on these
			}
			t.Run(sc.name, func(t *testing.T) {
				store, rdb, done := newSessionStoreTest(t)
				defer done()
				provided := sc.setup(t, store, rdb)
				sess := testSession()
				seedAssurance(t, store, sess)
				if _, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, provided, [32]byte{9}); err == nil {
					t.Fatal("expected the rotation to fail")
				}
				wantAssuranceGone(t, store, sess, "rotate "+sc.name)
			})
		}
	})

	t.Run("SwapSession failure branches", func(t *testing.T) {
		for _, sc := range swapScenarios() {
			if sc.wantRotated || sc.name == "missing" || sc.name == "corrupt blob" {
				continue
			}
			t.Run(sc.name, func(t *testing.T) {
				store, rdb, done := newSessionStoreTest(t)
				defer done()
				provided := sc.setup(t, store, rdb)
				sess := testSession()
				seedAssurance(t, store, sess)
				if err := store.SwapSession(ctx, sess.TenantID, sess.SessionID, provided, swapTarget(sess, "sid-new"), nil); err == nil {
					t.Fatal("expected the swap to fail")
				}
				wantAssuranceGone(t, store, sess, "swap "+sc.name)
			})
		}
	})
}

func TestAssuranceKeyRemovedWhenProfileSessionEnds(t *testing.T) {
	ctx := context.Background()
	swap := func(h *profileHarness, old *Session, newID string) (*Session, error) {
		next := *old
		next.SessionID = newID
		next.Role = "admin"
		next.RefreshHash = [32]byte{0xEE}
		next.SchemaVersion = 0
		return &next, h.store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, &next, nil)
	}
	removeMobile := map[string]ProfilePolicy{"web": {AbsoluteLifetime: 15 * day}}
	shortCeiling := map[string]ProfilePolicy{"mobile": {IdleTimeout: 90 * day, AbsoluteLifetime: day}}

	paths := []struct {
		name string
		// end puts the session in a state the path must end, and runs it.
		end func(h *profileHarness, sess *Session) error
	}{
		{"Get unknown profile", func(h *profileHarness, sess *Session) error {
			h.store.WithProfiles(removeMobile)
			_, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, 7*day)
			return err
		}},
		{"Get ceiling passed", func(h *profileHarness, sess *Session) error {
			h.advance(2 * day)
			h.store.WithProfiles(shortCeiling)
			_, err := h.store.Get(ctx, sess.TenantID, sess.SessionID, 7*day)
			return err
		}},
		{"rotate unknown profile", func(h *profileHarness, sess *Session) error {
			h.store.WithProfiles(removeMobile)
			_, err := h.refresh(sess)
			return err
		}},
		{"rotate ceiling passed", func(h *profileHarness, sess *Session) error {
			h.advance(2 * day)
			h.store.WithProfiles(shortCeiling)
			_, err := h.refresh(sess)
			return err
		}},
		{"swap unknown profile", func(h *profileHarness, sess *Session) error {
			h.store.WithProfiles(removeMobile)
			_, err := swap(h, sess, "mob-2")
			return err
		}},
		{"swap ceiling passed", func(h *profileHarness, sess *Session) error {
			h.advance(2 * day)
			h.store.WithProfiles(shortCeiling)
			_, err := swap(h, sess, "mob-2")
			return err
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			h := newProfileHarness(t, dressin(), 0)
			sess := h.create("mob-1", "mobile")
			if err := h.store.SaveAssurance(ctx, sess.TenantID, sess.SessionID, Assurance{MFAAt: 1, MFAMethod: "totp", AuthAt: 1}, 365*day); err != nil {
				t.Fatal(err)
			}
			if err := p.end(h, sess); err == nil {
				t.Fatal("expected the path to end the session with an error")
			}
			if h.exists(sess) {
				t.Fatal("the session survived")
			}
			wantAssuranceGone(t, h.store, sess, p.name)
		})
	}
}

// A successful swap keeps the behavior it always had: the old key is moved to
// the new session (or replaced by a fresh assurance) and never left behind.
func TestSwapSessionSuccessNeverLeavesOldAssuranceBehind(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()
	sess := testSession()
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	seedAssurance(t, store, sess)
	next := swapTarget(sess, "sid-new")
	if err := store.SwapSession(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, next, nil); err != nil {
		t.Fatal(err)
	}
	if keys, _ := rdb.Keys(ctx, "asa:*").Result(); len(keys) != 1 || keys[0] != store.assuranceKey(next.TenantID, next.SessionID) {
		t.Fatalf("expected only the new session's assurance key, got %v", keys)
	}
	if n, err := rdb.Exists(ctx, store.assuranceKey(sess.TenantID, sess.SessionID)).Result(); err != nil || n != 0 {
		t.Fatalf("old assurance key still exists: %v %v", n, err)
	}
}
