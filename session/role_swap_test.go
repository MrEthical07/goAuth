package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/redis/go-redis/v9"
)

func swapTarget(from *Session, sid string) *Session {
	mask := permission.Mask64(3)
	next := *from
	next.SessionID = sid
	next.Role = "admin"
	next.Mask = &mask
	next.RefreshHash = [32]byte{0xEE}
	return &next
}

func TestLuaSessionParserMatchesRotateScript(t *testing.T) {
	// The swap script copies the rotate script's blob parser. If the rotate
	// parser ever changes, the copy must change with it.
	if !strings.Contains(rotateRefreshScript, strings.TrimSpace(luaSessionParser)) {
		t.Fatal("swap script parser has drifted from rotateRefreshScript")
	}
}

func TestSwapSessionHappyPath(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}
	other := testSession()
	other.SessionID = "sid-other"
	if err := store.Save(ctx, other, time.Hour); err != nil {
		t.Fatalf("save other: %v", err)
	}
	countBefore, _ := store.TenantSessionCount(ctx, old.TenantID)

	next := swapTarget(old, "sid-new")
	if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err != nil {
		t.Fatalf("SwapSession failed: %v", err)
	}

	if _, err := store.Peek(ctx, old.TenantID, old.SessionID); !errors.Is(err, redis.Nil) {
		t.Fatalf("old session should be gone, got %v", err)
	}
	got, err := store.Peek(ctx, next.TenantID, next.SessionID)
	if err != nil {
		t.Fatalf("new session missing: %v", err)
	}
	if got.Role != "admin" || got.RefreshHash != next.RefreshHash {
		t.Fatalf("new session content wrong: %+v", got)
	}
	if got.CreatedAt != old.CreatedAt || got.ExpiresAt != old.ExpiresAt {
		t.Fatalf("lifetime not preserved: created %d/%d expires %d/%d", got.CreatedAt, old.CreatedAt, got.ExpiresAt, old.ExpiresAt)
	}

	ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID)
	have := map[string]bool{}
	for _, id := range ids {
		have[id] = true
	}
	if have[old.SessionID] || !have[next.SessionID] || !have[other.SessionID] || len(ids) != 2 {
		t.Fatalf("user index wrong: %v", ids)
	}

	if countAfter, _ := store.TenantSessionCount(ctx, old.TenantID); countAfter != countBefore {
		t.Fatalf("tenant count changed: %d -> %d", countBefore, countAfter)
	}

	// The new key must not outlive the old session's absolute lifetime.
	ttl, err := rdb.PTTL(ctx, store.key(next.TenantID, next.SessionID)).Result()
	if err != nil {
		t.Fatalf("pttl failed: %v", err)
	}
	remaining := time.Until(time.Unix(old.ExpiresAt, 0))
	if ttl <= 0 || ttl > remaining+time.Second {
		t.Fatalf("new session TTL %v outside (0, %v]", ttl, remaining)
	}
}

func TestSwapSessionDoesNotExtendLifetimeAcrossRepeatedSwaps(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	cur := testSession()
	cur.ExpiresAt = time.Now().Add(90 * time.Second).Unix()
	if err := store.Save(ctx, cur, 90*time.Second); err != nil {
		t.Fatalf("save: %v", err)
	}
	created, expires := cur.CreatedAt, cur.ExpiresAt

	for i := 0; i < 5; i++ {
		next := swapTarget(cur, "sid-hop-"+string(rune('a'+i)))
		if err := store.SwapSession(ctx, cur.TenantID, cur.SessionID, cur.RefreshHash, next, nil); err != nil {
			t.Fatalf("swap %d failed: %v", i, err)
		}
		cur = next
	}
	got, err := store.Peek(ctx, cur.TenantID, cur.SessionID)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if got.CreatedAt != created || got.ExpiresAt != expires {
		t.Fatalf("absolute lifetime moved: created %d->%d expires %d->%d", created, got.CreatedAt, expires, got.ExpiresAt)
	}
}

func TestSwapSessionAssuranceMoveAndWrite(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}
	held := Assurance{MFAAt: 1700000000, MFAMethod: "totp", AuthAt: 1700000000}
	if err := store.SaveAssurance(ctx, old.TenantID, old.SessionID, held, time.Hour); err != nil {
		t.Fatalf("save assurance: %v", err)
	}

	// No new assurance given: the old one moves to the new session.
	second := swapTarget(old, "sid-2")
	if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, second, nil); err != nil {
		t.Fatalf("swap failed: %v", err)
	}
	if a, err := store.GetAssurance(ctx, old.TenantID, old.SessionID); err != nil || a != nil {
		t.Fatalf("old assurance should be gone, got %v %v", a, err)
	}
	moved, err := store.GetAssurance(ctx, second.TenantID, second.SessionID)
	if err != nil || moved == nil || *moved != held {
		t.Fatalf("assurance not moved: %v %v", moved, err)
	}

	// A new assurance replaces whatever was there.
	fresh := Assurance{MFAAt: 1700000500, MFAMethod: "backup_code", AuthAt: 1700000500}
	third := swapTarget(second, "sid-3")
	if err := store.SwapSession(ctx, second.TenantID, second.SessionID, second.RefreshHash, third, &fresh); err != nil {
		t.Fatalf("swap with assurance failed: %v", err)
	}
	written, err := store.GetAssurance(ctx, third.TenantID, third.SessionID)
	if err != nil || written == nil || *written != fresh {
		t.Fatalf("assurance not written: %v %v", written, err)
	}
	if a, _ := store.GetAssurance(ctx, second.TenantID, second.SessionID); a != nil {
		t.Fatalf("superseded assurance left behind: %v", a)
	}

	// A session with no assurance gets none from a plain swap.
	bare := testSession()
	bare.SessionID = "sid-bare"
	if err := store.Save(ctx, bare, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}
	bareNext := swapTarget(bare, "sid-bare-2")
	if err := store.SwapSession(ctx, bare.TenantID, bare.SessionID, bare.RefreshHash, bareNext, nil); err != nil {
		t.Fatalf("swap failed: %v", err)
	}
	if a, _ := store.GetAssurance(ctx, bareNext.TenantID, bareNext.SessionID); a != nil {
		t.Fatalf("assurance appeared from nowhere: %v", a)
	}
}

func TestSwapSessionLegacySchemaOldSession(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	mask := permission.Mask64(1)
	now := time.Now()
	legacy := &Session{
		SchemaVersion: 4, SessionID: "sid-legacy", UserID: "u-legacy", TenantID: "t-legacy",
		Role: "member", Mask: &mask, PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
		RefreshHash: [32]byte{7}, CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	if err := rdb.Set(ctx, store.key(legacy.TenantID, legacy.SessionID), encodeLegacyV4Session(t, legacy), time.Hour).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	next := swapTarget(legacy, "sid-legacy-new")
	next.SchemaVersion = 0
	if err := store.SwapSession(ctx, legacy.TenantID, legacy.SessionID, legacy.RefreshHash, next, nil); err != nil {
		t.Fatalf("swap of a v4 session failed: %v", err)
	}
	got, err := store.Peek(ctx, next.TenantID, next.SessionID)
	if err != nil || got.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("new session should be written at the current schema: %v %v", got, err)
	}
}

func TestSwapSessionRejectsTenantOrNilTarget(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	if err := store.SwapSession(ctx, "t-1", "sid-1", [32]byte{1}, nil, nil); err == nil {
		t.Fatal("expected an error for a nil target")
	}
	old := testSession()
	next := swapTarget(old, "sid-2")
	next.TenantID = "other-tenant"
	if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err == nil {
		t.Fatal("expected an error for a cross-tenant target")
	}
}

type swapScenario struct {
	name  string
	setup func(t *testing.T, store *Store, rdb *redis.Client) (provided [32]byte)
	// wantRotated: both operations succeed.
	wantRotated bool
	wantErr     []error
}

func swapScenarios() []swapScenario {
	return []swapScenario{
		{
			name: "match",
			setup: func(t *testing.T, store *Store, _ *redis.Client) [32]byte {
				if err := store.Save(context.Background(), testSession(), time.Hour); err != nil {
					t.Fatal(err)
				}
				return testSession().RefreshHash
			},
			wantRotated: true,
		},
		{
			name: "missing",
			setup: func(t *testing.T, store *Store, _ *redis.Client) [32]byte {
				return [32]byte{1}
			},
			wantErr: []error{redis.Nil, ErrRefreshSessionNotFound},
		},
		{
			name: "expired",
			setup: func(t *testing.T, store *Store, _ *redis.Client) [32]byte {
				s := testSession()
				s.ExpiresAt = time.Now().Add(-time.Minute).Unix()
				if err := store.Save(context.Background(), s, time.Hour); err != nil {
					t.Fatal(err)
				}
				return s.RefreshHash
			},
			wantErr: []error{redis.Nil, ErrRefreshSessionExpired},
		},
		{
			name: "hash mismatch",
			setup: func(t *testing.T, store *Store, _ *redis.Client) [32]byte {
				if err := store.Save(context.Background(), testSession(), time.Hour); err != nil {
					t.Fatal(err)
				}
				return [32]byte{0x42}
			},
			wantErr: []error{ErrRefreshHashMismatch},
		},
		{
			name: "no ttl on the key",
			setup: func(t *testing.T, store *Store, rdb *redis.Client) [32]byte {
				s := testSession()
				if err := store.Save(context.Background(), s, time.Hour); err != nil {
					t.Fatal(err)
				}
				if err := rdb.Persist(context.Background(), store.key(s.TenantID, s.SessionID)).Err(); err != nil {
					t.Fatal(err)
				}
				return s.RefreshHash
			},
			wantErr: []error{redis.Nil, ErrRefreshSessionExpired},
		},
		{
			name: "corrupt blob",
			setup: func(t *testing.T, store *Store, rdb *redis.Client) [32]byte {
				if err := rdb.Set(context.Background(), store.key("t-1", "sid-1"), []byte("bad"), time.Hour).Err(); err != nil {
					t.Fatal(err)
				}
				return [32]byte{1}
			},
			wantErr: []error{ErrRefreshSessionCorrupt},
		},
	}
}

type keyspaceState struct {
	oldExists bool
	index     []string
	count     int
}

func captureState(t *testing.T, store *Store, rdb *redis.Client) keyspaceState {
	t.Helper()
	ctx := context.Background()
	n, err := rdb.Exists(ctx, store.key("t-1", "sid-1")).Result()
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := store.ActiveSessionIDs(ctx, "t-1", "u-1")
	filtered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "sid-new" { // the swap's own addition is checked separately
			filtered = append(filtered, id)
		}
	}
	count, _ := store.TenantSessionCount(ctx, "t-1")
	return keyspaceState{oldExists: n == 1, index: filtered, count: count}
}

// SwapSession must treat the old session exactly as RotateRefreshHash does:
// same errors, same deletion of the old session, same index and counter
// effects, on every branch.
func TestSwapSessionMatchesRotateRefreshHashFailureHandling(t *testing.T) {
	for _, sc := range swapScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			rotStore, rotRDB, rotDone := newSessionStoreTest(t)
			defer rotDone()
			swapStore, swapRDB, swapDone := newSessionStoreTest(t)
			defer swapDone()

			rotProvided := sc.setup(t, rotStore, rotRDB)
			swapProvided := sc.setup(t, swapStore, swapRDB)

			_, rotErr := rotStore.RotateRefreshHash(context.Background(), "t-1", "sid-1", rotProvided, [32]byte{9})
			next := swapTarget(testSession(), "sid-new")
			swapErr := swapStore.SwapSession(context.Background(), "t-1", "sid-1", swapProvided, next, nil)

			if sc.wantRotated {
				if rotErr != nil || swapErr != nil {
					t.Fatalf("expected success on both, got rotate=%v swap=%v", rotErr, swapErr)
				}
				return
			}
			for _, want := range sc.wantErr {
				if !errors.Is(rotErr, want) {
					t.Fatalf("rotate err %v does not match %v", rotErr, want)
				}
				if !errors.Is(swapErr, want) {
					t.Fatalf("swap err %v does not match %v (rotate gave %v)", swapErr, want, rotErr)
				}
			}

			rot := captureState(t, rotStore, rotRDB)
			swp := captureState(t, swapStore, swapRDB)
			if rot.oldExists != swp.oldExists || rot.count != swp.count || strings.Join(rot.index, ",") != strings.Join(swp.index, ",") {
				t.Fatalf("side effects differ: rotate=%+v swap=%+v", rot, swp)
			}
			if _, err := swapStore.Peek(context.Background(), "t-1", "sid-new"); !errors.Is(err, redis.Nil) {
				t.Fatalf("a failed swap must not create the new session, got %v", err)
			}
		})
	}
}

// A mismatching swap deletes the old session just as a refresh-token reuse
// does, including the user index and the tenant counter.
func TestSwapSessionMismatchRevokesSession(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	err := store.SwapSession(ctx, old.TenantID, old.SessionID, [32]byte{0x99}, swapTarget(old, "sid-new"), nil)
	if !errors.Is(err, ErrRefreshHashMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}
	if _, err := store.Peek(ctx, old.TenantID, old.SessionID); !errors.Is(err, redis.Nil) {
		t.Fatalf("old session must be deleted on mismatch, got %v", err)
	}
	if ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID); len(ids) != 0 {
		t.Fatalf("index entry left behind: %v", ids)
	}
	if n, _ := store.TenantSessionCount(ctx, old.TenantID); n != 0 {
		t.Fatalf("tenant counter not decremented: %d", n)
	}
}

// Many goroutines presenting the same refresh hash: exactly one swap wins,
// everything else loses the CAS, and no second live session or orphaned
// index entry remains.
func TestSwapSessionConcurrentSameHashExactlyOneWins(t *testing.T) {
	const rounds = 25
	const workers = 8

	for round := 0; round < rounds; round++ {
		store, _, done := newSessionStoreTest(t)
		ctx := context.Background()

		old := testSession()
		if err := store.Save(ctx, old, time.Hour); err != nil {
			t.Fatal(err)
		}

		var wins, losses int32
		var wg sync.WaitGroup
		barrier := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				next := swapTarget(old, "sid-new-"+string(rune('a'+i)))
				<-barrier
				if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err == nil {
					atomic.AddInt32(&wins, 1)
				} else {
					atomic.AddInt32(&losses, 1)
				}
			}(i)
		}
		close(barrier)
		wg.Wait()

		if wins != 1 || losses != workers-1 {
			done()
			t.Fatalf("round %d: wins=%d losses=%d, want exactly one winner", round, wins, losses)
		}
		ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID)
		// The first loser to run after the winner finds the old key gone
		// (not found); a loser that runs first cannot exist since only one
		// presented hash matches. The index must hold only the winner.
		if len(ids) != 1 || ids[0] == old.SessionID {
			done()
			t.Fatalf("round %d: index = %v, want exactly the winning session", round, ids)
		}
		done()
	}
}

func TestAssuranceEncodingRoundTrip(t *testing.T) {
	cases := []Assurance{
		{},
		{MFAAt: 1700000000, MFAMethod: "totp", AuthAt: 1700000000},
		{MFAAt: 1700000000, MFAMethod: "webauthn", AuthAt: 1700000900},
		{AuthAt: 1700000900},
	}
	for _, in := range cases {
		out, err := DecodeAssurance(EncodeAssurance(in))
		if err != nil || out != in {
			t.Fatalf("round trip of %+v gave %+v, %v", in, out, err)
		}
	}
	for _, bad := range []string{"", "x", "2|1|totp|1", "1|a|totp|1", "1|1|totp|b", "1|1|totp"} {
		if _, err := DecodeAssurance(bad); !errors.Is(err, ErrAssuranceCorrupt) {
			t.Fatalf("DecodeAssurance(%q) = %v, want ErrAssuranceCorrupt", bad, err)
		}
	}
}

func TestPeekIsReadOnlyAndKeepsExpiredSessions(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	expired := testSession()
	expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	if err := store.Save(ctx, expired, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := store.Peek(ctx, expired.TenantID, expired.SessionID)
	if err != nil || got.ExpiresAt != expired.ExpiresAt {
		t.Fatalf("Peek should return an expired session untouched, got %v %v", got, err)
	}
	if n, _ := rdb.Exists(ctx, store.key(expired.TenantID, expired.SessionID)).Result(); n != 1 {
		t.Fatal("Peek must not delete an expired session")
	}
	if _, err := store.Peek(ctx, "t-1", "nope"); !errors.Is(err, redis.Nil) {
		t.Fatalf("missing session should be redis.Nil, got %v", err)
	}
}
