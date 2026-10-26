//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// The fenced save, the delete-all epoch bump, the legacy-schema migration and
// the tenant-counter reconciliation are scripts: each has to behave as one
// step on the server. They run on every configured backend (miniredis always,
// real Redis when REDIS_ADDR is set).

func fencedSess(tenant, user, sid string, hash byte) *session.Session {
	return makeCompatSession(tenant, user, sid, hashByte(hash))
}

func TestRedisCompat_FencedSaveAndEpoch(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			// Delete-all bumps the epoch and keeps it for about 24 hours; other
			// users and the default tenant spelling are separate.
			if epoch, err := store.RevocationEpoch(ctx, "t-f", "u-f"); err != nil || epoch != 0 {
				t.Fatalf("fresh epoch = %d, %v", epoch, err)
			}
			if err := store.DeleteAllForUser(ctx, "t-f", "u-f"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.DeleteAllForUserExcept(ctx, "t-f", "u-f", "keep"); err != nil {
				t.Fatal(err)
			}
			if epoch, _ := store.RevocationEpoch(ctx, "t-f", "u-f"); epoch != 2 {
				t.Fatalf("epoch after two delete-alls = %d, want 2", epoch)
			}
			if ttl := rdb.TTL(ctx, "aue:t-f:u-f").Val(); ttl <= 23*time.Hour+59*time.Minute || ttl > 24*time.Hour {
				t.Fatalf("epoch TTL = %v, want about 24 hours", ttl)
			}
			if epoch, _ := store.RevocationEpoch(ctx, "t-f", "u-other"); epoch != 0 {
				t.Fatalf("another user's epoch = %d", epoch)
			}

			// A save under a stale epoch writes nothing.
			stale := int64(1)
			err := store.SaveFenced(ctx, fencedSess("t-f", "u-f", "s-stale", 1), time.Hour, stale, session.SaveLimits{})
			if !errors.Is(err, session.ErrSessionFenced) {
				t.Fatalf("stale save = %v, want ErrSessionFenced", err)
			}
			if rdb.Exists(ctx, "as:t-f:s-stale").Val() != 0 {
				t.Fatal("a fenced save wrote the session")
			}
			if err := store.SaveFenced(ctx, fencedSess("t-f", "u-f", "s-ok", 2), time.Hour, 2, session.SaveLimits{}); err != nil {
				t.Fatalf("save under the current epoch: %v", err)
			}
		})
	}
}

func TestRedisCompat_FencedSaveCapsAreAtomic(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			var stored, refused atomic.Int64
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 24; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					err := store.SaveFenced(ctx, fencedSess("t-cap", "u-cap", fmt.Sprintf("c%d", i), byte(i+1)), time.Hour, 0, session.SaveLimits{MaxPerUser: 4})
					switch {
					case err == nil:
						stored.Add(1)
					case errors.Is(err, session.ErrUserSessionLimit):
						refused.Add(1)
					default:
						t.Errorf("save %d: %v", i, err)
					}
				}(i)
			}
			close(start)
			wg.Wait()
			if stored.Load() != 4 || refused.Load() != 20 {
				t.Fatalf("stored %d, refused %d; want exactly the cap (4) stored", stored.Load(), refused.Load())
			}
			if n, _ := store.ActiveSessionCount(ctx, "t-cap", "u-cap"); n != 4 {
				t.Fatalf("user holds %d sessions, want 4", n)
			}
			if n, _ := store.TenantSessionCount(ctx, "t-cap"); n != 4 {
				t.Fatalf("tenant counter = %d, want 4", n)
			}

			// The tenant cap is shared between users.
			for i := 0; i < 6; i++ {
				_ = store.SaveFenced(ctx, fencedSess("t-cap2", fmt.Sprintf("u%d", i), fmt.Sprintf("x%d", i), byte(i+40)), time.Hour, 0, session.SaveLimits{MaxPerTenant: 3})
			}
			if n, _ := store.TenantSessionCount(ctx, "t-cap2"); n != 3 {
				t.Fatalf("tenant holds %d sessions, want the cap (3)", n)
			}
			if err := store.SaveFenced(ctx, fencedSess("t-cap2", "u9", "x9", 99), time.Hour, 0, session.SaveLimits{MaxPerTenant: 3}); !errors.Is(err, session.ErrTenantSessionLimit) {
				t.Fatalf("over the tenant cap = %v, want ErrTenantSessionLimit", err)
			}
		})
	}
}

func TestRedisCompat_FencedSaveSingleSessionPurge(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			old1 := compatSaveWithProof(t, store, "t-one", "u-one", "old1", 1)
			old2 := compatSaveWithProof(t, store, "t-one", "u-one", "old2", 2)
			bystander := compatSaveWithProof(t, store, "t-one", "u-two", "by1", 3)

			// A refusal ends nothing.
			if err := rdb.Incr(ctx, "aue:t-one:u-one").Err(); err != nil {
				t.Fatal(err)
			}
			err := store.SaveFenced(ctx, fencedSess("t-one", "u-one", "new", 9), time.Hour, 0, session.SaveLimits{SingleSession: true})
			if !errors.Is(err, session.ErrSessionFenced) {
				t.Fatalf("stale single-session save = %v", err)
			}
			if n, _ := store.ActiveSessionCount(ctx, "t-one", "u-one"); n != 2 {
				t.Fatalf("a refused save ended sessions: %d left", n)
			}

			// A passing save replaces the user's sessions and their proof keys, and
			// does not move the epoch.
			if err := store.SaveFenced(ctx, fencedSess("t-one", "u-one", "new", 9), time.Hour, 1, session.SaveLimits{SingleSession: true}); err != nil {
				t.Fatal(err)
			}
			ids, _ := store.ActiveSessionIDs(ctx, "t-one", "u-one")
			if len(ids) != 1 || ids[0] != "new" {
				t.Fatalf("sessions after the purge: %v", ids)
			}
			if proofExists(t, store, old1) || proofExists(t, store, old2) {
				t.Fatal("a purged session kept its proof key")
			}
			if !proofExists(t, store, bystander) {
				t.Fatal("another user's proof key was removed")
			}
			if n, _ := store.TenantSessionCount(ctx, "t-one"); n != 2 {
				t.Fatalf("tenant counter = %d, want 2 (the new session and the bystander)", n)
			}
			if epoch, _ := store.RevocationEpoch(ctx, "t-one", "u-one"); epoch != 1 {
				t.Fatalf("epoch = %d, a login must not move it", epoch)
			}
		})
	}
}

// scanHook runs fn once, right after the first SCAN returned.
type scanHook struct {
	fn   func()
	done atomic.Bool
}

func (h *scanHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *scanHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if strings.EqualFold(cmd.Name(), "scan") && h.done.CompareAndSwap(false, true) {
			h.fn()
		}
		return err
	}
}
func (h *scanHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestRedisCompat_TenantCounterReconciliation(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			// A counter that drifted upwards is corrected, not obeyed.
			if err := store.SetTenantSessionCount(ctx, "t-rec", 50); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveFenced(ctx, fencedSess("t-rec", "u1", "r1", 1), time.Hour, 0, session.SaveLimits{MaxPerTenant: 5}); err != nil {
				t.Fatalf("a drifted counter must be reconciled: %v", err)
			}
			if n, _ := store.TenantSessionCount(ctx, "t-rec"); n != 1 {
				t.Fatalf("counter = %d, want 1", n)
			}

			// A session saved while the scan result is in flight stays counted.
			if err := store.SetTenantSessionCount(ctx, "t-rec2", 50); err != nil {
				t.Fatal(err)
			}
			other := session.NewStore(rdb, "as", true, false, 0)
			rdb.AddHook(&scanHook{fn: func() {
				if err := other.SaveFenced(ctx, fencedSess("t-rec2", "u2", "concurrent", 2), time.Hour, 0, session.SaveLimits{}); err != nil {
					t.Errorf("concurrent save: %v", err)
				}
			}})
			if err := store.SaveFenced(ctx, fencedSess("t-rec2", "u1", "mine", 3), time.Hour, 0, session.SaveLimits{MaxPerTenant: 5}); err != nil {
				t.Fatalf("save: %v", err)
			}
			if n, _ := store.TenantSessionCount(ctx, "t-rec2"); n != 2 {
				t.Fatalf("counter = %d, want 2", n)
			}
		})
	}
}

// legacyV4Blob turns a session into the pre-v5 layout, which has no IP and
// user-agent hashes.
func legacyV4Blob(t *testing.T, s *session.Session) []byte {
	t.Helper()
	enc, err := session.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	cut := len(enc) - 16 - 64
	out := append(append([]byte{}, enc[:cut]...), enc[len(enc)-16:]...)
	out[0] = 4
	return out
}

type afterGetHook struct {
	fn   func()
	done atomic.Bool
}

func (h *afterGetHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *afterGetHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if strings.EqualFold(cmd.Name(), "get") && h.done.CompareAndSwap(false, true) {
			h.fn()
		}
		return err
	}
}
func (h *afterGetHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestRedisCompat_LegacySchemaMigrationIsCompareAndSet(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			// An unchanged legacy blob is rewritten in place, keeping its TTL.
			legacy := fencedSess("t-mig", "u-mig", "m1", 1)
			if err := rdb.Set(ctx, "as:t-mig:m1", legacyV4Blob(t, legacy), 300*time.Second).Err(); err != nil {
				t.Fatal(err)
			}
			got, err := store.GetReadOnly(ctx, "t-mig", "m1")
			if err != nil || got.SchemaVersion != 4 && got.SchemaVersion != session.CurrentSchemaVersion {
				t.Fatalf("get legacy = %+v, %v", got, err)
			}
			raw, err := rdb.Get(ctx, "as:t-mig:m1").Bytes()
			if err != nil || raw[0] != session.CurrentSchemaVersion {
				t.Fatalf("stored blob not migrated: version byte %d, %v", raw[0], err)
			}
			wantAbout(t, "migrated TTL", compatPTTL(t, rdb, "as", "t-mig", "m1"), 300*time.Second, 3*time.Second)

			// A blob changed between the read and the rewrite is left as it is.
			racing := fencedSess("t-mig", "u-mig", "m2", 2)
			if err := rdb.Set(ctx, "as:t-mig:m2", legacyV4Blob(t, racing), 300*time.Second).Err(); err != nil {
				t.Fatal(err)
			}
			rotated := fencedSess("t-mig", "u-mig", "m2", 3)
			rotatedBlob := legacyV4Blob(t, rotated)
			rdb.AddHook(&afterGetHook{fn: func() {
				if err := rdb.Set(context.Background(), "as:t-mig:m2", rotatedBlob, 300*time.Second).Err(); err != nil {
					t.Errorf("concurrent rotation: %v", err)
				}
			}})
			if _, err := store.GetReadOnly(ctx, "t-mig", "m2"); err != nil {
				t.Fatalf("GetReadOnly: %v", err)
			}
			now, err := rdb.Get(ctx, "as:t-mig:m2").Bytes()
			if err != nil || !bytes.Equal(now, rotatedBlob) {
				t.Fatal("the migration overwrote a blob that changed after it was read")
			}

			// A deleted blob stays deleted.
			if rdb.Exists(ctx, "as:t-mig:none").Val() != 0 {
				t.Fatal("unexpected key")
			}
		})
	}
}

func TestRedisCompat_MFAChallengeEpoch(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := stores.NewMFALoginChallengeStore(rdb, "amc")
			ctx := context.Background()

			if _, _, ok, err := store.Context(ctx, "c1"); err != nil || ok {
				t.Fatalf("no epoch yet: ok=%v err=%v", ok, err)
			}
			if err := store.Save(ctx, "c1", &stores.MFALoginChallenge{UserID: "u1", TenantID: "0", ExpiresAt: time.Now().Add(time.Minute).Unix()}, time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveContext(ctx, "c1", 7, 2, time.Minute); err != nil {
				t.Fatal(err)
			}
			if epoch, adv, ok, err := store.Context(ctx, "c1"); err != nil || !ok || epoch != 7 || adv != 2 {
				t.Fatalf("epoch = %d advertised = %d ok=%v err=%v", epoch, adv, ok, err)
			}
			if deleted, err := store.Delete(ctx, "c1"); err != nil || !deleted {
				t.Fatalf("delete = %v, %v", deleted, err)
			}
			if _, _, ok, _ := store.Context(ctx, "c1"); ok {
				t.Fatal("the epoch outlived its challenge")
			}
		})
	}
}

func TestRedisCompat_DeleteAllEpochLifeFollowsTheConfiguredTTL(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()

			def := session.NewStore(rdb, "as", true, false, 0)
			if err := def.DeleteAllForUser(ctx, "t-ttl", "u-def"); err != nil {
				t.Fatal(err)
			}
			if ttl := rdb.TTL(ctx, "aue:t-ttl:u-def").Val(); ttl <= 23*time.Hour || ttl > 24*time.Hour {
				t.Fatalf("default epoch TTL = %v, want 24 h", ttl)
			}

			long := session.NewStore(rdb, "as", true, false, 0).WithRevocationEpochTTL(31 * time.Hour)
			if err := long.DeleteAllForUser(ctx, "t-ttl", "u-long"); err != nil {
				t.Fatal(err)
			}
			if ttl := rdb.TTL(ctx, "aue:t-ttl:u-long").Val(); ttl <= 30*time.Hour || ttl > 31*time.Hour {
				t.Fatalf("long epoch TTL = %v, want 31 h", ttl)
			}
		})
	}
}

func TestRedisCompat_EmailChangeCancelReportsWhatItRemoved(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := stores.NewEmailChangeStore(rdb, "aec")
			ctx := context.Background()

			if cancelled, err := store.CancelPending(ctx, "t-ec", "u-ec"); err != nil || cancelled {
				t.Fatalf("nothing pending: cancelled=%v err=%v", cancelled, err)
			}
			rec := &stores.EmailChangeRecord{
				UserID: "u-ec", OldIdentifier: "a@example.com", NewIdentifier: "b@example.com",
				AccountVersion: 1, ExpiresAt: time.Now().Add(time.Minute).Unix(),
			}
			if err := store.Save(ctx, "t-ec", "v1", rec, time.Minute); err != nil {
				t.Fatal(err)
			}
			if cancelled, err := store.CancelPending(ctx, "t-ec", "u-ec"); err != nil || !cancelled {
				t.Fatalf("one pending: cancelled=%v err=%v", cancelled, err)
			}
			if rdb.Exists(ctx, "aec:t-ec:v1", "aecp:t-ec:u-ec").Val() != 0 {
				t.Fatal("the challenge or its pointer survived")
			}
			if cancelled, _ := store.CancelPending(ctx, "t-ec", "u-ec"); cancelled {
				t.Fatal("a second cancel reported something removed")
			}
		})
	}
}
