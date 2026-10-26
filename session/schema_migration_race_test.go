package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/redis/go-redis/v9"
)

// redisCommandHook runs after hooks for one command name, letting a test
// interleave another client's write between two of the store's commands.
type redisCommandHook struct {
	command string
	after   func()
}

func (h redisCommandHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h redisCommandHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if strings.EqualFold(cmd.Name(), h.command) && h.after != nil {
			h.after()
		}
		return err
	}
}

func (h redisCommandHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// Schema migration reads the blob, then rewrites it. A session deleted in
// between must stay deleted; a plain SET would resurrect it with its old
// refresh hash.
func TestSchemaMigrationDoesNotResurrectDeletedSession(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()

	mask := permission.Mask64(1)
	now := time.Now()
	legacy := &Session{
		SchemaVersion:     4,
		SessionID:         "sid-legacy",
		UserID:            "u-legacy",
		TenantID:          "t-legacy",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		RefreshHash:       [32]byte{7},
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}
	key := store.key(legacy.TenantID, legacy.SessionID)
	ctx := context.Background()
	if err := rdb.Set(ctx, key, encodeLegacyV4Session(t, legacy), time.Hour).Err(); err != nil {
		t.Fatalf("seed legacy session failed: %v", err)
	}

	deleted := false
	rdb.AddHook(redisCommandHook{command: "get", after: func() {
		if deleted {
			return
		}
		deleted = true
		if err := rdb.Del(ctx, key).Err(); err != nil {
			t.Errorf("concurrent delete failed: %v", err)
		}
	}})

	if _, err := store.GetReadOnly(ctx, legacy.TenantID, legacy.SessionID); err != nil {
		t.Fatalf("GetReadOnly failed: %v", err)
	}
	if !deleted {
		t.Fatal("interleaved delete never ran; the test did not exercise the race")
	}

	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		t.Fatalf("exists failed: %v", err)
	}
	if exists != 0 {
		t.Fatal("schema migration resurrected a session that was deleted mid-migration")
	}
}

// FAILED-BEFORE (R2-20): the rewrite SET the blob it had read with XX, which
// only guards against a deleted key. A refresh rotation that landed between the
// read and the rewrite was overwritten, restoring the refresh hash that had
// just been rotated out and logging the owner out.
func TestSchemaMigrationDoesNotUndoARefreshRotation(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()

	mask := permission.Mask64(1)
	now := time.Now()
	h1, h2, h3 := [32]byte{1}, [32]byte{2}, [32]byte{3}
	legacy := &Session{
		SchemaVersion:     4,
		SessionID:         "sid-rot",
		UserID:            "u-rot",
		TenantID:          "t-rot",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		RefreshHash:       h1,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}
	key := store.key(legacy.TenantID, legacy.SessionID)
	ctx := context.Background()
	if err := rdb.Set(ctx, key, encodeLegacyV4Session(t, legacy), time.Hour).Err(); err != nil {
		t.Fatalf("seed legacy session failed: %v", err)
	}
	if err := rdb.SAdd(ctx, store.userKey(legacy.TenantID, legacy.UserID), legacy.SessionID).Err(); err != nil {
		t.Fatalf("seed index failed: %v", err)
	}

	rotated := false
	rdb.AddHook(redisCommandHook{command: "get", after: func() {
		if rotated {
			return
		}
		rotated = true
		if _, err := store.RotateRefreshHash(ctx, legacy.TenantID, legacy.SessionID, h1, h2); err != nil {
			t.Errorf("concurrent rotation failed: %v", err)
		}
	}})

	if _, err := store.GetReadOnly(ctx, legacy.TenantID, legacy.SessionID); err != nil {
		t.Fatalf("GetReadOnly failed: %v", err)
	}
	if !rotated {
		t.Fatal("interleaved rotation never ran; the test did not exercise the race")
	}

	blob, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		t.Fatalf("stored session missing: %v", err)
	}
	stored, err := Decode(blob)
	if err != nil {
		t.Fatalf("decode stored session failed: %v", err)
	}
	if stored.RefreshHash != h2 {
		t.Fatal("the migration put the rotated-out refresh hash back")
	}
	if stored.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("the session was not lifted to v%d, it is v%d", CurrentSchemaVersion, stored.SchemaVersion)
	}
	if _, err := store.RotateRefreshHash(ctx, legacy.TenantID, legacy.SessionID, h2, h3); err != nil {
		t.Fatalf("the owner's current refresh hash was refused: %v", err)
	}
}
