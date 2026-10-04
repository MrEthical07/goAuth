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
	rdb.AddHook(redisCommandHook{command: "pttl", after: func() {
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
