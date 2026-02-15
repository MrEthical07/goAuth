package session

import (
	"context"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newSessionStoreTest(t *testing.T) (*Store, *redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewStore(rdb, "as", true, false, 0)
	return store, rdb, func() {
		rdb.Close()
		mr.Close()
	}
}

func testSession() *Session {
	m := permission.Mask64(1)
	now := time.Now()
	return &Session{
		SessionID:   "sid-1",
		UserID:      "u-1",
		TenantID:    "t-1",
		Role:        "member",
		Mask:        &m,
		CreatedAt:   now.Unix(),
		ExpiresAt:   now.Add(time.Hour).Unix(),
		RefreshHash: [32]byte{1},
	}
}

func TestDeleteSessionIdempotentCounterAndIndex(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()
	sess := testSession()

	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save session: %v", err)
	}
	if err := store.Delete(ctx, sess.TenantID, sess.SessionID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := store.Delete(ctx, sess.TenantID, sess.SessionID); err != nil {
		t.Fatalf("second delete: %v", err)
	}

	count, err := store.TenantSessionCount(ctx, sess.TenantID)
	if err != nil {
		t.Fatalf("tenant count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected tenant count 0, got %d", count)
	}

	userSet := store.userKey(sess.TenantID, sess.UserID)
	members, err := rdb.SMembers(ctx, userSet).Result()
	if err != nil {
		t.Fatalf("smembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected no user index members, got %v", members)
	}
}
