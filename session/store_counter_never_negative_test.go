package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestTenantCounterNeverNegative(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()
	sess := testSession()

	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save session: %v", err)
	}
	if err := store.Delete(ctx, sess.TenantID, sess.SessionID); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	for i := 0; i < 10; i++ {
		if err := store.Delete(ctx, sess.TenantID, sess.SessionID); err != nil {
			t.Fatalf("repeat delete %d: %v", i, err)
		}
	}

	count, err := store.TenantSessionCount(ctx, sess.TenantID)
	if err != nil {
		t.Fatalf("tenant count: %v", err)
	}
	if count < 0 {
		t.Fatalf("counter must never be negative, got %d", count)
	}
}

func TestTenantCounterNeverNegativeUnderConcurrentOps(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()

	ctx := context.Background()
	const (
		tenantID  = "t-1"
		userID    = "u-1"
		sessionsN = 24
		workers   = 16
		rounds    = 100
	)

	for i := 0; i < sessionsN; i++ {
		sess := testSession()
		sess.TenantID = tenantID
		sess.UserID = userID
		sess.SessionID = fmt.Sprintf("sid-%d", i)
		sess.RefreshHash = [32]byte{byte(i + 1)}
		if err := store.Save(ctx, sess, time.Hour); err != nil {
			t.Fatalf("save session %d failed: %v", i, err)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			<-start

			for r := 0; r < rounds; r++ {
				sid := fmt.Sprintf("sid-%d", (workerID+r)%sessionsN)

				switch (workerID + r) % 3 {
				case 0:
					if err := store.Delete(ctx, tenantID, sid); err != nil {
						t.Errorf("delete failed: %v", err)
					}
				case 1:
					var wrong [32]byte
					wrong[0] = 0xFF
					var next [32]byte
					next[0] = byte((workerID + r + 7) % 255)
					_, err := store.RotateRefreshHash(ctx, tenantID, sid, wrong, next)
					if err != nil && !errors.Is(err, ErrRefreshHashMismatch) && !errors.Is(err, redis.Nil) {
						t.Errorf("rotate failed: %v", err)
					}
				default:
					if err := store.DeleteAllForUser(ctx, tenantID, userID); err != nil {
						t.Errorf("delete-all failed: %v", err)
					}
				}
			}
		}(w)
	}

	close(start)
	wg.Wait()

	count, err := store.TenantSessionCount(ctx, tenantID)
	if err != nil {
		t.Fatalf("TenantSessionCount failed: %v", err)
	}
	if count < 0 {
		t.Fatalf("counter must never be negative, got %d", count)
	}
}
