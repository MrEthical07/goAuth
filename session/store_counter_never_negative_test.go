package session

import (
	"context"
	"testing"
	"time"
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
