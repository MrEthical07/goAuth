//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

func TestStoreConsistencyDeleteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, _, cleanup := newIntegrationStore(t)
	defer cleanup()

	sess := makeSession("0", "u1", "sid-delete", hashByte(5))
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := store.Delete(ctx, "0", "sid-delete"); err != nil {
		t.Fatalf("first Delete failed: %v", err)
	}
	if err := store.Delete(ctx, "0", "sid-delete"); err != nil {
		t.Fatalf("second Delete failed: %v", err)
	}

	count, err := store.TenantSessionCount(ctx, "0")
	if err != nil {
		t.Fatalf("TenantSessionCount failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected tenant count 0, got %d", count)
	}
}

func TestStoreConsistencyCounterNeverNegative(t *testing.T) {
	ctx := context.Background()
	store, _, cleanup := newIntegrationStore(t)
	defer cleanup()

	current := hashByte(7)
	wrong := hashByte(9)
	next := hashByte(8)
	sess := makeSession("0", "u2", "sid-mismatch", current)
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := store.RotateRefreshHash(ctx, "0", "sid-mismatch", wrong, next); !errors.Is(err, session.ErrRefreshHashMismatch) {
		t.Fatalf("expected ErrRefreshHashMismatch, got %v", err)
	}
	if _, err := store.RotateRefreshHash(ctx, "0", "sid-mismatch", wrong, next); !errors.Is(err, redis.Nil) {
		t.Fatalf("expected redis.Nil after delete, got %v", err)
	}

	count, err := store.TenantSessionCount(ctx, "0")
	if err != nil {
		t.Fatalf("TenantSessionCount failed: %v", err)
	}
	if count < 0 {
		t.Fatalf("tenant count must never be negative, got %d", count)
	}
}
