//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

func TestRefreshRaceSingleWinner(t *testing.T) {
	ctx := context.Background()
	store, _, cleanup := newIntegrationStore(t)
	defer cleanup()

	current := hashByte(1)
	sess := makeSession("0", "u1", "sid-race", current)
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		next := hashByte(byte(i + 2))
		go func(nextHash [32]byte) {
			defer wg.Done()
			<-start
			_, err := store.RotateRefreshHash(ctx, "0", "sid-race", current, nextHash)
			results <- err
		}(next)
	}

	close(start)
	wg.Wait()
	close(results)

	success := 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, session.ErrRefreshHashMismatch), errors.Is(err, redis.Nil):
		default:
			t.Fatalf("unexpected rotate error: %v", err)
		}
	}

	if success != 1 {
		t.Fatalf("expected exactly one winner, got %d", success)
	}
}
