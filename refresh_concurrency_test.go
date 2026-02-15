package goAuth

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestRefreshConcurrencySingleWinner(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)

	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _, err := engine.Refresh(context.Background(), refresh)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	success := 0
	fail := 0
	for err := range results {
		if err == nil {
			success++
			continue
		}
		if errors.Is(err, ErrRefreshReuse) || errors.Is(err, ErrSessionNotFound) {
			fail++
			continue
		}
		t.Fatalf("unexpected refresh error: %v", err)
	}

	if success != 1 {
		t.Fatalf("expected exactly one refresh success, got %d", success)
	}
	if fail != n-1 {
		t.Fatalf("expected %d refresh failures, got %d", n-1, fail)
	}

	if keys := rdb.DBSize(context.Background()).Val(); keys < 0 {
		t.Fatalf("unexpected redis db size %d", keys)
	}
}
