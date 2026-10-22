package session

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// DeleteAllForUser used to read the user's session set, count, check and then
// delete in separate round trips. A session saved in between survived the
// "logout everywhere", and the counter, lowered by what had been counted
// rather than by what was deleted, drifted from the sessions that existed.
//
// This test uses only the API the old implementation had, so it can run
// against it: writers save sessions for one user while DeleteAllForUser runs.
// Afterwards (a) no session whose Save had returned before the call began
// survives, and (b) the tenant counter equals the sessions that exist.
func TestDeleteAllForUserIsAtomicUnderConcurrentSaves(t *testing.T) {
	ctx := context.Background()
	const (
		rounds   = 25
		existing = 30
		writers  = 8
		tenant   = "t-1"
		user     = "u-1"
	)

	for round := 0; round < rounds; round++ {
		store, rdb, done := newSessionStoreTest(t)

		save := func(id string) error {
			s := testSession()
			s.SessionID = id
			s.TenantID = tenant
			s.UserID = user
			return store.Save(ctx, s, time.Hour)
		}

		var before []string
		for i := 0; i < existing; i++ {
			id := fmt.Sprintf("old-%d", i)
			if err := save(id); err != nil {
				t.Fatalf("save: %v", err)
			}
			before = append(before, id)
		}

		var (
			started atomic.Bool
			stop    atomic.Bool
			mu      sync.Mutex
			wg      sync.WaitGroup
		)
		beforeCall := append([]string(nil), before...)
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					id := fmt.Sprintf("w%d-%d", w, i)
					if err := save(id); err != nil {
						t.Errorf("save: %v", err)
						return
					}
					// Save returned and the call had not started when this
					// flag was read, so the session predates the call.
					if !started.Load() {
						mu.Lock()
						beforeCall = append(beforeCall, id)
						mu.Unlock()
					}
				}
			}(w)
		}

		time.Sleep(time.Duration(2+round%5) * time.Millisecond)
		started.Store(true)
		if err := store.DeleteAllForUser(ctx, tenant, user); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		stop.Store(true)
		wg.Wait()

		for _, id := range beforeCall {
			if n, _ := rdb.Exists(ctx, store.key(tenant, id)).Result(); n != 0 {
				t.Fatalf("round %d: session %s existed before DeleteAllForUser began and survived it", round, id)
			}
		}

		live, err := store.EstimateActiveSessions(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		count, err := store.TenantSessionCount(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if count != live {
			t.Fatalf("round %d: tenant counter = %d, live sessions = %d", round, count, live)
		}
		indexed, _ := store.ActiveSessionCount(ctx, tenant, user)
		if indexed != live {
			t.Fatalf("round %d: user index holds %d sessions, live sessions = %d", round, indexed, live)
		}
		done()
	}
}
