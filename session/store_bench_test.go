package session

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// benchStore runs against the Redis at REDIS_ADDR when it is set (so round
// trips cost what they cost), and against miniredis otherwise.
func benchStore(b *testing.B) (*Store, redis.UniversalClient) {
	b.Helper()
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: addr})
		b.Cleanup(func() { rdb.FlushDB(context.Background()); _ = rdb.Close() })
		return NewStore(rdb, "as", true, false, 0), rdb
	}
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b.Cleanup(func() { _ = rdb.Close(); mr.Close() })
	return NewStore(rdb, "as", true, false, 0), rdb
}

func benchSessions(n int) []*Session {
	out := make([]*Session, n)
	for i := range out {
		s := testSession()
		s.TenantID, s.UserID = "t-bench", "u-bench"
		s.SessionID = fmt.Sprintf("bench-%d", i)
		out[i] = s
	}
	return out
}

// BenchmarkStoreDelete is one logout: the session is saved outside the timer.
func BenchmarkStoreDelete(b *testing.B) {
	store, _ := benchStore(b)
	ctx := context.Background()
	s := benchSessions(1)[0]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := store.Save(ctx, s, time.Hour); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := store.Delete(ctx, s.TenantID, s.SessionID); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStoreDeleteAllForUser is one logout-everywhere with 1, 10 and 100
// sessions: the sessions are saved outside the timer.
func BenchmarkStoreDeleteAllForUser(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("sessions=%d", n), func(b *testing.B) {
			store, _ := benchStore(b)
			ctx := context.Background()
			sessions := benchSessions(n)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				for _, s := range sessions {
					if err := store.Save(ctx, s, time.Hour); err != nil {
						b.Fatal(err)
					}
				}
				b.StartTimer()
				if err := store.DeleteAllForUser(ctx, "t-bench", "u-bench"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
