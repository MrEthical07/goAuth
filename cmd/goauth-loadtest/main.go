package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type sessionState struct {
	sid  string
	hash [32]byte
	mu   sync.Mutex
}

func main() {
	var (
		sessions    = flag.Int("sessions", 100000, "number of sessions to seed")
		concurrency = flag.Int("concurrency", 256, "number of concurrent workers")
		ops         = flag.Int("ops", 200000, "operations per phase (validate + refresh)")
		redisAddr   = flag.String("redis-addr", "", "redis address; if empty, REDIS_ADDR env or miniredis is used")
		prefix      = flag.String("prefix", "as", "session key prefix")
	)
	flag.Parse()

	if *sessions <= 0 || *concurrency <= 0 || *ops <= 0 {
		fmt.Fprintln(os.Stderr, "sessions, concurrency, and ops must be > 0")
		os.Exit(2)
	}

	ctx := context.Background()

	addr := *redisAddr
	if addr == "" {
		addr = os.Getenv("REDIS_ADDR")
	}

	var (
		cleanup func()
		client  redis.UniversalClient
	)
	if addr == "" {
		mr, err := miniredis.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to start miniredis: %v\n", err)
			os.Exit(1)
		}
		addr = mr.Addr()
		client = redis.NewUniversalClient(&redis.UniversalOptions{
			Addrs: []string{addr},
		})
		cleanup = func() {
			_ = client.Close()
			mr.Close()
		}
		fmt.Printf("using miniredis at %s\n", addr)
	} else {
		client = redis.NewUniversalClient(&redis.UniversalOptions{
			Addrs: []string{addr},
		})
		cleanup = func() { _ = client.Close() }
		fmt.Printf("using redis at %s\n", addr)
	}
	defer cleanup()

	store := session.NewStore(client, *prefix, false, false, 0)

	states := make([]sessionState, *sessions)
	fmt.Printf("seeding %d sessions...\n", *sessions)
	startSeed := time.Now()
	for i := 0; i < *sessions; i++ {
		sid := fmt.Sprintf("sid-%d", i)
		h := hashFor(i)
		states[i] = sessionState{sid: sid, hash: h}
		if err := store.Save(ctx, buildSession(sid, h), 24*time.Hour); err != nil {
			fmt.Fprintf(os.Stderr, "save failed: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("seeded in %s\n", time.Since(startSeed).Round(time.Millisecond))

	validateStats := runValidatePhase(ctx, store, states, *ops, *concurrency)
	refreshStats := runRefreshPhase(ctx, store, states, *ops, *concurrency)

	fmt.Println("---- results ----")
	printStats("validate", validateStats)
	printStats("refresh", refreshStats)
}

func runValidatePhase(ctx context.Context, store *session.Store, states []sessionState, ops, concurrency int) phaseStats {
	var (
		wg        sync.WaitGroup
		cursor    int64
		failures  int64
		latencies = make([]time.Duration, 0, ops)
		mu        sync.Mutex
	)

	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(worker)*7919))
			for {
				i := int(atomic.AddInt64(&cursor, 1)) - 1
				if i >= ops {
					return
				}
				idx := r.Intn(len(states))
				t0 := time.Now()
				_, err := store.GetReadOnly(ctx, "0", states[idx].sid)
				d := time.Since(t0)
				if err != nil {
					atomic.AddInt64(&failures, 1)
				}
				mu.Lock()
				latencies = append(latencies, d)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	total := time.Since(start)
	return computeStats(total, latencies, failures)
}

func runRefreshPhase(ctx context.Context, store *session.Store, states []sessionState, ops, concurrency int) phaseStats {
	var (
		wg        sync.WaitGroup
		cursor    int64
		failures  int64
		latencies = make([]time.Duration, 0, ops)
		mu        sync.Mutex
	)

	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(worker)*6151))
			for {
				i := int(atomic.AddInt64(&cursor, 1)) - 1
				if i >= ops {
					return
				}
				idx := r.Intn(len(states))
				state := &states[idx]

				state.mu.Lock()
				current := state.hash
				next := nextHash(current, i+worker+1)
				t0 := time.Now()
				_, err := store.RotateRefreshHash(ctx, "0", state.sid, current, next)
				d := time.Since(t0)
				if err == nil {
					state.hash = next
				} else {
					atomic.AddInt64(&failures, 1)
				}
				state.mu.Unlock()

				mu.Lock()
				latencies = append(latencies, d)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	total := time.Since(start)
	return computeStats(total, latencies, failures)
}

type phaseStats struct {
	total    time.Duration
	ops      int
	failures int64
	p50      time.Duration
	p95      time.Duration
	p99      time.Duration
	opsPerS  float64
}

func computeStats(total time.Duration, samples []time.Duration, failures int64) phaseStats {
	if len(samples) == 0 {
		return phaseStats{total: total}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return phaseStats{
		total:    total,
		ops:      len(samples),
		failures: failures,
		p50:      percentile(samples, 50),
		p95:      percentile(samples, 95),
		p99:      percentile(samples, 99),
		opsPerS:  float64(len(samples)) / total.Seconds(),
	}
}

func percentile(samples []time.Duration, p int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	if p <= 0 {
		return samples[0]
	}
	if p >= 100 {
		return samples[len(samples)-1]
	}
	idx := (len(samples) - 1) * p / 100
	return samples[idx]
}

func printStats(name string, s phaseStats) {
	fmt.Printf("%s: ops=%d failures=%d total=%s ops/sec=%.0f p50=%s p95=%s p99=%s\n",
		name,
		s.ops,
		s.failures,
		s.total.Round(time.Millisecond),
		s.opsPerS,
		s.p50.Round(time.Microsecond),
		s.p95.Round(time.Microsecond),
		s.p99.Round(time.Microsecond),
	)
}

func buildSession(sid string, refreshHash [32]byte) *session.Session {
	mask := permission.Mask64(1)
	now := time.Now()
	return &session.Session{
		SessionID:         sid,
		UserID:            "u1",
		TenantID:          "0",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       refreshHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(24 * time.Hour).Unix(),
	}
}

func hashFor(i int) [32]byte {
	var out [32]byte
	for j := 0; j < len(out); j++ {
		out[j] = byte((i + j*17 + 11) % 251)
	}
	return out
}

func nextHash(current [32]byte, salt int) [32]byte {
	out := current
	for i := 0; i < len(out); i++ {
		out[i] ^= byte((salt + i*13) & 0xFF)
	}
	return out
}
