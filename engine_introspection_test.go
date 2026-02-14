package goAuth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
)

func TestIntrospectionSessionCountAndListAfterLoginLogout(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	ctx := WithTenantID(context.Background(), "0")
	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	sessionID, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	count, err := engine.GetActiveSessionCount(ctx, "u1")
	if err != nil {
		t.Fatalf("GetActiveSessionCount failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 active session, got %d", count)
	}

	list, err := engine.ListActiveSessions(ctx, "u1")
	if err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected list length 1, got %d", len(list))
	}
	if list[0].SessionID != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, list[0].SessionID)
	}

	if err := engine.LogoutInTenant(ctx, "0", sessionID); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	countAfter, err := engine.GetActiveSessionCount(ctx, "u1")
	if err != nil {
		t.Fatalf("GetActiveSessionCount after logout failed: %v", err)
	}
	if countAfter != 0 {
		t.Fatalf("expected 0 active sessions after logout, got %d", countAfter)
	}
}

func TestIntrospectionTenantIsolationEnforced(t *testing.T) {
	cfg := accountTestConfig()
	cfg.MultiTenant.Enabled = true

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "t1",
				PasswordHash:      hash,
				Status:            AccountActive,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctxT1 := WithTenantID(context.Background(), "t1")
	_, refresh, err := engine.Login(ctxT1, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	sessionID, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	count, err := engine.GetActiveSessionCount(ctxT1, "u1")
	if err != nil {
		t.Fatalf("GetActiveSessionCount failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 active session for tenant t1, got %d", count)
	}

	if _, err := engine.GetActiveSessionCount(context.Background(), "u1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for missing tenant context, got %v", err)
	}

	if _, err := engine.GetSessionInfo(WithTenantID(context.Background(), "t2"), "t1", sessionID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for tenant mismatch, got %v", err)
	}
}

func TestIntrospectionActiveSessionEstimate(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	ctx := WithTenantID(context.Background(), "0")
	for i := 0; i < 3; i++ {
		if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
			t.Fatalf("login %d failed: %v", i, err)
		}
	}

	estimate, err := engine.ActiveSessionEstimate(ctx)
	if err != nil {
		t.Fatalf("ActiveSessionEstimate failed: %v", err)
	}
	if estimate != 3 {
		t.Fatalf("expected estimate=3, got %d", estimate)
	}
}

func TestIntrospectionHealthRedisUnavailable(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	done()

	health := engine.Health(context.Background())
	if health.RedisAvailable {
		t.Fatal("expected redis unavailable after test redis shutdown")
	}
}

func TestIntrospectionNoPanicWhenRedisDown(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	done()

	if _, err := engine.GetActiveSessionCount(context.Background(), "u1"); err == nil {
		t.Fatal("expected GetActiveSessionCount to fail when redis is down")
	}
	if _, err := engine.ActiveSessionEstimate(context.Background()); err == nil {
		t.Fatal("expected ActiveSessionEstimate to fail when redis is down")
	}
}

func TestIntrospectionReadOnlyDoesNotModifyState(t *testing.T) {
	cfg := accountTestConfig()
	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "0",
				PasswordHash:      hash,
				Status:            AccountActive,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	stale := &session.Session{
		SessionID: "stale-session",
		UserID:    "u1",
		TenantID:  "0",
		Role:      "member",
		Mask: func() interface{} {
			var m permission.Mask64
			return &m
		}(),
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            uint8(AccountActive),
		CreatedAt:         time.Now().Add(-10 * time.Minute).Unix(),
		ExpiresAt:         time.Now().Add(-1 * time.Minute).Unix(),
	}
	encoded, err := session.Encode(stale)
	if err != nil {
		t.Fatalf("encode stale session failed: %v", err)
	}

	ctx := context.Background()
	if err := rdb.Set(ctx, "as:0:stale-session", encoded, time.Hour).Err(); err != nil {
		t.Fatalf("seed stale session failed: %v", err)
	}
	if err := rdb.SAdd(ctx, "au:0:u1", "stale-session").Err(); err != nil {
		t.Fatalf("seed stale index failed: %v", err)
	}

	_, err = engine.GetSessionInfo(WithTenantID(ctx, "0"), "0", "stale-session")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for stale session, got %v", err)
	}

	if exists := rdb.Exists(ctx, "as:0:stale-session").Val(); exists != 1 {
		t.Fatal("expected stale key to remain for read-only introspection")
	}
	members, err := rdb.SMembers(ctx, "au:0:u1").Result()
	if err != nil {
		t.Fatalf("read index members failed: %v", err)
	}
	if len(members) != 1 || members[0] != "stale-session" {
		t.Fatalf("expected stale index member to remain, got %v", members)
	}
}

func TestIntrospectionConcurrentCallsSafe(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	ctx := WithTenantID(context.Background(), "0")
	for i := 0; i < 2; i++ {
		if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
			t.Fatalf("login %d failed: %v", i, err)
		}
	}

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := engine.GetActiveSessionCount(ctx, "u1"); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if _, err := engine.ListActiveSessions(ctx, "u1"); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if _, err := engine.ActiveSessionEstimate(ctx); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				_ = engine.Health(ctx)
			}
		}()
	}
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("concurrent introspection failed: %v", err)
	default:
	}
}

func TestIntrospectionMetricsSnapshotUnaffected(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.EnableLatencyHistograms = false

	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "0",
				PasswordHash:      hash,
				Status:            AccountActive,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := WithTenantID(context.Background(), "0")
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	before := engine.MetricsSnapshot()

	if _, err := engine.GetActiveSessionCount(ctx, "u1"); err != nil {
		t.Fatalf("GetActiveSessionCount failed: %v", err)
	}
	if _, err := engine.ListActiveSessions(ctx, "u1"); err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}
	if _, err := engine.ActiveSessionEstimate(ctx); err != nil {
		t.Fatalf("ActiveSessionEstimate failed: %v", err)
	}
	_ = engine.Health(ctx)

	after := engine.MetricsSnapshot()
	for id := MetricID(0); id < metricIDCount; id++ {
		if before.Counters[id] != after.Counters[id] {
			t.Fatalf("expected metrics counter %d unchanged, before=%d after=%d", id, before.Counters[id], after.Counters[id])
		}
	}
}

func TestIntrospectionGetLoginAttemptsMissingReturnsZero(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	attempts, err := engine.GetLoginAttempts(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("GetLoginAttempts failed: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("expected zero attempts for missing identifier, got %d", attempts)
	}
}
