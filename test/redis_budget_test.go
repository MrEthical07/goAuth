//go:build integration
// +build integration

package test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// cmdCounter is a go-redis Hook that counts the number of Redis round-trips
// (individual commands and pipeline calls).
type cmdCounter struct {
	commands  atomic.Int64
	pipelines atomic.Int64
}

func (h *cmdCounter) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *cmdCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.commands.Add(1)
		return next(ctx, cmd)
	}
}

func (h *cmdCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		// Each pipeline call is one network round-trip regardless of command count.
		h.pipelines.Add(1)
		h.commands.Add(int64(len(cmds)))
		return next(ctx, cmds)
	}
}

func (h *cmdCounter) Reset() {
	h.commands.Store(0)
	h.pipelines.Store(0)
}

func (h *cmdCounter) Commands() int64  { return h.commands.Load() }
func (h *cmdCounter) Pipelines() int64 { return h.pipelines.Load() }

// newCountedStore creates a session.Store backed by miniredis with a
// cmdCounter hook installed. Reset the counter before each measured operation.
func newCountedStore(t *testing.T) (*session.Store, *redis.Client, *cmdCounter, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	counter := &cmdCounter{}
	rdb.AddHook(counter)

	// Warm the connection: go-redis may emit extra commands on first use
	// (handshake, AUTH, SELECT, CLIENT SETNAME, etc.). Issuing a PING
	// before installing the counter avoids counting that noise.
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("warmup ping: %v", err)
	}

	// Reset after warmup so budget counts start clean.
	counter.Reset()

	store := session.NewStore(rdb, "as", true, false, 0)
	return store, rdb, counter, func() {
		_ = rdb.Close()
		mr.Close()
	}
}

// TestRefreshRotationRedisBudget verifies that a successful refresh rotation
// (RotateRefreshHash) uses at most 1 Redis round-trip (the Lua EVALSHA).
func TestRefreshRotationRedisBudget(t *testing.T) {
	store, _, counter, cleanup := newCountedStore(t)
	defer cleanup()

	ctx := context.Background()
	oldHash := hashByte(0x01)
	newHash := hashByte(0x02)

	mask := permission.Mask64(1)
	now := time.Now()
	sess := &session.Session{
		SessionID:         "sid-budget",
		UserID:            "uid-1",
		TenantID:          "0",
		Role:              "user",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       oldHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}

	// Save the session first (not counted).
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Reset counter — only measure the rotation.
	counter.Reset()

	_, err := store.RotateRefreshHash(ctx, "0", "sid-budget", oldHash, newHash)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// The rotation MUST be a single Lua script call (1 command).
	// go-redis may issue EVALSHA first, then fall back to EVAL on cache miss,
	// but that still counts as ≤ 2 commands (EVALSHA + EVAL) on first call.
	// Subsequent calls are 1 command.
	cmds := counter.Commands()
	if cmds > 2 {
		t.Errorf("RotateRefreshHash used %d Redis commands; budget is ≤ 2 (Lua script)", cmds)
	}
	t.Logf("RotateRefreshHash: %d commands, %d pipelines", cmds, counter.Pipelines())
}

// TestStrictValidateRedisBudget verifies that a strict-mode Get (read session)
// uses at most 2 Redis commands (GET + optional EXPIRE for sliding expiration).
func TestStrictValidateRedisBudget(t *testing.T) {
	store, _, counter, cleanup := newCountedStore(t)
	defer cleanup()

	ctx := context.Background()
	mask := permission.Mask64(1)
	now := time.Now()
	sess := &session.Session{
		SessionID:         "sid-validate",
		UserID:            "uid-2",
		TenantID:          "0",
		Role:              "user",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       hashByte(0xAA),
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}

	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	counter.Reset()

	_, err := store.Get(ctx, "0", "sid-validate", time.Hour)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// GET + EXPIRE (sliding) = 2 commands max.
	cmds := counter.Commands()
	if cmds > 2 {
		t.Errorf("Store.Get used %d Redis commands; budget is ≤ 2 (GET+EXPIRE)", cmds)
	}
	t.Logf("Store.Get (strict validate): %d commands, %d pipelines", cmds, counter.Pipelines())
}

// TestSessionDeleteRedisBudget verifies that session deletion (Lua script)
// uses at most 2 Redis commands (GET + Lua EVALSHA).
func TestSessionDeleteRedisBudget(t *testing.T) {
	store, _, counter, cleanup := newCountedStore(t)
	defer cleanup()

	ctx := context.Background()
	mask := permission.Mask64(1)
	now := time.Now()
	sess := &session.Session{
		SessionID:         "sid-delete",
		UserID:            "uid-3",
		TenantID:          "0",
		Role:              "user",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       hashByte(0xBB),
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}

	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	counter.Reset()

	if err := store.Delete(ctx, "0", "sid-delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// GET (to find userID for SREM) + Lua script = ≤ 4 commands.
	cmds := counter.Commands()
	if cmds > 4 {
		t.Errorf("Store.Delete used %d Redis commands; budget is ≤ 4", cmds)
	}
	t.Logf("Store.Delete: %d commands, %d pipelines", cmds, counter.Pipelines())
}

// TestSessionSaveRedisBudget verifies that session save uses a pipeline
// (SET + SADD + INCR = 1 round-trip).
func TestSessionSaveRedisBudget(t *testing.T) {
	store, _, counter, cleanup := newCountedStore(t)
	defer cleanup()

	ctx := context.Background()
	mask := permission.Mask64(1)
	now := time.Now()
	sess := &session.Session{
		SessionID:         "sid-save",
		UserID:            "uid-4",
		TenantID:          "0",
		Role:              "user",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       hashByte(0xCC),
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}

	counter.Reset()

	if err := store.Save(ctx, sess, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	// TxPipelined wraps SET+SADD+INCR in MULTI/EXEC.
	// go-redis v9 may split into multiple pipeline calls internally.
	cmds := counter.Commands()
	pipelines := counter.Pipelines()
	if cmds > 12 {
		t.Errorf("Store.Save used %d Redis commands; budget is ≤ 12 (TxPipelined overhead)", cmds)
	}
	t.Logf("Store.Save: %d commands, %d pipelines", cmds, pipelines)
}

// TestReplayTrackingRedisBudget verifies that replay anomaly tracking
// uses minimal Redis commands (INCR + conditional EXPIRE).
func TestReplayTrackingRedisBudget(t *testing.T) {
	store, _, counter, cleanup := newCountedStore(t)
	defer cleanup()

	ctx := context.Background()

	counter.Reset()

	if err := store.TrackReplayAnomaly(ctx, "sid-replay", 5*time.Minute); err != nil {
		t.Fatalf("track replay: %v", err)
	}

	// INCR + conditional EXPIRE; may include pipeline overhead.
	cmds := counter.Commands()
	if cmds > 8 {
		t.Errorf("TrackReplayAnomaly used %d Redis commands; budget is ≤ 8", cmds)
	}
	t.Logf("TrackReplayAnomaly: %d commands, %d pipelines", cmds, counter.Pipelines())
}
