package goAuth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingSink struct {
	count atomic.Int64
}

func (s *countingSink) Emit(context.Context, AuditEvent) {
	s.count.Add(1)
}

func (s *countingSink) Count() int64 {
	return s.count.Load()
}

type captureSink struct {
	events chan AuditEvent
}

func newCaptureSink(buffer int) *captureSink {
	if buffer <= 0 {
		buffer = 1
	}
	return &captureSink{
		events: make(chan AuditEvent, buffer),
	}
}

func (s *captureSink) Emit(ctx context.Context, event AuditEvent) {
	select {
	case s.events <- event:
	case <-ctx.Done():
	}
}

type gateSink struct {
	gate chan struct{}
}

func newGateSink() *gateSink {
	return &gateSink{
		gate: make(chan struct{}),
	}
}

func (s *gateSink) Emit(context.Context, AuditEvent) {
	<-s.gate
}

func buildAuditTestEngine(t *testing.T, cfg Config, sink AuditSink, up UserProvider) (*Engine, func()) {
	t.Helper()

	mr, rdb := newTestRedis(t)
	builder := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{
			"member": {"perm.read"},
		}).
		WithUserProvider(up).
		WithAuditSink(sink)

	engine, err := builder.Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}

	return engine, func() {
		engine.Close()
		mr.Close()
	}
}

func TestAuditDisabledNoSinkCalls(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Audit.Enabled = false

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

	sink := &countingSink{}
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	_, _, _ = engine.Login(WithClientIP(context.Background(), "203.0.113.1"), "alice", "wrong-password")
	time.Sleep(30 * time.Millisecond)

	if sink.Count() != 0 {
		t.Fatalf("expected no audit sink calls when disabled, got %d", sink.Count())
	}
}

func TestAuditEnabledSinkReceivesEventWithFields(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Audit.Enabled = true
	cfg.Audit.BufferSize = 16
	cfg.Audit.DropIfFull = true

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

	sink := newCaptureSink(8)
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	ctx := WithTenantID(WithClientIP(context.Background(), "198.51.100.33"), "44")
	_, _, _ = engine.Login(ctx, "alice", "super-secret-password")

	select {
	case ev := <-sink.events:
		if ev.EventType == "" {
			t.Fatal("expected event type to be populated")
		}
		if ev.IP != "198.51.100.33" {
			t.Fatalf("expected IP 198.51.100.33, got %q", ev.IP)
		}
		if ev.TenantID != "44" {
			t.Fatalf("expected tenant 44, got %q", ev.TenantID)
		}
		if ev.Error == "super-secret-password" {
			t.Fatal("sensitive password leaked in error")
		}
		if ev.Metadata != nil {
			for _, v := range ev.Metadata {
				if v == "super-secret-password" {
					t.Fatal("sensitive password leaked in metadata")
				}
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected audit event to be received")
	}
}

func TestAuditBufferFullDropIfFullTrueDoesNotBlock(t *testing.T) {
	sink := newGateSink()
	dispatcher := newAuditDispatcher(AuditConfig{
		Enabled:    true,
		BufferSize: 1,
		DropIfFull: true,
	}, sink)
	defer func() {
		close(sink.gate)
		dispatcher.Close()
	}()

	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e1"})
	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e2"})

	start := time.Now()
	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e3"})
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("expected non-blocking emit when DropIfFull is true")
	}
	if dispatcher.Dropped() == 0 {
		t.Fatal("expected dropped counter to increment when queue is full")
	}
}

func TestAuditBufferFullDropIfFullFalseBlocksUntilSpace(t *testing.T) {
	sink := newGateSink()
	dispatcher := newAuditDispatcher(AuditConfig{
		Enabled:    true,
		BufferSize: 1,
		DropIfFull: false,
	}, sink)
	defer func() {
		close(sink.gate)
		dispatcher.Close()
	}()

	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e1"})
	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e2"})

	done := make(chan struct{})
	go func() {
		dispatcher.Emit(context.Background(), AuditEvent{EventType: "e3"})
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("expected emit to block while buffer is full")
	case <-time.After(150 * time.Millisecond):
	}

	sink.gate <- struct{}{}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected blocked emit to proceed after space is available")
	}
}

func TestAuditJSONWriterSinkWritesJSONLines(t *testing.T) {
	var buf syncBuffer
	sink := NewJSONWriterSink(&buf)
	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: auditEventLoginSuccess,
		UserID:    "u1",
		TenantID:  "0",
		IP:        "127.0.0.1",
		Success:   true,
	}
	sink.Emit(context.Background(), event)

	if !buf.Contains("login_success") {
		t.Fatal("expected JSON log line to contain event type")
	}
	if !buf.Contains("\"user_id\":\"u1\"") {
		t.Fatal("expected JSON log line to contain user id")
	}
}

func TestAuditDispatcherCloseIdempotentAndEmitAfterCloseSafe(t *testing.T) {
	dispatcher := newAuditDispatcher(AuditConfig{
		Enabled:    true,
		BufferSize: 4,
		DropIfFull: true,
	}, &countingSink{})

	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e1"})
	dispatcher.Close()
	dispatcher.Close()
	dispatcher.Emit(context.Background(), AuditEvent{EventType: "e2"})
}

func TestAuditNoSecretsInEvents(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Audit.Enabled = true
	cfg.Audit.BufferSize = 32
	cfg.Audit.DropIfFull = false

	up := newHardeningUserProvider(t)
	sensitivePassword := "correct-password-123"

	sink := newCaptureSink(32)
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	_, refreshToken, err := engine.Login(context.Background(), "alice", sensitivePassword)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if _, _, err := engine.Refresh(context.Background(), refreshToken); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	passwordHash := up.users["u1"].PasswordHash
	secretNeedles := []string{
		sensitivePassword,
		refreshToken,
		passwordHash,
	}

	// Collect a bounded number of audit events generated by the operations above.
	events := make([]AuditEvent, 0, 8)
	timeout := time.After(2 * time.Second)
collectLoop:
	for len(events) < 8 {
		select {
		case ev := <-sink.events:
			events = append(events, ev)
		case <-timeout:
			break collectLoop
		}
	}

	if len(events) == 0 {
		t.Fatal("expected at least one audit event")
	}

	for _, ev := range events {
		for _, needle := range secretNeedles {
			if needle == "" {
				continue
			}
			if stringContains(ev.Error, needle) {
				t.Fatalf("sensitive value leaked in audit error field: %q", needle)
			}
			for k, v := range ev.Metadata {
				if stringContains(k, needle) || stringContains(v, needle) {
					t.Fatalf("sensitive value leaked in audit metadata: %q", needle)
				}
			}
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) Contains(v string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return stringContains(string(b.buf), v)
}

func stringContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
