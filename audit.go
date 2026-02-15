package goAuth

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditEvent defines a public type used by goAuth APIs.
//
// AuditEvent instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuditEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	UserID    string            `json:"user_id,omitempty"`
	TenantID  string            `json:"tenant_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// AuditSink defines a public type used by goAuth APIs.
//
// AuditSink instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuditSink interface {
	Emit(ctx context.Context, event AuditEvent)
}

// NoOpSink defines a public type used by goAuth APIs.
//
// NoOpSink instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type NoOpSink struct{}

// Emit describes the emit operation and its observable behavior.
//
// Emit may return an error when input validation, dependency calls, or security checks fail.
// Emit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (NoOpSink) Emit(context.Context, AuditEvent) {}

// ChannelSink defines a public type used by goAuth APIs.
//
// ChannelSink instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type ChannelSink struct {
	events chan AuditEvent
}

// NewChannelSink describes the newchannelsink operation and its observable behavior.
//
// NewChannelSink may return an error when input validation, dependency calls, or security checks fail.
// NewChannelSink does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewChannelSink(buffer int) *ChannelSink {
	if buffer <= 0 {
		buffer = 1
	}
	return &ChannelSink{
		events: make(chan AuditEvent, buffer),
	}
}

// Emit describes the emit operation and its observable behavior.
//
// Emit may return an error when input validation, dependency calls, or security checks fail.
// Emit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *ChannelSink) Emit(ctx context.Context, event AuditEvent) {
	select {
	case s.events <- event:
	case <-ctx.Done():
	}
}

// Events describes the events operation and its observable behavior.
//
// Events may return an error when input validation, dependency calls, or security checks fail.
// Events does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *ChannelSink) Events() <-chan AuditEvent {
	return s.events
}

// JSONWriterSink defines a public type used by goAuth APIs.
//
// JSONWriterSink instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type JSONWriterSink struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewJSONWriterSink describes the newjsonwritersink operation and its observable behavior.
//
// NewJSONWriterSink may return an error when input validation, dependency calls, or security checks fail.
// NewJSONWriterSink does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return &JSONWriterSink{
		writer: w,
	}
}

// Emit describes the emit operation and its observable behavior.
//
// Emit may return an error when input validation, dependency calls, or security checks fail.
// Emit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *JSONWriterSink) Emit(ctx context.Context, event AuditEvent) {
	if s == nil || s.writer == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = s.writer.Write(data)
	_, _ = s.writer.Write([]byte("\n"))
}
