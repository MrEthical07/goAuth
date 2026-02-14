package goAuth

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

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

type AuditSink interface {
	Emit(ctx context.Context, event AuditEvent)
}

type NoOpSink struct{}

func (NoOpSink) Emit(context.Context, AuditEvent) {}

type ChannelSink struct {
	events chan AuditEvent
}

func NewChannelSink(buffer int) *ChannelSink {
	if buffer <= 0 {
		buffer = 1
	}
	return &ChannelSink{
		events: make(chan AuditEvent, buffer),
	}
}

func (s *ChannelSink) Emit(ctx context.Context, event AuditEvent) {
	select {
	case s.events <- event:
	case <-ctx.Done():
	}
}

func (s *ChannelSink) Events() <-chan AuditEvent {
	return s.events
}

type JSONWriterSink struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return &JSONWriterSink{
		writer: w,
	}
}

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
