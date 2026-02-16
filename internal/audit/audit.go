package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event is the canonical audit event model used by internal dispatching and root APIs.
type Event struct {
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

// Sink receives emitted audit events.
type Sink interface {
	Emit(ctx context.Context, event Event)
}

// NoOpSink drops audit events.
type NoOpSink struct{}

func (NoOpSink) Emit(context.Context, Event) {}

// ChannelSink writes audit events into a buffered channel.
type ChannelSink struct {
	events chan Event
}

func NewChannelSink(buffer int) *ChannelSink {
	if buffer <= 0 {
		buffer = 1
	}
	return &ChannelSink{
		events: make(chan Event, buffer),
	}
}

func (s *ChannelSink) Emit(ctx context.Context, event Event) {
	select {
	case s.events <- event:
	case <-ctx.Done():
	}
}

func (s *ChannelSink) Events() <-chan Event {
	return s.events
}

// JSONWriterSink writes one JSON object per line.
type JSONWriterSink struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return &JSONWriterSink{
		writer: w,
	}
}

func (s *JSONWriterSink) Emit(ctx context.Context, event Event) {
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
