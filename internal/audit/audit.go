package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
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

	writeErrors atomic.Uint64
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
		s.writeErrors.Add(1)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.writer.Write(data); err != nil {
		s.writeErrors.Add(1)
		return
	}
	if _, err := s.writer.Write([]byte("\n")); err != nil {
		s.writeErrors.Add(1)
	}
}

// ErrorCount returns the number of JSON encoding or write failures observed
// by this sink.
func (s *JSONWriterSink) ErrorCount() uint64 {
	if s == nil {
		return 0
	}
	return s.writeErrors.Load()
}

// SlogSink writes audit events through a slog.Logger for easy integration with
// structured log backends.
type SlogSink struct {
	logger *slog.Logger
	level  slog.Level
}

// NewSlogSink creates a [SlogSink] that writes audit events at info level.
func NewSlogSink(logger *slog.Logger) *SlogSink {
	return &SlogSink{
		logger: logger,
		level:  slog.LevelInfo,
	}
}

func (s *SlogSink) Emit(ctx context.Context, event Event) {
	if s == nil || s.logger == nil {
		return
	}

	attrs := []slog.Attr{
		slog.String("event_type", event.EventType),
		slog.Time("event_timestamp", event.Timestamp),
		slog.Bool("success", event.Success),
	}
	if event.UserID != "" {
		attrs = append(attrs, slog.String("user_id", event.UserID))
	}
	if event.TenantID != "" {
		attrs = append(attrs, slog.String("tenant_id", event.TenantID))
	}
	if event.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", event.SessionID))
	}
	if event.IP != "" {
		attrs = append(attrs, slog.String("ip", event.IP))
	}
	if event.Error != "" {
		attrs = append(attrs, slog.String("error", event.Error))
	}
	if len(event.Metadata) > 0 {
		attrs = append(attrs, slog.Any("metadata", event.Metadata))
	}

	s.logger.LogAttrs(ctx, s.level, "goauth.audit", attrs...)
}
