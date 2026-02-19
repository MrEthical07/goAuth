// Package audit implements async event dispatching for security-relevant operations.
//
// # Components
//
//   - [Sink] — interface for event consumers (channel, JSON writer, no-op).
//   - [Dispatcher] — buffered async relay with drop-if-full / block-if-full semantics.
//   - [Event] — structured audit record with timestamp, type, user, tenant, IP, metadata.
//
// # Architecture boundaries
//
// This package owns event buffering and sink delivery. It does NOT decide which events
// to emit — that responsibility belongs to the Engine and flow functions.
//
// # What this package must NOT do
//
//   - Filter or suppress events based on business logic.
//   - Import goAuth or any sibling internal package.
//   - Perform network I/O beyond what a caller-supplied Sink does.
package audit
