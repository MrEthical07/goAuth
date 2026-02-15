package goAuth

import (
	"context"
	"sync"
	"sync/atomic"
)

type auditDispatcher struct {
	cfg       AuditConfig
	sink      AuditSink
	ch        chan AuditEvent
	done      chan struct{}
	wg        sync.WaitGroup
	dropped   atomic.Uint64
	closed    atomic.Bool
	closeOnce sync.Once
}

func newAuditDispatcher(cfg AuditConfig, sink AuditSink) *auditDispatcher {
	if !cfg.Enabled {
		return nil
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1
	}
	if sink == nil {
		sink = NoOpSink{}
	}

	d := &auditDispatcher{
		cfg:  cfg,
		sink: sink,
		ch:   make(chan AuditEvent, cfg.BufferSize),
		done: make(chan struct{}),
	}

	d.wg.Add(1)
	go d.run()

	return d
}

func (d *auditDispatcher) run() {
	defer d.wg.Done()

	for {
		select {
		case event := <-d.ch:
			d.sink.Emit(context.Background(), event)
		case <-d.done:
			for {
				select {
				case event := <-d.ch:
					d.sink.Emit(context.Background(), event)
				default:
					return
				}
			}
		}
	}
}

// Emit describes the emit operation and its observable behavior.
//
// Emit may return an error when input validation, dependency calls, or security checks fail.
// Emit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (d *auditDispatcher) Emit(ctx context.Context, event AuditEvent) {
	if d == nil || d.closed.Load() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if d.cfg.DropIfFull {
		select {
		case d.ch <- event:
		case <-d.done:
		default:
			d.dropped.Add(1)
		}
		return
	}

	select {
	case d.ch <- event:
	case <-ctx.Done():
	case <-d.done:
	}
}

// Close describes the close operation and its observable behavior.
//
// Close may return an error when input validation, dependency calls, or security checks fail.
// Close does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (d *auditDispatcher) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.done)
		d.wg.Wait()
	})
}

// Dropped describes the dropped operation and its observable behavior.
//
// Dropped may return an error when input validation, dependency calls, or security checks fail.
// Dropped does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (d *auditDispatcher) Dropped() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}
