package audit

import (
	"context"
	"sync"
	"sync/atomic"
)

// Config controls dispatcher buffering behavior.
type Config struct {
	Enabled    bool
	BufferSize int
	DropIfFull bool
}

// Dispatcher asynchronously forwards audit events to a sink.
type Dispatcher struct {
	cfg       Config
	sink      Sink
	ch        chan Event
	done      chan struct{}
	wg        sync.WaitGroup
	dropped   atomic.Uint64
	closed    atomic.Bool
	closeOnce sync.Once
}

func NewDispatcher(cfg Config, sink Sink) *Dispatcher {
	if !cfg.Enabled {
		return nil
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1
	}
	if sink == nil {
		sink = NoOpSink{}
	}

	d := &Dispatcher{
		cfg:  cfg,
		sink: sink,
		ch:   make(chan Event, cfg.BufferSize),
		done: make(chan struct{}),
	}

	d.wg.Add(1)
	go d.run()

	return d
}

func (d *Dispatcher) run() {
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

func (d *Dispatcher) Emit(ctx context.Context, event Event) {
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

func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.done)
		d.wg.Wait()
	})
}

func (d *Dispatcher) Dropped() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}
