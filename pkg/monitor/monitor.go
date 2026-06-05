package monitor

import (
	"context"
	"sync"
)

// Monitor defines the interface for collecting execution logs.
type Monitor interface {
	// Start starts harvesting events from the target PID and its descendants.
	Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error

	// Stop terminates the telemetry gathering.
	Stop() error
}

// InstrumentationBus coordinates the stream of events from all monitors.
type InstrumentationBus struct {
	mu        sync.RWMutex
	consumers []chan<- Event
	stream    chan Event
	cancel    context.CancelFunc
}

func NewInstrumentationBus() *InstrumentationBus {
	return &InstrumentationBus{
		stream: make(chan Event, 5000),
	}
}

// Publish sends an event down the pipeline.
func (b *InstrumentationBus) Publish(ev Event) {
	select {
	case b.stream <- ev:
	default:
		// Drop event if buffer is fully choked to prevent blocking monitors
	}
}

// RegisterConsumer adds a listener channel to receive incoming events.
func (b *InstrumentationBus) RegisterConsumer(c chan<- Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consumers = append(b.consumers, c)
}

// Stream returns the main channel where all events flow.
func (b *InstrumentationBus) Stream() <-chan Event {
	return b.stream
}

// StartPipeline spawns the dispatcher routing events to all registered consumers.
func (b *InstrumentationBus) StartPipeline(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel

	go func() {
		for {
			select {
			case ev := <-b.stream:
				b.mu.RLock()
				for _, consumer := range b.consumers {
					select {
					case consumer <- ev:
					default:
						// Consumer buffer full, skip to prevent blocking
					}
				}
				b.mu.RUnlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopPipeline shuts down the dispatcher.
func (b *InstrumentationBus) StopPipeline() {
	if b.cancel != nil {
		b.cancel()
	}
}
