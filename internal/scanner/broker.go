package scanner

import "sync"

// broker is a tiny fan-out for scan events. It also keeps a bounded
// history so late subscribers can replay the events they missed (the
// runner often pushes the first `progress` event before the SSE client
// has had time to connect).
//
// Slow live subscribers drop events rather than backpressure the
// producer (the scan goroutine).
type broker struct {
	mu        sync.Mutex
	subs      map[*subscriber]struct{}
	bufferLen int
	history   []Event
	closed    bool
}

type subscriber struct {
	ch chan Event
}

func newBroker(bufferLen int) *broker {
	if bufferLen <= 0 {
		bufferLen = 32
	}
	return &broker{
		subs:      make(map[*subscriber]struct{}),
		bufferLen: bufferLen,
	}
}

// subscribe returns a buffered channel of Events plus a cancel func. Past
// events are replayed first (best effort: if the channel buffer is too
// small they are dropped, just like live events would be).
func (b *broker) subscribe() (<-chan Event, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		// Closed brokers still let callers replay history once, then close.
		ch := make(chan Event, len(b.history)+1)
		for _, e := range b.history {
			ch <- e
		}
		close(ch)
		noop := func() {}
		return ch, noop, nil
	}
	bufLen := b.bufferLen
	if h := len(b.history); h > bufLen {
		bufLen = h + 8
	}
	s := &subscriber{ch: make(chan Event, bufLen)}
	for _, e := range b.history {
		select {
		case s.ch <- e:
		default:
		}
	}
	b.subs[s] = struct{}{}
	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
	}
	return s.ch, cancel, nil
}

// publish records e in the bounded history and best-effort delivers it to
// every current subscriber.
func (b *broker) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.history = append(b.history, e)
	const historyMax = 256
	if len(b.history) > historyMax {
		b.history = b.history[len(b.history)-historyMax:]
	}
	for s := range b.subs {
		select {
		case s.ch <- e:
		default:
		}
	}
}

// close terminates the broker. New subscribers replay history once and
// receive a closed channel; existing live channels are drained and closed.
func (b *broker) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for s := range b.subs {
		close(s.ch)
		delete(b.subs, s)
	}
}
