package sse

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Broker fans out alert events to connected SSE clients (AC-23.2).
// Thread-safe; designed for concurrent subscribe/unsubscribe/publish.
type Broker struct {
	mu      sync.RWMutex
	clients map[uint64]chan []byte
	nextID  uint64
}

func NewBroker() *Broker {
	return &Broker{
		clients: make(map[uint64]chan []byte),
	}
}

// Subscribe returns a channel that receives SSE-formatted alert payloads
// and a cleanup function the caller MUST defer.
func (b *Broker) Subscribe() (<-chan []byte, func()) {
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	ch := make(chan []byte, 64)
	b.clients[id] = ch
	b.mu.Unlock()

	cleanup := func() {
		b.mu.Lock()
		delete(b.clients, id)
		close(ch)
		b.mu.Unlock()
	}
	return ch, cleanup
}

// Publish serializes the alert and sends it to all connected clients.
// Slow clients that can't keep up have the message dropped (non-blocking send).
func (b *Broker) Publish(alert any) {
	data, err := json.Marshal(alert)
	if err != nil {
		return
	}
	payload := []byte(fmt.Sprintf("data: %s\n\n", data))

	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}
