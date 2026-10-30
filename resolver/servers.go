package resolver

import (
	"net/netip"
	"sync"
	"time"
)

// failPenalty is what a server that didn't answer counts as, so it sinks
// below servers that did.
const failPenalty = 2 * time.Second

// rtts keeps a smoothed round-trip time per server, the way TCP does:
// each new sample moves the estimate an eighth of the way.
type rtts struct {
	mu sync.Mutex
	m  map[netip.Addr]time.Duration
}

func (t *rtts) observe(s netip.Addr, took time.Duration, ok bool) {
	if !ok {
		took = failPenalty
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[netip.Addr]time.Duration{}
	}
	if old, seen := t.m[s]; seen {
		took = old + (took-old)/8
	}
	t.m[s] = took
}

func (t *rtts) get(s netip.Addr) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.m[s]
	return d, ok
}
