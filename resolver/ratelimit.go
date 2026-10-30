package resolver

import (
	"net/netip"
	"sync"
	"time"
)

// limiter is a token bucket per client address: each may send rate
// queries a second, with bursts up to twice that.
type limiter struct {
	rate float64
	now  func() time.Time

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (l *limiter) allow(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.buckets == nil {
		l.buckets = map[netip.Addr]*bucket{}
	}
	if len(l.buckets) > 10_000 {
		// A crude sweep: buckets idle for a few seconds are full again anyway.
		for k, b := range l.buckets {
			if now.Sub(b.last) > 5*time.Second {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[a]
	if !ok {
		b = &bucket{tokens: 2 * l.rate, last: now}
		l.buckets[a] = b
	}
	b.tokens = min(2*l.rate, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
