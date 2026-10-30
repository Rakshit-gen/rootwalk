package resolver

import (
	"context"
	"sync"
)

// flights lets identical lookups that arrive together share one walk
// from the root, so a burst of clients asking for the same name costs
// the servers one set of queries.
type flights struct {
	mu sync.Mutex
	m  map[cacheKey]*flight
}

type flight struct {
	done chan struct{}
	ans  Answer
	err  error
}

func (f *flights) do(ctx context.Context, k cacheKey, lookup func() (Answer, error)) (Answer, error) {
	f.mu.Lock()
	if c, ok := f.m[k]; ok {
		f.mu.Unlock()
		select {
		case <-c.done:
			return c.ans, c.err
		case <-ctx.Done():
			return Answer{}, ctx.Err()
		}
	}
	if f.m == nil {
		f.m = map[cacheKey]*flight{}
	}
	c := &flight{done: make(chan struct{})}
	f.m[k] = c
	f.mu.Unlock()

	c.ans, c.err = lookup()
	f.mu.Lock()
	delete(f.m, k)
	f.mu.Unlock()
	close(c.done)
	return c.ans, c.err
}
