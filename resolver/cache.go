package resolver

import (
	"strings"
	"sync"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// maxTTL caps how long anything is kept, whatever a server claims.
const maxTTL = 24 * time.Hour

type cacheKey struct {
	name string
	t    dnsmsg.Type
}

type entry struct {
	rrs     []dnsmsg.RR
	rcode   uint8 // RcodeNXDomain for a cached "no such name"
	expires time.Time
}

// Cache holds answers until their TTL runs out. Expired entries are only
// dropped when looked up, which is fine for one machine's queries.
type Cache struct {
	mu           sync.Mutex
	m            map[cacheKey]entry
	Now          func() time.Time // time.Now unless a test sets it
	hits, misses int
}

func NewCache() *Cache { return &Cache{m: map[cacheKey]entry{}, Now: time.Now} }

func key(name string, t dnsmsg.Type) cacheKey { return cacheKey{strings.ToLower(dnsmsg.Fqdn(name)), t} }

// Put stores records for name and type, for the shortest TTL among them.
func (c *Cache) Put(name string, t dnsmsg.Type, rrs []dnsmsg.RR) {
	if len(rrs) == 0 {
		return
	}
	ttl := rrs[0].TTL
	for _, r := range rrs {
		ttl = min(ttl, r.TTL)
	}
	c.put(name, t, entry{rrs: rrs}, time.Duration(ttl)*time.Second)
}

func (c *Cache) put(name string, t dnsmsg.Type, e entry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e.expires = c.Now().Add(min(ttl, maxTTL))
	c.m[key(name, t)] = e
}

// Get returns what is cached for name and type, with TTLs counted down to
// what is left.
func (c *Cache) Get(name string, t dnsmsg.Type) (rrs []dnsmsg.RR, rcode uint8, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(name, t)
	e, found := c.m[k]
	now := c.Now()
	if !found || !now.Before(e.expires) {
		delete(c.m, k)
		c.misses++
		return nil, 0, false
	}
	c.hits++
	left := uint32(e.expires.Sub(now) / time.Second)
	out := make([]dnsmsg.RR, len(e.rrs))
	for i, r := range e.rrs {
		r.TTL = left
		out[i] = r
	}
	return out, e.rcode, true
}

// Stats is how many lookups were answered from the cache and how many weren't.
func (c *Cache) Stats() (hits, misses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
