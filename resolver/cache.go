package resolver

import (
	"container/list"
	"net/netip"
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
	key     cacheKey
	rrs     []dnsmsg.RR
	rcode   uint8 // RcodeNXDomain for a cached "no such name"
	expires time.Time
}

// Cache holds answers until their TTL runs out, and at most Max of them:
// past that, the least recently used goes.
type Cache struct {
	Max int              // DefaultMax unless set
	Now func() time.Time // time.Now unless a test sets it

	mu           sync.Mutex
	m            map[cacheKey]*list.Element // of *entry, most recently used at the front
	lru          list.List
	zones        map[string]delegation
	hits, misses int
}

const DefaultMax = 100_000

func (c *Cache) limit() int {
	if c.Max <= 0 {
		return DefaultMax
	}
	return c.Max
}

type delegation struct {
	servers []netip.Addr
	expires time.Time
}

func NewCache() *Cache {
	return &Cache{m: map[cacheKey]*list.Element{}, zones: map[string]delegation{}, Now: time.Now}
}

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
	e.key, e.expires = key(name, t), c.Now().Add(min(ttl, maxTTL))
	if old, ok := c.m[e.key]; ok {
		c.lru.Remove(old)
	}
	c.m[e.key] = c.lru.PushFront(&e)
	for c.lru.Len() > c.limit() {
		delete(c.m, c.lru.Remove(c.lru.Back()).(*entry).key)
	}
}

// Get returns what is cached for name and type, with TTLs counted down to
// what is left.
func (c *Cache) Get(name string, t dnsmsg.Type) (rrs []dnsmsg.RR, rcode uint8, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.m[key(name, t)]
	now := c.Now()
	if !found || !now.Before(el.Value.(*entry).expires) {
		if found && !now.Before(el.Value.(*entry).expires.Add(staleFor)) {
			delete(c.m, el.Value.(*entry).key)
			c.lru.Remove(el)
		}
		c.misses++
		return nil, 0, false
	}
	c.lru.MoveToFront(el)
	e := el.Value.(*entry)
	c.hits++
	left := uint32(e.expires.Sub(now) / time.Second)
	out := make([]dnsmsg.RR, len(e.rrs))
	for i, r := range e.rrs {
		r.TTL = left
		out[i] = r
	}
	return out, e.rcode, true
}

// staleFor is how long an expired entry is kept for GetStale, and
// staleTTL the TTL it is handed out with (RFC 8767 suggests both).
const (
	staleFor = 24 * time.Hour
	staleTTL = 30
)

// GetStale returns an entry that has expired in the last day, for when
// every server for it has stopped answering.
func (c *Cache) GetStale(name string, t dnsmsg.Type) (rrs []dnsmsg.RR, rcode uint8, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.m[key(name, t)]
	if !found || !c.Now().Before(el.Value.(*entry).expires.Add(staleFor)) {
		return nil, 0, false
	}
	e := el.Value.(*entry)
	out := make([]dnsmsg.RR, len(e.rrs))
	for i, r := range e.rrs {
		r.TTL = staleTTL
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

// PutNegative caches "no such name" (rcode NXDomain) or "no records of this
// type" (rcode Success with nothing), for as long as RFC 2308 allows: the
// smaller of the SOA record's TTL and its minimum field. The SOA is kept so
// it can be handed back in the authority section.
func (c *Cache) PutNegative(name string, t dnsmsg.Type, rcode uint8, soa dnsmsg.RR) {
	ttl := min(soa.TTL, soa.SOA.Minimum)
	soa.TTL = ttl
	c.put(name, t, entry{rrs: []dnsmsg.RR{soa}, rcode: rcode}, time.Duration(ttl)*time.Second)
}

// PutZone remembers the servers a referral handed out for zone, so later
// lookups under it can skip the walk from the root.
func (c *Cache) PutZone(zone string, servers []netip.Addr, ttl uint32) {
	if len(servers) == 0 || ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if limit := max(1, c.limit()/10); len(c.zones) >= limit {
		// Rare enough that a sweep beats keeping a second LRU list.
		for z, d := range c.zones {
			if !now.Before(d.expires) || len(c.zones) >= limit {
				delete(c.zones, z)
			}
		}
	}
	c.zones[strings.ToLower(dnsmsg.Fqdn(zone))] = delegation{servers, now.Add(min(time.Duration(ttl)*time.Second, maxTTL))}
}

// Closest returns the deepest zone at or above name whose servers are
// cached, or "" if there is none.
func (c *Cache) Closest(name string) (string, []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	for z := strings.ToLower(dnsmsg.Fqdn(name)); z != "."; {
		if d, ok := c.zones[z]; ok && now.Before(d.expires) {
			return z, d.servers
		}
		_, z, _ = strings.Cut(z, ".")
		if z == "" {
			z = "."
		}
	}
	return "", nil
}
