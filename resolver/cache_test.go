package resolver

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) wait(d time.Duration) { c.t = c.t.Add(d) }
func newTestCache() (*Cache, *clock) {
	clk := &clock{time.Unix(1_800_000_000, 0)}
	c := NewCache()
	c.Now = clk.now
	return c, clk
}

func a(name string, ttl uint32, ip string) dnsmsg.RR {
	return dnsmsg.RR{Name: name, Type: dnsmsg.TypeA, Class: 1, TTL: ttl, Addr: netip.MustParseAddr(ip)}
}

func TestCacheCountsDownAndExpires(t *testing.T) {
	c, clk := newTestCache()
	c.Put("Example.COM", dnsmsg.TypeA, []dnsmsg.RR{a("example.com.", 300, "192.0.2.1"), a("example.com.", 60, "192.0.2.2")})
	clk.wait(20 * time.Second)
	rrs, _, ok := c.Get("example.com.", dnsmsg.TypeA)
	if !ok || len(rrs) != 2 || rrs[0].TTL != 40 || rrs[1].TTL != 40 {
		t.Fatalf("after 20s of a 60s TTL: %v %v", rrs, ok)
	}
	clk.wait(40 * time.Second)
	if _, _, ok := c.Get("example.com.", dnsmsg.TypeA); ok {
		t.Fatal("still cached when the TTL ran out")
	}
	if h, m := c.Stats(); h != 1 || m != 1 {
		t.Fatalf("stats %d hits %d misses", h, m)
	}
}

func TestCacheCapsTTLsAtADay(t *testing.T) {
	c, clk := newTestCache()
	c.Put("x.", dnsmsg.TypeA, []dnsmsg.RR{a("x.", 1<<31, "192.0.2.1")})
	clk.wait(maxTTL)
	if _, _, ok := c.Get("x.", dnsmsg.TypeA); ok {
		t.Fatal("kept past a day")
	}
}
