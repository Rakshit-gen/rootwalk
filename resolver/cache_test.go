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

func TestNegativeAnswersLastTheSOAMinimum(t *testing.T) {
	c, clk := newTestCache()
	soa := dnsmsg.RR{Name: "example.", Type: dnsmsg.TypeSOA, Class: 1, TTL: 3600,
		SOA: dnsmsg.SOA{MName: "ns.example.", RName: "h.example.", Minimum: 300}}
	c.PutNegative("nope.example.", dnsmsg.TypeA, dnsmsg.RcodeNXDomain, soa)
	clk.wait(299 * time.Second)
	rrs, rcode, ok := c.Get("nope.example.", dnsmsg.TypeA)
	if !ok || rcode != dnsmsg.RcodeNXDomain || rrs[0].Type != dnsmsg.TypeSOA || rrs[0].TTL != 1 {
		t.Fatalf("got %v %d %v", rrs, rcode, ok)
	}
	clk.wait(time.Second)
	if _, _, ok := c.Get("nope.example.", dnsmsg.TypeA); ok {
		t.Fatal("negative answer outlived the SOA minimum")
	}
}

func TestClosestFindsTheDeepestUnexpiredZone(t *testing.T) {
	c, clock := newTestCache()
	com := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	example := []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	c.PutZone("com.", com, 600)
	c.PutZone("Example.com", example, 60)
	for name, want := range map[string]string{"www.example.com.": "example.com.", "example.com.": "example.com.",
		"other.com.": "com.", "example.org.": "", "a.b.c.example.com": "example.com."} {
		if z, _ := c.Closest(name); z != want {
			t.Errorf("Closest(%s) = %q, want %q", name, z, want)
		}
	}
	clock.wait(61 * time.Second)
	if z, s := c.Closest("www.example.com."); z != "com." || s[0] != com[0] {
		t.Fatalf("after expiry got %q %v, want com.", z, s)
	}
}
