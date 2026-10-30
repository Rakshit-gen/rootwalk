package resolver

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiterAllowsBurstsThenTheRate(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := &limiter{rate: 5, now: c.now}
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	count := func(addr netip.Addr, n int) (ok int) {
		for range n {
			if l.allow(addr) {
				ok++
			}
		}
		return ok
	}
	if got := count(a, 50); got != 10 {
		t.Fatalf("burst allowed %d, want 10", got)
	}
	if got := count(b, 3); got != 3 {
		t.Fatalf("another client was held back: %d of 3", got)
	}
	c.wait(time.Second)
	if got := count(a, 50); got != 5 {
		t.Fatalf("a second later allowed %d, want 5", got)
	}
}
