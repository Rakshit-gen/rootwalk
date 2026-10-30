package resolver

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestRTTsSmoothAndPenaliseFailures(t *testing.T) {
	var r rtts
	a := netip.MustParseAddr("192.0.2.1")
	if _, ok := r.get(a); ok {
		t.Fatal("known before any sample")
	}
	r.observe(a, 80*time.Millisecond, true)
	r.observe(a, 160*time.Millisecond, true)
	if d, _ := r.get(a); d != 90*time.Millisecond {
		t.Fatalf("got %v, want 90ms", d)
	}
	r.observe(a, 0, false)
	if d, _ := r.get(a); d != 90*time.Millisecond+(failPenalty-90*time.Millisecond)/8 {
		t.Fatalf("after a failure got %v", d)
	}
}

func TestOrderPutsUntriedFirstAndFailuresLast(t *testing.T) {
	var r rtts
	fast, slow, down, fresh := addrs("192.0.2.1")[0], addrs("192.0.2.2")[0], addrs("192.0.2.3")[0], addrs("192.0.2.4")[0]
	r.observe(fast, 10*time.Millisecond, true)
	r.observe(slow, 300*time.Millisecond, true)
	r.observe(down, 0, false)
	for range 20 {
		if got := r.order([]netip.Addr{down, slow, fresh, fast}); !slices.Equal(got, []netip.Addr{fresh, fast, slow, down}) {
			t.Fatalf("got %v", got)
		}
	}
}

func TestADeadServerIsAskedOnlyOnce(t *testing.T) {
	n, r := world(t)
	r.Roots = addrs("10.9.9.9", "10.0.0.1")
	for _, name := range []string{"www.example.test", "example.test", "nope.example.test"} {
		if _, err := r.Resolve(ctx, name, 1); err != nil {
			t.Fatal(err)
		}
	}
	if n.asked[addrs("10.9.9.9")[0]] != 1 {
		t.Fatalf("the dead root was asked %d times", n.asked[addrs("10.9.9.9")[0]])
	}
}
