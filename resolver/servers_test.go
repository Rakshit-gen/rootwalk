package resolver

import (
	"net/netip"
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
