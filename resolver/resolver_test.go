package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

var ctx = context.Background()

func TestWalksDownFromTheRoot(t *testing.T) {
	n, r := world(t)
	var steps []string
	r.Trace = func(s string) { steps = append(steps, s) }
	ans, err := r.Resolve(ctx, "WWW.example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Answers) != 1 || ans.Answers[0].Addr.String() != "192.0.2.80" {
		t.Fatalf("got %v", ans.Answers)
	}
	if n.queries != 3 || len(steps) != 3 {
		t.Fatalf("%d queries, steps %q", n.queries, steps)
	}
}

func TestTriesTheNextServerWhenOneIsDown(t *testing.T) {
	n, r := world(t)
	r.Roots = addrs("10.9.9.9", "10.0.0.1") // the first doesn't exist
	if _, err := r.Resolve(ctx, "example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if n.queries != 4 {
		t.Fatalf("%d queries, want 4", n.queries)
	}
}

func TestIgnoresGlueOutsideTheServersZone(t *testing.T) {
	n, r := world(t)
	// The .test server is compromised: it delegates example.test to a
	// server in another TLD and supplies an address for it, which it has
	// no authority to give.
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns.attacker.example.",
		"ns.attacker.example. 3600 A 6.6.6.6"))
	n.add("6.6.6.6", zone(t, "example.test.", "www.example.test. 1 A 6.6.6.6"))
	ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if err == nil {
		t.Fatalf("followed out-of-zone glue to %v", ans.Answers)
	}
}

func TestReferralsMustGoDown(t *testing.T) {
	m := dnsmsg.Message{Authority: []dnsmsg.RR{{Name: "test.", Type: dnsmsg.TypeNS, Target: "ns.nic.test."}}}
	if zone, _ := referral(m, "www.example.test.", "test."); zone != "" {
		t.Fatalf("a .test server referring to test. itself was followed to %q", zone)
	}
}

func TestLooksUpNameserversThatCameWithoutGlue(t *testing.T) {
	n, r := world(t)
	// other.test is served by a host inside example.test, so .test has no glue for it.
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.",
		"ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS dns.example.test."))
	n.add("10.0.2.1", zone(t, "example.test.", "dns.example.test. 300 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.", "www.other.test. 300 A 192.0.2.33"))
	ans, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA)
	if err != nil || ans.Answers[0].Addr.String() != "192.0.2.33" {
		t.Fatalf("%v %v", ans, err)
	}
}

func TestGivesUpOnNameserversThatNeedEachOther(t *testing.T) {
	n, r := world(t)
	// a.test's server lives in b.test and b.test's in a.test, neither with glue.
	n.add("10.0.1.1", zone(t, "test.", "a.test. 3600 NS ns.b.test.", "b.test. 3600 NS ns.a.test."))
	if _, err := r.Resolve(ctx, "www.a.test", dnsmsg.TypeA); err == nil {
		t.Fatal("resolved a circular delegation")
	}
}

func TestFollowsCNAMEsWithinAndAcrossZones(t *testing.T) {
	n, r := world(t)
	n.add("10.0.2.1", zone(t, "example.test.",
		"example.test. 300 SOA ns1.example.test. h.example.test. 60",
		"www.example.test. 300 CNAME web.example.test.",
		"web.example.test. 300 A 192.0.2.80",
		"cdn.example.test. 300 CNAME edge.other.test."))
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.",
		"ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS ns.other.test.",
		"ns.other.test. 3600 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.", "edge.other.test. 20 A 192.0.2.99"))

	ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if err != nil || len(ans.Answers) != 2 || ans.Answers[1].Addr.String() != "192.0.2.80" {
		t.Fatalf("in-zone: %v %v", ans.Answers, err)
	}
	ans, err = r.Resolve(ctx, "cdn.example.test", dnsmsg.TypeA)
	if err != nil || len(ans.Answers) != 2 || ans.Answers[0].Type != dnsmsg.TypeCNAME || ans.Answers[1].Addr.String() != "192.0.2.99" {
		t.Fatalf("across zones: %v %v", ans.Answers, err)
	}
}

func TestStopsAtCNAMELoops(t *testing.T) {
	n, r := world(t)
	n.add("10.0.2.1", zone(t, "example.test.",
		"a.example.test. 300 CNAME b.other.test."))
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS ns.other.test.", "ns.other.test. 3600 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.", "b.other.test. 300 CNAME a.example.test."))
	if _, err := r.Resolve(ctx, "a.example.test", dnsmsg.TypeA); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("got %v", err)
	}
}
