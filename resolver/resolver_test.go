package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	r.Roots = addrs("10.9.9.9", "10.0.0.1")      // the first doesn't exist
	r.rtt.observe(r.Roots[1], time.Second, true) // so the untried dead one is asked first
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

func TestNamesThatDontExistAndTypesThatArent(t *testing.T) {
	_, r := world(t)
	ans, err := r.Resolve(ctx, "nope.example.test", dnsmsg.TypeA)
	if err != nil || ans.Rcode != dnsmsg.RcodeNXDomain || len(ans.Authority) != 1 || ans.Authority[0].SOA.Minimum != 60 {
		t.Fatalf("NXDOMAIN: %+v %v", ans, err)
	}
	ans, err = r.Resolve(ctx, "www.example.test", dnsmsg.TypeAAAA)
	if err != nil || ans.Rcode != dnsmsg.RcodeSuccess || len(ans.Answers) != 0 || len(ans.Authority) != 1 {
		t.Fatalf("no AAAA: %+v %v", ans, err)
	}
}

func TestTheCacheAnswersRepeatsWithoutTheNetwork(t *testing.T) {
	n, r := world(t)
	r.Cache, _ = newTestCache()
	for _, q := range []struct {
		name string
		t    dnsmsg.Type
	}{{"www.example.test", dnsmsg.TypeA}, {"nope.example.test", dnsmsg.TypeA}, {"www.example.test", dnsmsg.TypeAAAA}} {
		first, err := r.Resolve(ctx, q.name, q.t)
		if err != nil {
			t.Fatal(err)
		}
		before := n.queries
		again, err := r.Resolve(ctx, q.name, q.t)
		if err != nil || n.queries != before {
			t.Fatalf("%s %s: %d more queries, %v", q.name, q.t, n.queries-before, err)
		}
		if again.Rcode != first.Rcode || len(again.Answers) != len(first.Answers) || len(again.Authority) != len(first.Authority) {
			t.Fatalf("%s %s: cached %+v, first %+v", q.name, q.t, again, first)
		}
	}
}

func TestASecondNameInAZoneSkipsTheRoot(t *testing.T) {
	n, r := world(t)
	r.Cache, _ = newTestCache()
	if _, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	before := n.queries
	if _, err := r.Resolve(ctx, "nope.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := n.queries - before; got != 1 {
		t.Fatalf("a new name in a cached zone took %d queries, want 1", got)
	}
}

func TestSkipsServersThatFailOrRefuse(t *testing.T) {
	for _, rcode := range []uint8{dnsmsg.RcodeServFail, dnsmsg.RcodeRefused, dnsmsg.RcodeFormErr} {
		n, r := world(t)
		n.servers[netip.MustParseAddr("10.0.0.2")] = func(q dnsmsg.Question) dnsmsg.Message {
			return dnsmsg.Message{Header: dnsmsg.Header{Response: true, Rcode: rcode}, Questions: []dnsmsg.Question{q}}
		}
		r.Roots = addrs("10.0.0.2", "10.0.0.1")
		ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
		if err != nil || len(ans.Answers) != 1 {
			t.Fatalf("rcode %d: %+v, %v", rcode, ans, err)
		}
	}
	_, r := world(t)
	r.Roots = addrs("10.0.2.1") // example.test's server refuses anything outside its zone
	if _, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("got %v, want ErrNoAnswer", err)
	}
}

func TestTimeoutCoversTheWholeLookup(t *testing.T) {
	n, r := world(t)
	n.delay = 20 * time.Millisecond
	r.Timeout = 50 * time.Millisecond // enough for two of the three queries
	start := time.Now()
	_, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a deadline error", err)
	}
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("took %v", took)
	}
}

func TestIgnoresRecordsForCNAMETargetsOutsideTheServersZone(t *testing.T) {
	n, r := world(t)
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS ns.other.test.", "ns.other.test. 3600 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.",
		"bank.other.test. 300 A 192.0.2.10",
		"bank.other.test. 300 CNAME wrong.other.test.")) // never followed: the A answers first
	n.servers[addrs("10.0.2.1")[0]] = func(q dnsmsg.Question) dnsmsg.Message {
		return dnsmsg.Message{Header: dnsmsg.Header{Response: true, Authoritative: true}, Questions: []dnsmsg.Question{q},
			Answers: []dnsmsg.RR{
				rr(t, "evil.example.test. 300 CNAME bank.other.test."),
				rr(t, "bank.other.test. 300 A 203.0.113.66"), // example.test's server has no say over other.test
			}}
	}
	r.Cache, _ = newTestCache()
	ans, err := r.Resolve(ctx, "evil.example.test", dnsmsg.TypeA)
	if err != nil || len(ans.Answers) != 2 || ans.Answers[1].Addr.String() != "192.0.2.10" {
		t.Fatalf("got %v %v", ans.Answers, err)
	}
	if rrs, _, _ := r.Cache.Get("bank.other.test", dnsmsg.TypeA); len(rrs) != 1 || rrs[0].Addr.String() != "192.0.2.10" {
		t.Fatalf("cache has %v", rrs)
	}
}

func TestAReferralToManyMissingNameserversCostsLittle(t *testing.T) {
	n, r := world(t)
	lines := []string{"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1"}
	for i := range 200 {
		lines = append(lines, fmt.Sprintf("victim.test. 3600 NS ns%d.example.test.", i)) // none of them exist
	}
	n.add("10.0.1.1", zone(t, "test.", lines...))
	r.Cache, _ = newTestCache()
	if _, err := r.Resolve(ctx, "www.victim.test", dnsmsg.TypeA); err == nil {
		t.Fatal("resolved through nameservers that don't exist")
	}
	if n.queries > 20 {
		t.Fatalf("one lookup sent %d queries", n.queries)
	}
}

func TestOneLookupSendsAtMostMaxQueries(t *testing.T) {
	n, r := world(t)
	// Every root is down, so each referral step tries all of them.
	r.Roots = nil
	for i := range 100 {
		r.Roots = append(r.Roots, netip.AddrFrom4([4]byte{10, 9, 0, byte(i)}))
	}
	_, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if !errors.Is(err, ErrBudget) || n.queries != maxQueries {
		t.Fatalf("%d queries, %v", n.queries, err)
	}
}

func TestUsesIPv6GlueOnlyWhenAllowed(t *testing.T) {
	n, r := world(t)
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.",
		"ns1.example.test. 3600 AAAA 2001:db8::53")) // reachable over IPv6 only
	n.add("2001:db8::53", zone(t, "example.test.", "www.example.test. 300 A 192.0.2.80"))
	if _, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err == nil {
		t.Fatal("used IPv6 glue with IPv6 off")
	}
	r.IPv6 = true
	if ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err != nil || len(ans.Answers) != 1 {
		t.Fatalf("with IPv6 on: %v %v", ans, err)
	}
}

func TestANameserverBehindACNAMEStillGetsItsAddress(t *testing.T) {
	n, r := world(t)
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS dns.example.test."))
	n.add("10.0.2.1", zone(t, "example.test.",
		"dns.example.test. 300 CNAME host.example.test.",
		"host.example.test. 300 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.", "www.other.test. 300 A 192.0.2.33"))
	before := n.asked[netip.Addr{}]
	if ans, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA); err != nil || len(ans.Answers) != 1 {
		t.Fatalf("%v %v", ans, err)
	}
	if n.asked[netip.Addr{}] != before {
		t.Fatal("sent a query to the zero address taken from a CNAME")
	}
}

func TestLooksUpIPv6AddressesOfGluelessNameservers(t *testing.T) {
	n, r := world(t)
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS v6only.example.test."))
	n.add("10.0.2.1", zone(t, "example.test.",
		"example.test. 300 SOA ns1.example.test. h.example.test. 60",
		"v6only.example.test. 300 AAAA 2001:db8::99"))
	n.add("2001:db8::99", zone(t, "other.test.", "www.other.test. 300 A 192.0.2.33"))
	if _, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA); err == nil {
		t.Fatal("reached an IPv6-only nameserver with IPv6 off")
	}
	r.IPv6 = true
	if ans, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA); err != nil || len(ans.Answers) != 1 {
		t.Fatalf("%v %v", ans, err)
	}
}

func TestServesStaleWhenTheServersStopAnswering(t *testing.T) {
	n, r := world(t)
	var clock *clock
	r.Cache, clock = newTestCache()
	if _, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	clock.wait(2 * time.Hour) // past every TTL in the world
	n.servers = nil
	ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if err != nil || len(ans.Answers) != 1 || ans.Answers[0].TTL != staleTTL {
		t.Fatalf("got %v, %v", ans.Answers, err)
	}
	if _, err := r.Resolve(ctx, "never.example.test", dnsmsg.TypeA); err == nil {
		t.Fatal("answered a name that was never cached")
	}
}

func TestConcurrentLookupsForOneNameShareTheWork(t *testing.T) {
	n, r := world(t)
	n.delay = 20 * time.Millisecond
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Resolve(ctx, "WWW.example.test", dnsmsg.TypeA)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n.queries != 3 {
		t.Fatalf("10 lookups sent %d queries, want 3", n.queries)
	}
}

func TestAnswersCountTheirQueries(t *testing.T) {
	n, r := world(t)
	r.Cache, _ = newTestCache()
	for _, want := range []int{3, 0} {
		ans, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
		if err != nil || ans.Queries != want {
			t.Fatalf("Queries %d, want %d (%v)", ans.Queries, want, err)
		}
	}
	if ans, _ := r.Resolve(ctx, "nope.example.test", dnsmsg.TypeA); ans.Queries != 1 || n.queries != 4 {
		t.Fatalf("Queries %d, network saw %d", ans.Queries, n.queries)
	}
}

func TestBelow(t *testing.T) {
	for _, c := range []struct{ name, zone, want string }{
		{"a.b.example.com.", ".", "com."},
		{"a.b.example.com.", "com.", "example.com."},
		{"a.b.example.com.", "example.com.", "b.example.com."},
		{"a.b.example.com.", "b.example.com.", "a.b.example.com."},
		{"example.com.", "example.com.", "example.com."},
		{`a\.b.example.com.`, "example.com.", `a\.b.example.com.`},
	} {
		if got := below(c.name, c.zone); got != c.want {
			t.Errorf("below(%q, %q) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

func TestServersSeeOnlyOneLabelMoreThanTheirZone(t *testing.T) {
	n, r := world(t)
	var seen []string
	for addr, serve := range n.servers {
		n.servers[addr] = func(q dnsmsg.Question) dnsmsg.Message {
			seen = append(seen, addr.String()+" "+q.String())
			return serve(q)
		}
	}
	n.add("10.0.2.1", zone(t, "example.test.",
		"example.test. 300 SOA ns1.example.test. h.example.test. 60",
		"deep.a.b.example.test. 300 A 192.0.2.7",
		"b.example.test. 300 TXT x")) // b exists; a.b is empty but has a name below it
	serve := n.servers[addrs("10.0.2.1")[0]]
	n.servers[addrs("10.0.2.1")[0]] = func(q dnsmsg.Question) dnsmsg.Message {
		seen = append(seen, "10.0.2.1 "+q.String())
		return serve(q)
	}
	ans, err := r.Resolve(ctx, "deep.a.b.example.test", dnsmsg.TypeA)
	if err != nil || len(ans.Answers) != 1 {
		t.Fatalf("%v %v", ans, err)
	}
	want := []string{
		"10.0.0.1 test. A", "10.0.1.1 example.test. A", "10.0.2.1 b.example.test. A",
		"10.0.2.1 a.b.example.test. A",      // the fake wrongly says NXDOMAIN, so...
		"10.0.2.1 deep.a.b.example.test. A", // ...the full name is asked
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("servers saw\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
	seen, r.NoMinimise = nil, true
	r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	if seen[0] != "10.0.0.1 www.example.test. A" {
		t.Fatalf("with NoMinimise the root saw %q", seen[0])
	}
}

func TestStopsMinimisingTwoLabelsIntoAZone(t *testing.T) {
	n, r := world(t)
	n.add("10.0.2.1", zone(t, "example.test.",
		"example.test. 300 SOA ns1.example.test. h.example.test. 60",
		"a.b.c.d.example.test. 300 A 192.0.2.7",
		"d.example.test. 300 TXT x", "c.d.example.test. 300 TXT x", "b.c.d.example.test. 300 TXT x"))
	if _, err := r.Resolve(ctx, "a.b.c.d.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	// test., example.test., then d and c.d, then the full name.
	if n.queries != 5 {
		t.Fatalf("%d queries, want 5", n.queries)
	}
}

func TestTraceIndentsNestedLookups(t *testing.T) {
	n, r := world(t)
	n.add("10.0.1.1", zone(t, "test.",
		"example.test. 3600 NS ns1.example.test.", "ns1.example.test. 3600 A 10.0.2.1",
		"other.test. 3600 NS dns.example.test."))
	n.add("10.0.2.1", zone(t, "example.test.", "dns.example.test. 300 A 10.0.3.1"))
	n.add("10.0.3.1", zone(t, "other.test.", "www.other.test. 300 A 192.0.2.33"))
	var lines []string
	r.Trace = func(l string) { lines = append(lines, l) }
	if _, err := r.Resolve(ctx, "www.other.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	nested := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "  ") && strings.Contains(l, "dns.example.test") {
			nested++
		}
	}
	if nested == 0 || strings.HasPrefix(lines[0], " ") {
		t.Fatalf("trace:\n%s", strings.Join(lines, "\n"))
	}
}
