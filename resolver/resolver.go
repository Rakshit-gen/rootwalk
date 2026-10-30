package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// RootServers are the IPv4 addresses of a to m.root-servers.net (IANA root hints).
var RootServers = addrs("198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129",
	"199.7.83.42", "202.12.27.33")

// RootServersV6 are their IPv6 addresses, used when Resolver.IPv6 is set.
var RootServersV6 = addrs("2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d",
	"2001:500:a8::e", "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53", "2001:7fe::53",
	"2001:503:c27::2:30", "2001:7fd::1", "2001:500:9f::42", "2001:dc3::35")

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// Answer is the outcome of a lookup.
type Answer struct {
	Rcode     uint8
	Answers   []dnsmsg.RR
	Authority []dnsmsg.RR // the SOA, for a negative answer

	next string // a CNAME target the answer stopped at, still to look up
}

// Resolver walks from the root servers down to an authoritative answer.
type Resolver struct {
	Net   Exchanger
	Roots []netip.Addr // RootServers (and RootServersV6 with IPv6) unless set
	Trace func(string) // called with each step, if set
	Cache *Cache       // nil means no caching

	// Timeout bounds a whole Resolve, every referral and nested lookup
	// included. 10 seconds unless set.
	Timeout time.Duration

	// IPv6 lets nameservers be reached over IPv6 as well as IPv4. Leave it
	// off on a network without an IPv6 route, or every IPv6 server tried
	// costs a timeout.
	IPv6 bool

	rtt rtts
}

const (
	maxReferrals = 16
	maxDepth     = 8 // nested lookups for nameserver addresses
	maxCNAMEs    = 8
	maxGlueless  = 4  // nameservers looked up per referral that came without glue
	maxQueries   = 64 // sent for one Resolve, nested lookups and retries included
)

var (
	ErrNoAnswer = errors.New("no server gave a usable answer")
	ErrBudget   = fmt.Errorf("sent %d queries without an answer", maxQueries)
)

// budget counts the queries one Resolve may still send. It rides in the
// context so nested lookups draw from the same one.
type budget struct{ left atomic.Int32 }

type budgetKey struct{}

func spend(ctx context.Context) bool {
	b, ok := ctx.Value(budgetKey{}).(*budget)
	return !ok || b.left.Add(-1) >= 0
}

func (r *Resolver) trace(format string, args ...any) {
	if r.Trace != nil {
		r.Trace(fmt.Sprintf(format, args...))
	}
}

// Resolve finds the records of type t for name, following CNAMEs. The
// answer holds the whole chain, CNAMEs first.
func (r *Resolver) Resolve(ctx context.Context, name string, t dnsmsg.Type) (Answer, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	b := &budget{}
	b.left.Store(maxQueries)
	return r.resolve(context.WithValue(ctx, budgetKey{}, b), dnsmsg.Fqdn(name), t, 0)
}

func (r *Resolver) resolve(ctx context.Context, name string, t dnsmsg.Type, depth int) (Answer, error) {
	var chain []dnsmsg.RR
	seen := map[string]bool{}
	for range maxCNAMEs + 1 {
		if seen[strings.ToLower(name)] {
			return Answer{}, fmt.Errorf("%s: CNAME loop", name)
		}
		seen[strings.ToLower(name)] = true
		ans, err := r.cached(ctx, name, t, depth)
		if err != nil {
			return Answer{}, err
		}
		chain = append(chain, ans.Answers...)
		if ans.next == "" {
			ans.Answers = chain
			return ans, nil
		}
		r.trace("following CNAME to %s", ans.next)
		name = ans.next
	}
	return Answer{}, fmt.Errorf("%s: more than %d CNAMEs", name, maxCNAMEs)
}

// cached answers from the cache, or looks the name up and stores the result.
func (r *Resolver) cached(ctx context.Context, name string, t dnsmsg.Type, depth int) (Answer, error) {
	if r.Cache == nil {
		return r.lookup(ctx, name, t, depth)
	}
	if rrs, rcode, ok := r.Cache.Get(name, t); ok {
		r.trace("cache has %s %s", name, t)
		if rrs[0].Type != t { // a negative entry holds only the SOA
			return Answer{Rcode: rcode, Authority: rrs}, nil
		}
		return Answer{Answers: rrs}, nil
	}
	if rrs, _, ok := r.Cache.Get(name, dnsmsg.TypeCNAME); ok && t != dnsmsg.TypeCNAME {
		r.trace("cache has %s CNAME", name)
		return Answer{Answers: rrs, next: rrs[0].Target}, nil
	}
	ans, err := r.lookup(ctx, name, t, depth)
	if err != nil {
		return ans, err
	}
	// Each record set is cached under its own name, so a chain is reusable from any point.
	for _, rr := range ans.Answers {
		r.Cache.Put(rr.Name, rr.Type, matching(ans.Answers, rr.Name, rr.Type))
	}
	if len(ans.Answers) == 0 && len(ans.Authority) > 0 {
		r.Cache.PutNegative(name, t, ans.Rcode, ans.Authority[0])
	}
	return ans, nil
}

func (r *Resolver) lookup(ctx context.Context, name string, t dnsmsg.Type, depth int) (Answer, error) {
	if depth > maxDepth {
		return Answer{}, fmt.Errorf("%s %s: nameserver lookups nested more than %d deep", name, t, maxDepth)
	}
	servers := r.Roots
	if servers == nil {
		servers = RootServers
		if r.IPv6 {
			servers = append(slices.Clone(RootServers), RootServersV6...)
		}
	}
	zone := "."
	if r.Cache != nil {
		if z, cached := r.Cache.Closest(name); z != "" {
			r.trace("starting at %s from the cache", z)
			zone, servers = z, cached
		}
	}
	q := dnsmsg.Question{Name: name, Type: t, Class: dnsmsg.ClassINET}
	for range maxReferrals {
		m, server, err := r.ask(ctx, servers, q)
		if err != nil {
			return Answer{}, err
		}
		if answers := matching(m.Answers, name, t); len(answers) > 0 {
			r.trace("%s answered %s from %s", server, q, zone)
			return Answer{Rcode: m.Rcode, Answers: answers}, nil
		}
		if chain, end := cnames(m.Answers, name, zone); len(chain) > 0 && t != dnsmsg.TypeCNAME {
			r.trace("%s answered %s with a CNAME", server, q)
			// Records for a target outside the server's zone aren't its to give.
			if answers := matching(m.Answers, end, t); len(answers) > 0 && inZone(end, zone) {
				return Answer{Rcode: m.Rcode, Answers: append(chain, answers...)}, nil
			}
			return Answer{Rcode: m.Rcode, Answers: chain, next: end}, nil
		}
		soa := matchingType(m.Authority, dnsmsg.TypeSOA)
		if m.Rcode == dnsmsg.RcodeNXDomain {
			r.trace("%s says %s doesn't exist", server, name)
			return Answer{Rcode: dnsmsg.RcodeNXDomain, Authority: soa}, nil
		}
		child, ns := referral(m, name, zone)
		if child == "" {
			if m.Rcode == dnsmsg.RcodeSuccess && (m.Authoritative || len(soa) > 0) {
				r.trace("%s says %s has no %s records", server, name, t)
				return Answer{Rcode: dnsmsg.RcodeSuccess, Authority: soa}, nil
			}
			return Answer{}, fmt.Errorf("%s: %s gave neither an answer nor a referral", q, server)
		}
		glue := glueFor(m, ns, zone, r.IPv6)
		r.trace("%s sent %s to %s (%d servers, %d with addresses)", server, q, child, len(ns), len(glue))
		if len(glue) == 0 {
			glue = r.addressesOf(ctx, ns, depth)
		}
		if len(glue) == 0 {
			return Answer{}, fmt.Errorf("%s: no address found for any of %s's servers", q, child)
		}
		if r.Cache != nil {
			if nsrr := matching(m.Authority, child, dnsmsg.TypeNS); len(nsrr) > 0 {
				r.Cache.PutZone(child, glue, nsrr[0].TTL)
			}
		}
		zone, servers = child, glue
	}
	return Answer{}, fmt.Errorf("%s: more than %d referrals", q, maxReferrals)
}

// addressesOf looks up the nameservers' addresses, stopping at the first
// that resolves: one working server is enough to carry on. Only the first
// few are tried, so a referral to hundreds of names that don't resolve
// can't turn one query into hundreds (the NXNSAttack).
func (r *Resolver) addressesOf(ctx context.Context, ns []string, depth int) []netip.Addr {
	for _, n := range ns[:min(len(ns), maxGlueless)] {
		r.trace("looking up %s's address", n)
		ans, err := r.resolve(ctx, n, dnsmsg.TypeA, depth+1)
		if err != nil {
			continue
		}
		var out []netip.Addr
		for _, rr := range matchingType(ans.Answers, dnsmsg.TypeA) { // not the CNAMEs on the way
			out = append(out, rr.Addr)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// ask tries the servers, fastest known first, until one gives a reply worth using. A
// server that fails, refuses or doesn't understand the query is skipped.
func (r *Resolver) ask(ctx context.Context, servers []netip.Addr, q dnsmsg.Question) (dnsmsg.Message, netip.Addr, error) {
	var errs []error
	for _, s := range r.rtt.order(servers) {
		if err := ctx.Err(); err != nil {
			return dnsmsg.Message{}, netip.Addr{}, fmt.Errorf("%s: %w", q, err)
		}
		if !spend(ctx) {
			return dnsmsg.Message{}, netip.Addr{}, fmt.Errorf("%s: %w", q, ErrBudget)
		}
		start := time.Now()
		actx, cancel := context.WithTimeout(ctx, r.rtt.timeout(s))
		m, err := r.Net.Exchange(actx, s, q)
		cancel()
		if ctx.Err() == nil { // our deadline running out says nothing about the server
			r.rtt.observe(s, time.Since(start), err == nil)
		}
		if err == nil && m.Rcode != dnsmsg.RcodeSuccess && m.Rcode != dnsmsg.RcodeNXDomain {
			err = fmt.Errorf("%s answered %s with rcode %d", s, q, m.Rcode)
		}
		if err == nil {
			return m, s, nil
		}
		r.trace("%v", err)
		errs = append(errs, err)
	}
	return dnsmsg.Message{}, netip.Addr{}, fmt.Errorf("%w: %w", ErrNoAnswer, errors.Join(errs...))
}

func matching(rrs []dnsmsg.RR, name string, t dnsmsg.Type) []dnsmsg.RR {
	var out []dnsmsg.RR
	for _, rr := range rrs {
		if strings.EqualFold(rr.Name, name) && rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

func matchingType(rrs []dnsmsg.RR, t dnsmsg.Type) []dnsmsg.RR {
	var out []dnsmsg.RR
	for _, rr := range rrs {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

// cnames follows CNAME records for name within one reply, returning the
// chain and the name it ends at. It stops at the first target outside zone,
// the zone of the server that sent the reply.
func cnames(rrs []dnsmsg.RR, name, zone string) ([]dnsmsg.RR, string) {
	var chain []dnsmsg.RR
	for range maxCNAMEs {
		if len(chain) > 0 && !inZone(name, zone) {
			break
		}
		c := matching(rrs, name, dnsmsg.TypeCNAME)
		if len(c) == 0 {
			break
		}
		chain = append(chain, c[0])
		name = c[0].Target
	}
	return chain, name
}

// referral returns the zone a reply delegates to and its nameservers. Only
// a delegation strictly below the zone the server was asked as counts: a
// server for .test can't hand out the servers for com.
func referral(m dnsmsg.Message, name, from string) (string, []string) {
	var zone string
	var ns []string
	for _, rr := range m.Authority {
		if rr.Type != dnsmsg.TypeNS || !inZone(name, rr.Name) || !inZone(rr.Name, from) || strings.EqualFold(rr.Name, from) {
			continue
		}
		if zone == "" {
			zone = strings.ToLower(rr.Name)
		}
		if strings.EqualFold(rr.Name, zone) {
			ns = append(ns, strings.ToLower(rr.Target))
		}
	}
	return zone, ns
}

// glueFor returns the addresses the additional section gives for the
// nameservers, believing only addresses for names inside the zone the
// server was asked as. IPv6 addresses are kept only if v6 is set.
func glueFor(m dnsmsg.Message, ns []string, from string, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Additional {
		if rr.Type != dnsmsg.TypeA && rr.Type != dnsmsg.TypeAAAA || !inZone(rr.Name, from) {
			continue
		}
		for _, n := range ns {
			if strings.EqualFold(rr.Name, n) && (rr.Addr.Is4() || v6) {
				out = append(out, rr.Addr)
			}
		}
	}
	return out
}

// inZone reports whether name is zone or under it.
func inZone(name, zone string) bool {
	name, zone = strings.ToLower(dnsmsg.Fqdn(name)), strings.ToLower(dnsmsg.Fqdn(zone))
	return zone == "." || name == zone || strings.HasSuffix(name, "."+zone)
}
