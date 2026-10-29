package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// RootServers are the IPv4 addresses of a to m.root-servers.net (IANA root hints).
var RootServers = addrs("198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129",
	"199.7.83.42", "202.12.27.33")

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
}

// Resolver walks from the root servers down to an authoritative answer.
type Resolver struct {
	Net   Exchanger
	Roots []netip.Addr // RootServers unless set
	Trace func(string) // called with each step, if set
}

const maxReferrals = 16

var ErrNoAnswer = errors.New("no server gave a usable answer")

func (r *Resolver) trace(format string, args ...any) {
	if r.Trace != nil {
		r.Trace(fmt.Sprintf(format, args...))
	}
}

// Resolve finds the records of type t for name.
func (r *Resolver) Resolve(ctx context.Context, name string, t dnsmsg.Type) (Answer, error) {
	return r.lookup(ctx, dnsmsg.Fqdn(name), t)
}

func (r *Resolver) lookup(ctx context.Context, name string, t dnsmsg.Type) (Answer, error) {
	servers := r.Roots
	if servers == nil {
		servers = RootServers
	}
	zone := "."
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
		child, ns := referral(m, name, zone)
		if child == "" {
			return Answer{}, fmt.Errorf("%s: %s gave neither an answer nor a referral", q, server)
		}
		glue := glueFor(m, ns, zone)
		r.trace("%s sent %s to %s (%d servers, %d with addresses)", server, q, child, len(ns), len(glue))
		if len(glue) == 0 {
			return Answer{}, fmt.Errorf("%s: referral to %s has no addresses", q, child)
		}
		zone, servers = child, glue
	}
	return Answer{}, fmt.Errorf("%s: more than %d referrals", q, maxReferrals)
}

// ask tries the servers in turn until one replies.
func (r *Resolver) ask(ctx context.Context, servers []netip.Addr, q dnsmsg.Question) (dnsmsg.Message, netip.Addr, error) {
	var errs []error
	for _, s := range servers {
		m, err := r.Net.Exchange(ctx, s, q)
		if err == nil {
			return m, s, nil
		}
		errs = append(errs, err)
	}
	return dnsmsg.Message{}, netip.Addr{}, fmt.Errorf("%w: %v", ErrNoAnswer, errors.Join(errs...))
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
// server was asked as.
func glueFor(m dnsmsg.Message, ns []string, from string) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Additional {
		if rr.Type != dnsmsg.TypeA && rr.Type != dnsmsg.TypeAAAA || !inZone(rr.Name, from) {
			continue
		}
		for _, n := range ns {
			if strings.EqualFold(rr.Name, n) && rr.Addr.Is4() { // IPv4 only: no IPv6 route is assumed
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
