package resolver

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// rr parses one line of zone data: "name ttl TYPE data...".
func rr(t *testing.T, line string) dnsmsg.RR {
	t.Helper()
	f := strings.Fields(line)
	ttl, _ := strconv.Atoi(f[1])
	typ, err := dnsmsg.ParseType(f[2])
	if err != nil {
		t.Fatal(err)
	}
	r := dnsmsg.RR{Name: f[0], Type: typ, Class: 1, TTL: uint32(ttl)}
	switch typ {
	case dnsmsg.TypeA, dnsmsg.TypeAAAA:
		r.Addr = netip.MustParseAddr(f[3])
	case dnsmsg.TypeNS, dnsmsg.TypeCNAME:
		r.Target = f[3]
	case dnsmsg.TypeSOA:
		min, _ := strconv.Atoi(f[5])
		r.SOA = dnsmsg.SOA{MName: f[3], RName: f[4], Minimum: uint32(min)}
	}
	return r
}

// authority is a fake authoritative server for one zone. NS records below
// the zone's own name are delegations.
type authority struct {
	zone string
	rrs  []dnsmsg.RR
}

func zone(t *testing.T, name string, lines ...string) *authority {
	z := &authority{zone: name}
	for _, l := range lines {
		z.rrs = append(z.rrs, rr(t, l))
	}
	return z
}

func (z *authority) answer(q dnsmsg.Question) dnsmsg.Message {
	m := dnsmsg.Message{Header: dnsmsg.Header{Response: true}, Questions: []dnsmsg.Question{q}}
	if !inZone(q.Name, z.zone) {
		m.Rcode = dnsmsg.RcodeRefused
		return m
	}
	// The deepest delegation covering the name, if any.
	var cut string
	for _, r := range z.rrs {
		if r.Type == dnsmsg.TypeNS && !strings.EqualFold(r.Name, z.zone) && inZone(q.Name, r.Name) && len(r.Name) > len(cut) {
			cut = r.Name
		}
	}
	if cut != "" {
		for _, r := range z.rrs {
			if r.Type == dnsmsg.TypeNS && r.Name == cut {
				m.Authority = append(m.Authority, r)
				for _, g := range z.rrs {
					if g.Name == r.Target && (g.Type == dnsmsg.TypeA || g.Type == dnsmsg.TypeAAAA) {
						m.Additional = append(m.Additional, g)
					}
				}
			}
		}
		return m
	}
	m.Authoritative = true
	exists := false
	for _, r := range z.rrs {
		if strings.EqualFold(r.Name, q.Name) {
			exists = true
			if r.Type == q.Type || r.Type == dnsmsg.TypeCNAME {
				m.Answers = append(m.Answers, r)
			}
		}
	}
	if len(m.Answers) == 0 {
		if !exists {
			m.Rcode = dnsmsg.RcodeNXDomain
		}
		for _, r := range z.rrs {
			if r.Type == dnsmsg.TypeSOA {
				m.Authority = append(m.Authority, r)
			}
		}
	}
	return m
}

// network routes queries to fake servers by address and counts them.
type network struct {
	servers map[netip.Addr]func(dnsmsg.Question) dnsmsg.Message
	queries int
	delay   time.Duration // how long each query takes
}

func (n *network) Exchange(ctx context.Context, server netip.Addr, q dnsmsg.Question) (dnsmsg.Message, error) {
	n.queries++
	select {
	case <-time.After(n.delay):
	case <-ctx.Done():
		return dnsmsg.Message{}, ctx.Err()
	}
	s, ok := n.servers[server]
	if !ok {
		return dnsmsg.Message{}, errors.New("timeout")
	}
	return s(q), nil
}

func (n *network) add(addr string, z *authority) {
	if n.servers == nil {
		n.servers = map[netip.Addr]func(dnsmsg.Question) dnsmsg.Message{}
	}
	n.servers[netip.MustParseAddr(addr)] = z.answer
}

// A root, a .test TLD and an example.test zone, each on its own server.
func world(t *testing.T) (*network, *Resolver) {
	n := &network{}
	n.add("10.0.0.1", zone(t, ".",
		". 86400 SOA a.root. nstld. 86400",
		"test. 172800 NS ns.nic.test.",
		"ns.nic.test. 172800 A 10.0.1.1"))
	n.add("10.0.1.1", zone(t, "test.",
		"test. 900 SOA ns.nic.test. h.nic.test. 900",
		"example.test. 3600 NS ns1.example.test.",
		"ns1.example.test. 3600 A 10.0.2.1"))
	n.add("10.0.2.1", zone(t, "example.test.",
		"example.test. 300 SOA ns1.example.test. h.example.test. 60",
		"www.example.test. 300 A 192.0.2.80",
		"example.test. 300 A 192.0.2.1"))
	return n, &Resolver{Net: n, Roots: addrs("10.0.0.1")}
}
