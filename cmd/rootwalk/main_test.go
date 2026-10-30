package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// oneServer pretends to be every server at once: authoritative for
// everything, with A records for names starting "www." and nothing else.
type oneServer struct{}

func (s *oneServer) Exchange(_ context.Context, _ netip.Addr, q dnsmsg.Question) (dnsmsg.Message, error) {
	m := dnsmsg.Message{Header: dnsmsg.Header{Response: true, Authoritative: true}, Questions: []dnsmsg.Question{q}}
	soa := dnsmsg.RR{Name: "test.", Type: dnsmsg.TypeSOA, Class: 1, TTL: 60, SOA: dnsmsg.SOA{MName: "ns.test.", RName: "h.test.", Minimum: 60}}
	switch {
	case strings.HasPrefix(q.Name, "www.") && q.Type == dnsmsg.TypeA:
		m.Answers = []dnsmsg.RR{{Name: q.Name, Type: dnsmsg.TypeA, Class: 1, TTL: 60, Addr: netip.MustParseAddr("192.0.2.1")}}
	case strings.HasPrefix(q.Name, "www."), q.Name == "test." || q.Name == "example.test.":
		m.Authority = []dnsmsg.RR{soa}
	default:
		m.Rcode = dnsmsg.RcodeNXDomain
		m.Authority = []dnsmsg.RR{soa}
	}
	return m, nil
}

func rootwalk(args ...string) (code int, out, errs string) {
	var stdout, stderr bytes.Buffer
	code = run(args, &oneServer{}, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestLookups(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"www.example.test"}, 0, "www.example.test.\t60\tA\t192.0.2.1\n"},
		{[]string{"www.example.test", "aaaa"}, 0, "; www.example.test. has no AAAA records\n"},
		{[]string{"nope.example.test"}, 0, "; nope.example.test. doesn't exist\n"},
		{[]string{"-json", "www.example.test"}, 0, `{"name":"www.example.test.","type":"A","rcode":"NOERROR",` +
			`"answers":[{"name":"www.example.test.","ttl":60,"type":"A","data":"192.0.2.1"}],"authority":[],"ms":`},
		{[]string{"-short", "www.example.test"}, 0, "192.0.2.1\n"},
		{[]string{"-short", "nope.example.test"}, 0, ""},
	} {
		code, out, errs := rootwalk(c.args...)
		if code != c.code || out != c.out && !(strings.HasSuffix(c.out, `"ms":`) && strings.HasPrefix(out, c.out)) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", c.args, code, out, errs)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "A", "extra"}, {"a", "NOTATYPE"}, {"-nope"}, {"serve", "extra"},
		{"serve", "-allow", "not-a-prefix"}, {"-short", "-json", "a"}} {
		if code, _, _ := rootwalk(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
