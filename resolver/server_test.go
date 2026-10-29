package resolver

import (
	"testing"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

func TestReplyAnswersLikeARecursiveResolver(t *testing.T) {
	n, r := world(t)
	q := dnsmsg.NewQuery(7, "www.example.test", dnsmsg.TypeA, 1232)
	q.RecursionDesired = true
	m := r.Reply(ctx, q)
	if m.ID != 7 || !m.Response || !m.RecursionDesired || !m.RecursionAvailable || m.Rcode != dnsmsg.RcodeSuccess {
		t.Fatalf("header %+v", m.Header)
	}
	if len(m.Answers) != 1 || m.Answers[0].Addr.String() != "192.0.2.80" {
		t.Fatalf("answers %v", m.Answers)
	}
	if m = r.Reply(ctx, dnsmsg.NewQuery(8, "nope.example.test", dnsmsg.TypeA, 0)); m.Rcode != dnsmsg.RcodeNXDomain || len(m.Authority) != 1 {
		t.Fatalf("NXDOMAIN reply %+v", m)
	}
	delete(n.servers, addrs("10.0.2.1")[0])
	if m = r.Reply(ctx, dnsmsg.NewQuery(9, "mail.example.test", dnsmsg.TypeA, 0)); m.Rcode != dnsmsg.RcodeServFail {
		t.Fatalf("with example.test's server gone got rcode %d, want SERVFAIL", m.Rcode)
	}
	two := dnsmsg.NewQuery(10, "a.test", dnsmsg.TypeA, 0)
	two.Questions = append(two.Questions, two.Questions[0])
	notQuery := dnsmsg.NewQuery(11, "a.test", dnsmsg.TypeA, 0)
	notQuery.Opcode = 2
	before := n.queries
	if m = r.Reply(ctx, two); m.Rcode != dnsmsg.RcodeFormErr {
		t.Fatalf("two questions got rcode %d", m.Rcode)
	}
	if m = r.Reply(ctx, notQuery); m.Rcode != dnsmsg.RcodeNotImp {
		t.Fatalf("opcode 2 got rcode %d", m.Rcode)
	}
	if n.queries != before {
		t.Fatal("a bad query reached the network")
	}
}
