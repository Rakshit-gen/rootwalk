package resolver

import (
	"context"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// Reply answers a query from a client the way a recursive resolver does:
// one question, looked up from the root, with the outcome's rcode. A lookup
// that fails becomes SERVFAIL so the client can try elsewhere.
func (r *Resolver) Reply(ctx context.Context, q dnsmsg.Message) dnsmsg.Message {
	m := dnsmsg.Message{
		Header: dnsmsg.Header{ID: q.ID, Response: true, Opcode: q.Opcode,
			RecursionDesired: q.RecursionDesired, RecursionAvailable: true},
		Questions: q.Questions,
	}
	switch {
	case q.Response:
		m.Rcode = dnsmsg.RcodeFormErr
	case q.Opcode != 0:
		m.Rcode = dnsmsg.RcodeNotImp
	case len(q.Questions) != 1 || q.Questions[0].Class != dnsmsg.ClassINET:
		m.Rcode = dnsmsg.RcodeFormErr
	default:
		ans, err := r.Resolve(ctx, q.Questions[0].Name, q.Questions[0].Type)
		if err != nil {
			r.trace("%s: %v", q.Questions[0], err)
			m.Rcode = dnsmsg.RcodeServFail
			break
		}
		m.Rcode, m.Answers, m.Authority = ans.Rcode, ans.Answers, ans.Authority
	}
	return m
}
