package resolver

import (
	"context"
	"net"

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

// ServeUDP answers queries arriving on conn until ctx is done, each in its
// own goroutine so a slow lookup doesn't hold up the rest.
func (r *Resolver) ServeUDP(ctx context.Context, conn net.PacketConn) error {
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		q, err := dnsmsg.Unpack(buf[:n])
		if err != nil {
			continue // not DNS, or not worth a reply
		}
		go func() {
			if b, err := fitUDP(r.Reply(ctx, q), q); err == nil {
				conn.WriteTo(b, from)
			}
		}()
	}
}

// fitUDP packs a reply for UDP. It advertises EDNS0 back to clients that
// used it, and if the reply won't fit the client's buffer it sends just
// the header and question with TC set, so the client retries over TCP.
func fitUDP(m dnsmsg.Message, q dnsmsg.Message) ([]byte, error) {
	limit := 512
	for _, rr := range q.Additional {
		if rr.Type == dnsmsg.TypeOPT {
			limit = max(512, min(int(rr.Class), udpSize))
			m.Additional = []dnsmsg.RR{{Name: ".", Type: dnsmsg.TypeOPT, Class: udpSize}}
		}
	}
	b, err := m.Pack()
	if err != nil || len(b) <= limit {
		return b, err
	}
	m.Truncated, m.Answers, m.Authority = true, nil, nil
	return m.Pack()
}
