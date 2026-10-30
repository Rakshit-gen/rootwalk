package resolver

import (
	"context"
	"encoding/binary"
	"net"
	"time"

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
	e, edns := q.EDNS()
	if edns {
		m.Additional = []dnsmsg.RR{{Name: ".", Type: dnsmsg.TypeOPT, Class: udpSize}}
	}
	switch {
	case edns && e.Version > 0:
		// BADVERS, rcode 16: its upper bits go in the OPT record (RFC 6891).
		m.Additional[0].TTL = 1 << 24
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

// fitUDP packs a reply for UDP. If it won't fit the client's buffer, 512
// bytes or what its EDNS0 record says, it sends just the header and
// question with TC set, so the client retries over TCP.
func fitUDP(m dnsmsg.Message, q dnsmsg.Message) ([]byte, error) {
	limit := 512
	if e, ok := q.EDNS(); ok {
		limit = max(512, min(int(e.UDPSize), udpSize))
	}
	b, err := m.Pack()
	if err != nil || len(b) <= limit {
		return b, err
	}
	m.Truncated, m.Answers, m.Authority = true, nil, nil
	return m.Pack()
}

// ServeTCP answers queries on connections from ln until ctx is done. A
// client may send several queries on one connection; it is closed after
// idle seconds without one.
func (r *Resolver) ServeTCP(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go r.serveConn(ctx, conn)
	}
}

const idle = 10 * time.Second

func (r *Resolver) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	for {
		conn.SetDeadline(time.Now().Add(idle))
		b, err := read(conn, "tcp")
		if err != nil {
			return
		}
		q, err := dnsmsg.Unpack(b)
		if err != nil {
			return
		}
		out, err := r.Reply(ctx, q).Pack()
		if err != nil || len(out) > 65535 {
			return
		}
		conn.SetDeadline(time.Now().Add(idle))
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil {
			return
		}
	}
}
