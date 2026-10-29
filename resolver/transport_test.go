package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// A server on 127.0.0.1 that answers UDP with a reply for some other query
// and then a truncated one, and TCP with the full answer.
func fakeServer(t *testing.T) uint16 {
	var tl net.Listener
	var ul net.PacketConn
	for range 20 {
		var err error
		if tl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ul, err = net.ListenPacket("udp", tl.Addr().String()); err == nil {
			break
		}
		tl.Close()
	}
	t.Cleanup(func() { tl.Close(); ul.Close() })
	reply := func(query []byte, id uint16, truncated bool) []byte {
		q, _ := dnsmsg.Unpack(query)
		m := dnsmsg.Message{Header: dnsmsg.Header{ID: id, Response: true, Truncated: truncated}, Questions: q.Questions}
		if !truncated {
			m.Answers = []dnsmsg.RR{{Name: q.Questions[0].Name, Type: dnsmsg.TypeA, Class: 1, TTL: 5, Addr: netip.MustParseAddr("192.0.2.9")}}
		}
		b, _ := m.Pack()
		return b
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			id := binary.BigEndian.Uint16(buf)
			ul.WriteTo(reply(buf[:n], id+1, false), from) // wrong ID: must be ignored
			ul.WriteTo(reply(buf[:n], id, true), from)
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			var size [2]byte
			io.ReadFull(c, size[:])
			q := make([]byte, binary.BigEndian.Uint16(size[:]))
			io.ReadFull(c, q)
			r := reply(q, binary.BigEndian.Uint16(q), false)
			c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
			c.Close()
		}
	}()
	return uint16(tl.Addr().(*net.TCPAddr).Port)
}

func TestTruncatedAnswersAreFetchedOverTCP(t *testing.T) {
	n := Net{Port: fakeServer(t), Timeout: time.Second}
	m, err := n.Exchange(context.Background(), netip.MustParseAddr("127.0.0.1"), dnsmsg.Question{Name: "x.example.", Type: dnsmsg.TypeA, Class: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.Truncated || len(m.Answers) != 1 || m.Answers[0].Addr.String() != "192.0.2.9" {
		t.Fatalf("got %+v", m)
	}
}
