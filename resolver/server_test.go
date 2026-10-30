package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

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

// serving starts r on a loopback port, UDP and TCP, and returns a client for it.
func serving(t *testing.T, r *Resolver) (Net, netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Resolver: r}
	go s.ServeTCP(ctx, ln)
	go s.ServeUDP(ctx, pc)
	return Net{Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port)}, netip.MustParseAddr("127.0.0.1")
}

// bigWorld is world with a name that has more A records than fit in 512 bytes.
func bigWorld(t *testing.T) (*network, *Resolver) {
	n, r := world(t)
	lines := []string{"example.test. 300 SOA ns1.example.test. h.example.test. 60"}
	for i := range 100 { // 1600 bytes or so, past the 1232 EDNS0 buffer
		lines = append(lines, fmt.Sprintf("big.example.test. 300 A 192.0.2.%d", i+1))
	}
	n.add("10.0.2.1", zone(t, "example.test.", lines...))
	return n, r
}

func TestServesOverUDP(t *testing.T) {
	_, r := world(t)
	client, at := serving(t, r)
	m, err := client.Exchange(ctx, at, dnsmsg.Question{Name: "www.example.test.", Type: dnsmsg.TypeA, Class: dnsmsg.ClassINET})
	if err != nil || len(m.Answers) != 1 || m.Answers[0].Addr.String() != "192.0.2.80" {
		t.Fatalf("got %+v, %v", m, err)
	}
}

func TestTruncatesWhatDoesntFitTheClientsBuffer(t *testing.T) {
	_, r := bigWorld(t)
	client, at := serving(t, r)
	conn, err := net.Dial("udp", netip.AddrPortFrom(at, client.Port).String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := dnsmsg.NewQuery(1, "big.example.test", dnsmsg.TypeA, 0)
	q.Additional = nil // no EDNS0, so 512 bytes is the limit
	b, _ := q.Pack()
	conn.Write(b)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := dnsmsg.Unpack(buf[:n])
	if err != nil || !m.Truncated || len(m.Answers) != 0 || n > 512 {
		t.Fatalf("%d bytes, TC=%v, %d answers, %v", n, m.Truncated, len(m.Answers), err)
	}
}

func TestAClientFallsBackToTCPForTheWholeAnswer(t *testing.T) {
	_, r := bigWorld(t)
	client, at := serving(t, r)
	m, err := client.Exchange(ctx, at, dnsmsg.Question{Name: "big.example.test.", Type: dnsmsg.TypeA, Class: dnsmsg.ClassINET})
	if err != nil || m.Truncated || len(m.Answers) != 100 {
		t.Fatalf("TC=%v, %d answers, %v", m.Truncated, len(m.Answers), err)
	}
}

func TestRepliesSpeakEDNSOnlyToClientsThatDo(t *testing.T) {
	_, r := world(t)
	plain := dnsmsg.NewQuery(1, "www.example.test", dnsmsg.TypeA, 0)
	plain.Additional = nil
	if m := r.Reply(ctx, plain); len(m.Additional) != 0 {
		t.Fatalf("OPT sent to a client without EDNS: %v", m.Additional)
	}
	if e, ok := r.Reply(ctx, dnsmsg.NewQuery(2, "www.example.test", dnsmsg.TypeA, 4096)).EDNS(); !ok || e.UDPSize != udpSize {
		t.Fatalf("got %+v %v", e, ok)
	}
	v1 := dnsmsg.NewQuery(3, "www.example.test", dnsmsg.TypeA, 1232)
	v1.Additional[0].TTL = 1 << 16
	m := r.Reply(ctx, v1)
	if len(m.Answers) != 0 || m.Additional[0].TTL>>24 != 1 {
		t.Fatalf("EDNS version 1 got %+v, want BADVERS", m)
	}
}

func TestOnlyAllowedClientsGetAnswers(t *testing.T) {
	n, r := world(t)
	s := &Server{Resolver: r}
	q := dnsmsg.NewQuery(1, "www.example.test", dnsmsg.TypeA, 0)
	for from, want := range map[string]uint8{
		"127.0.0.1:5000": dnsmsg.RcodeSuccess, "[::1]:5000": dnsmsg.RcodeSuccess,
		"192.168.1.20:5000": dnsmsg.RcodeSuccess, "[fe80::1]:5000": dnsmsg.RcodeSuccess,
		"203.0.113.9:5000": dnsmsg.RcodeRefused, "[2001:db8::1]:5000": dnsmsg.RcodeRefused,
	} {
		if m := s.answer(ctx, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(from)), q); m.Rcode != want {
			t.Errorf("%s: rcode %d, want %d", from, m.Rcode, want)
		}
	}
	s.Allow = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	before := n.queries
	if m := s.answer(ctx, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:5000")), q); m.Rcode != dnsmsg.RcodeRefused {
		t.Errorf("loopback outside Allow got rcode %d", m.Rcode)
	}
	if n.queries != before {
		t.Error("a refused client's query reached the network")
	}
	if m := s.answer(ctx, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.9:5000")), q); m.Rcode != dnsmsg.RcodeSuccess {
		t.Errorf("an allowed client got rcode %d", m.Rcode)
	}
}

func TestClientsOverTheRateAreSentToTCP(t *testing.T) {
	_, r := world(t)
	s := &Server{Resolver: r, Rate: 2}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeUDP(ctx, pc)
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	truncated, answered := 0, 0
	for i := range 6 {
		b, _ := dnsmsg.NewQuery(uint16(i), "www.example.test", dnsmsg.TypeA, 1232).Pack()
		conn.Write(b)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		got, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		m, err := dnsmsg.Unpack(buf[:got])
		if err != nil {
			t.Fatal(err)
		}
		if m.Truncated {
			truncated++
		} else if len(m.Answers) == 1 {
			answered++
		}
	}
	if truncated != 2 || answered != 4 {
		t.Fatalf("%d of 6 truncated (want 2), %d answered (want 4)", truncated, answered)
	}
}
