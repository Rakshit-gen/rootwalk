// Package resolver answers questions by walking down from the root servers.
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// Exchanger sends one query to one server. The resolver only talks to the
// network through this, so tests can swap in fake servers.
type Exchanger interface {
	Exchange(ctx context.Context, server netip.Addr, q dnsmsg.Question) (dnsmsg.Message, error)
}

// Net talks to real servers on port 53 over UDP.
type Net struct {
	Timeout time.Duration
	Port    uint16 // 53 unless set; tests point it elsewhere
}

const udpSize = 1232 // the EDNS0 size DNS Flag Day 2020 settled on

func (n Net) Exchange(ctx context.Context, server netip.Addr, q dnsmsg.Question) (dnsmsg.Message, error) {
	return n.exchange(ctx, "udp", server, q)
}

func (n Net) exchange(ctx context.Context, network string, server netip.Addr, q dnsmsg.Question) (dnsmsg.Message, error) {
	timeout := n.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	port := n.Port
	if port == 0 {
		port = 53
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(server, port).String())
	if err != nil {
		return dnsmsg.Message{}, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	id := randomID()
	query, err := dnsmsg.NewQuery(id, q.Name, q.Type, udpSize).Pack()
	if err != nil {
		return dnsmsg.Message{}, err
	}
	if _, err := conn.Write(query); err != nil {
		return dnsmsg.Message{}, err
	}
	for {
		reply, err := read(conn, network)
		if err != nil {
			return dnsmsg.Message{}, err
		}
		m, err := dnsmsg.Unpack(reply)
		// A UDP reply with the wrong ID or question may be a spoofing
		// attempt or a late answer to something else: keep listening.
		if err == nil && matches(m, id, q) {
			return m, nil
		}
	}
}

func read(conn net.Conn, network string) ([]byte, error) {
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	return buf[:n], err
}

func matches(m dnsmsg.Message, id uint16, q dnsmsg.Question) bool {
	return m.Response && m.ID == id && len(m.Questions) == 1 &&
		strings.EqualFold(m.Questions[0].Name, dnsmsg.Fqdn(q.Name)) && m.Questions[0].Type == q.Type
}

func randomID() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
