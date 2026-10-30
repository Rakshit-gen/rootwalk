package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// Type is a record type.
type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41
)

const ClassINET = 1

var typeNames = map[Type]string{TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeOPT: "OPT"}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// ParseType reads "A", "aaaa" or "TYPE65".
func ParseType(s string) (Type, error) {
	s = strings.ToUpper(s)
	for t, name := range typeNames {
		if name == s {
			return t, nil
		}
	}
	var n uint16
	if _, err := fmt.Sscanf(s, "TYPE%d", &n); err == nil {
		return Type(n), nil
	}
	return 0, fmt.Errorf("unknown record type %q", s)
}

// Question is what is being asked.
type Question struct {
	Name  string
	Type  Type
	Class uint16
}

func (q Question) String() string { return q.Name + " " + q.Type.String() }

func (q Question) append(b []byte, c compression) ([]byte, error) {
	b, err := c.appendName(b, q.Name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	return binary.BigEndian.AppendUint16(b, q.Class), nil
}

func readQuestion(msg []byte, off int) (Question, int, error) {
	name, off, err := readName(msg, off)
	if err != nil {
		return Question{}, 0, err
	}
	if off+4 > len(msg) {
		return Question{}, 0, ErrShort
	}
	return Question{name, Type(binary.BigEndian.Uint16(msg[off:])), binary.BigEndian.Uint16(msg[off+2:])}, off + 4, nil
}

// SOA is the start of a zone. Its Minimum bounds how long a "no such
// name" answer may be cached (RFC 2308).
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

// RR is one resource record. Which data field is set depends on Type:
// Addr for A and AAAA, Target for NS, CNAME, PTR, MX and SRV, Pref for MX
// and SRV (its priority), Weight and Port for SRV, SOA for SOA, Text for
// TXT, and Raw for everything else.
type RR struct {
	Name   string
	Type   Type
	Class  uint16
	TTL    uint32
	Addr   netip.Addr
	Target string
	Pref   uint16
	Weight uint16
	Port   uint16
	SOA    SOA
	Text   []string
	Raw    []byte
}

func (r RR) String() string {
	var data string
	switch r.Type {
	case TypeA, TypeAAAA:
		data = r.Addr.String()
	case TypeNS, TypeCNAME, TypePTR:
		data = r.Target
	case TypeMX:
		data = fmt.Sprintf("%d %s", r.Pref, r.Target)
	case TypeSRV:
		data = fmt.Sprintf("%d %d %d %s", r.Pref, r.Weight, r.Port, r.Target)
	case TypeSOA:
		s := r.SOA
		data = fmt.Sprintf("%s %s %d %d %d %d %d", s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
	case TypeTXT:
		q := make([]string, len(r.Text))
		for i, t := range r.Text {
			q[i] = fmt.Sprintf("%q", t)
		}
		data = strings.Join(q, " ")
	default:
		data = fmt.Sprintf(`\# %d %x`, len(r.Raw), r.Raw)
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", r.Name, r.TTL, r.Type, data)
}

func readRR(msg []byte, off int) (RR, int, error) {
	var r RR
	var err error
	if r.Name, off, err = readName(msg, off); err != nil {
		return RR{}, 0, err
	}
	if off+10 > len(msg) {
		return RR{}, 0, ErrShort
	}
	r.Type = Type(binary.BigEndian.Uint16(msg[off:]))
	r.Class = binary.BigEndian.Uint16(msg[off+2:])
	r.TTL = binary.BigEndian.Uint32(msg[off+4:])
	n := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if off+n > len(msg) {
		return RR{}, 0, ErrShort
	}
	data, end := msg[off:off+n], off+n
	bad := fmt.Errorf("dnsmsg: bad %s data", r.Type)
	switch r.Type {
	case TypeA, TypeAAAA:
		addr, ok := netip.AddrFromSlice(data)
		if !ok || (r.Type == TypeA) != (n == 4) {
			return RR{}, 0, bad
		}
		r.Addr = addr
	case TypeNS, TypeCNAME, TypePTR:
		// Names inside data may point anywhere earlier in the message.
		if r.Target, off, err = readName(msg, off); err != nil || off != end {
			return RR{}, 0, bad
		}
	case TypeMX:
		if n < 3 {
			return RR{}, 0, bad
		}
		r.Pref = binary.BigEndian.Uint16(data)
		if r.Target, off, err = readName(msg, off+2); err != nil || off != end {
			return RR{}, 0, bad
		}
	case TypeSRV:
		if n < 7 {
			return RR{}, 0, bad
		}
		r.Pref, r.Weight, r.Port = binary.BigEndian.Uint16(data), binary.BigEndian.Uint16(data[2:]), binary.BigEndian.Uint16(data[4:])
		if r.Target, off, err = readName(msg, off+6); err != nil || off != end {
			return RR{}, 0, bad
		}
	case TypeSOA:
		s := &r.SOA
		if s.MName, off, err = readName(msg, off); err != nil {
			return RR{}, 0, bad
		}
		if s.RName, off, err = readName(msg, off); err != nil || end-off != 20 {
			return RR{}, 0, bad
		}
		u := func(i int) uint32 { return binary.BigEndian.Uint32(msg[off+4*i:]) }
		s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum = u(0), u(1), u(2), u(3), u(4)
	case TypeTXT:
		for i := 0; i < n; {
			l := int(data[i])
			if i+1+l > n {
				return RR{}, 0, bad
			}
			r.Text = append(r.Text, string(data[i+1:i+1+l]))
			i += 1 + l
		}
	default:
		r.Raw = append([]byte(nil), data...)
	}
	return r, end, nil
}

func (r RR) append(b []byte, c compression) ([]byte, error) {
	b, err := c.appendName(b, r.Name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(r.Type))
	b = binary.BigEndian.AppendUint16(b, r.Class)
	b = binary.BigEndian.AppendUint32(b, r.TTL)
	lenAt := len(b)
	b = append(b, 0, 0)
	switch r.Type {
	case TypeA, TypeAAAA:
		if !r.Addr.IsValid() || (r.Type == TypeA) != r.Addr.Is4() {
			return nil, fmt.Errorf("dnsmsg: %s record needs an IPv%s address", r.Type, map[bool]string{true: "4", false: "6"}[r.Type == TypeA])
		}
		b = append(b, r.Addr.AsSlice()...)
	// RFC 3597: only these original types may have their data compressed.
	case TypeNS, TypeCNAME, TypePTR:
		b, err = c.appendName(b, r.Target)
	case TypeMX:
		b = binary.BigEndian.AppendUint16(b, r.Pref)
		b, err = c.appendName(b, r.Target)
	case TypeSRV:
		b = binary.BigEndian.AppendUint16(b, r.Pref)
		b = binary.BigEndian.AppendUint16(b, r.Weight)
		b = binary.BigEndian.AppendUint16(b, r.Port)
		b, err = appendName(b, r.Target) // RFC 2782: never compressed
	case TypeSOA:
		if b, err = c.appendName(b, r.SOA.MName); err == nil {
			b, err = c.appendName(b, r.SOA.RName)
		}
		for _, n := range []uint32{r.SOA.Serial, r.SOA.Refresh, r.SOA.Retry, r.SOA.Expire, r.SOA.Minimum} {
			b = binary.BigEndian.AppendUint32(b, n)
		}
	case TypeTXT:
		for _, t := range r.Text {
			if len(t) > 255 {
				return nil, fmt.Errorf("dnsmsg: TXT string longer than 255 bytes")
			}
			b = append(append(b, byte(len(t))), t...)
		}
	default:
		b = append(b, r.Raw...)
	}
	if err != nil {
		return nil, err
	}
	n := len(b) - lenAt - 2
	if n > 0xffff {
		return nil, fmt.Errorf("dnsmsg: record data too long")
	}
	binary.BigEndian.PutUint16(b[lenAt:], uint16(n))
	return b, nil
}
