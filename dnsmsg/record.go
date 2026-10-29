package dnsmsg

import (
	"encoding/binary"
	"fmt"
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
	TypeOPT   Type = 41
)

const ClassINET = 1

var typeNames = map[Type]string{TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT"}

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

func (q Question) append(b []byte) ([]byte, error) {
	b, err := appendName(b, q.Name)
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
