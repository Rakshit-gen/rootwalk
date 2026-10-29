// Package dnsmsg reads and writes DNS messages (RFC 1035) in wire format.
package dnsmsg

import (
	"encoding/binary"
	"errors"
)

// ErrShort means the message ended before a field it promised.
var (
	ErrShort    = errors.New("dnsmsg: message too short")
	ErrTrailing = errors.New("dnsmsg: bytes left after the last record")
)

// Response codes this resolver cares about.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

// Header is the fixed 12 bytes at the start of every message.
type Header struct {
	ID                 uint16
	Response           bool // QR
	Opcode             uint8
	Authoritative      bool // AA
	Truncated          bool // TC
	RecursionDesired   bool // RD
	RecursionAvailable bool // RA
	Rcode              uint8
	QDCount, ANCount   uint16
	NSCount, ARCount   uint16
}

func (h Header) flags() uint16 {
	f := uint16(h.Opcode&0xf)<<11 | uint16(h.Rcode&0xf)
	for _, b := range []struct {
		on  bool
		bit uint16
	}{{h.Response, 15}, {h.Authoritative, 10}, {h.Truncated, 9}, {h.RecursionDesired, 8}, {h.RecursionAvailable, 7}} {
		if b.on {
			f |= 1 << b.bit
		}
	}
	return f
}

func (h Header) append(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, h.ID)
	b = binary.BigEndian.AppendUint16(b, h.flags())
	for _, n := range []uint16{h.QDCount, h.ANCount, h.NSCount, h.ARCount} {
		b = binary.BigEndian.AppendUint16(b, n)
	}
	return b
}

func parseHeader(b []byte) (Header, error) {
	if len(b) < 12 {
		return Header{}, ErrShort
	}
	u := func(i int) uint16 { return binary.BigEndian.Uint16(b[i:]) }
	f := u(2)
	return Header{
		ID:                 u(0),
		Response:           f&(1<<15) != 0,
		Opcode:             uint8(f>>11) & 0xf,
		Authoritative:      f&(1<<10) != 0,
		Truncated:          f&(1<<9) != 0,
		RecursionDesired:   f&(1<<8) != 0,
		RecursionAvailable: f&(1<<7) != 0,
		Rcode:              uint8(f & 0xf),
		QDCount:            u(4), ANCount: u(6), NSCount: u(8), ARCount: u(10),
	}, nil
}
