package dnsmsg

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrLabel   = errors.New("dnsmsg: bad label")
	ErrName    = errors.New("dnsmsg: name longer than 255 bytes")
	ErrPointer = errors.New("dnsmsg: bad compression pointer")
)

// readName reads a possibly compressed name at off and returns it in
// presentation form with a trailing dot ("example.com."), and the offset
// just past it. Pointers must point backwards, so a loop can't spin.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1 // where the name ends in the original position, once a pointer is followed
	wire := 1 // bytes the name takes uncompressed, for the 255 limit
	for limit := off; ; {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		n := int(msg[off])
		switch n & 0xc0 {
		case 0x00:
			if n == 0 {
				if end < 0 {
					end = off + 1
				}
				if sb.Len() == 0 {
					return ".", end, nil
				}
				return sb.String(), end, nil
			}
			if off+1+n > len(msg) {
				return "", 0, ErrShort
			}
			if wire += n + 1; wire > 255 {
				return "", 0, ErrName
			}
			for _, c := range msg[off+1 : off+1+n] {
				if c == '.' || c == '\\' {
					sb.WriteByte('\\')
				}
				sb.WriteByte(c)
			}
			sb.WriteByte('.')
			off += 1 + n
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, ErrShort
			}
			ptr := (n&0x3f)<<8 | int(msg[off+1])
			if ptr >= limit {
				return "", 0, ErrPointer
			}
			if end < 0 {
				end = off + 2
			}
			off, limit = ptr, ptr
		default:
			return "", 0, ErrLabel // 0x40 and 0x80 are reserved
		}
	}
}

// appendName writes name uncompressed. It accepts names with or without
// the trailing dot and the \. and \\ escapes readName produces.
func appendName(b []byte, name string) ([]byte, error) {
	if name == "." || name == "" {
		return append(b, 0), nil
	}
	start := len(b)
	var label []byte
	flush := func() error {
		if len(label) == 0 || len(label) > 63 {
			return ErrLabel
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
		label = label[:0]
		return nil
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c == '\\' && i+1 < len(name):
			i++
			label = append(label, name[i])
		case c == '.':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			label = append(label, c)
		}
	}
	if len(label) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	b = append(b, 0)
	if len(b)-start > 255 {
		return nil, ErrName
	}
	return b, nil
}

// compression maps the wire form of each name suffix already written to
// its offset in the message, so later names can point back at it. A nil
// compression writes names in full.
type compression map[string]int

func (c compression) appendName(b []byte, name string) ([]byte, error) {
	start := len(b)
	b, err := appendName(b, name)
	if err != nil || c == nil {
		return b, err
	}
	for i := start; b[i] != 0; i += int(b[i]) + 1 {
		// Exact bytes, so a pointer never changes a name's case. The lookup
		// doesn't copy the suffix; only storing a new one does.
		if at, ok := c[string(b[i:])]; ok {
			return binary.BigEndian.AppendUint16(b[:i], 0xc000|uint16(at)), nil
		}
		if i < 0x4000 {
			c[string(b[i:])] = i
		}
	}
	return b, nil
}

// CheckName reports whether name can be written in a message: no empty
// labels, none over 63 bytes, and 255 bytes in all.
func CheckName(name string) error {
	_, err := appendName(nil, name)
	return err
}

// Fqdn adds the trailing dot if it is missing.
func Fqdn(name string) string {
	if strings.HasSuffix(name, ".") && !strings.HasSuffix(name, `\.`) {
		return name
	}
	return name + "."
}
