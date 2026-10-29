package dnsmsg

import (
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
