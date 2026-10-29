package dnsmsg

import "testing"

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{ID: 0xbeef, Response: true, Opcode: 2, Authoritative: true, Truncated: true,
		RecursionDesired: true, RecursionAvailable: true, Rcode: RcodeNXDomain, QDCount: 1, ANCount: 2, NSCount: 3, ARCount: 4}
	got, err := parseHeader(h.append(nil))
	if err != nil || got != h {
		t.Fatalf("got %+v, %v; want %+v", got, err, h)
	}
	if _, err := parseHeader(make([]byte, 11)); err != ErrShort {
		t.Fatalf("11 bytes: got %v, want ErrShort", err)
	}
}

func TestHeaderFlagBits(t *testing.T) {
	// A standard recursive query from dig: RD set, nothing else.
	b := Header{ID: 1, RecursionDesired: true, QDCount: 1}.append(nil)
	if b[2] != 0x01 || b[3] != 0x00 {
		t.Fatalf("flags = %#x %#x, want 0x01 0x00", b[2], b[3])
	}
}
