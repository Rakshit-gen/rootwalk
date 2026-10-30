package dnsmsg

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	m := Message{
		Header:    Header{ID: 7, Response: true, Authoritative: true},
		Questions: []Question{{"example.", TypeA, ClassINET}},
		Answers:   []RR{{Name: "example.", Type: TypeA, Class: ClassINET, TTL: 60, Addr: netip.MustParseAddr("192.0.2.7")}},
		Authority: []RR{{Name: "example.", Type: TypeNS, Class: ClassINET, TTL: 60, Target: "ns.example."}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	m.QDCount, m.ANCount, m.NSCount = 1, 1, 1
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("got %+v\nwant %+v", got, m)
	}
	if _, err := Unpack(append(b, 0)); err != ErrTrailing {
		t.Errorf("trailing byte: %v", err)
	}
}

func TestNewQueryLooksLikeDigs(t *testing.T) {
	b, err := NewQuery(1, "example.com", TypeA, 1232).Pack()
	if err != nil {
		t.Fatal(err)
	}
	// Header, question, then the OPT record: root name, type 41, class 1232.
	want := "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01" +
		"\x07example\x03com\x00\x00\x01\x00\x01" +
		"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
	if string(b) != want {
		t.Fatalf("got %q\nwant %q", b, want)
	}
}

func TestPackCompressesRepeatedNames(t *testing.T) {
	m := Message{Header: Header{ID: 1, Response: true}, Questions: []Question{{"www.example.com.", TypeA, ClassINET}}}
	for i := range 20 {
		m.Answers = append(m.Answers, RR{Name: "www.example.com.", Type: TypeA, Class: ClassINET, TTL: 60,
			Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
	}
	m.Authority = []RR{{Name: "Example.com.", Type: TypeNS, Class: ClassINET, TTL: 60, Target: "ns.example.com."}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// 12 header, 21 question, 20 answers of pointer+10+4, then "\x07Example" and a pointer, 10, and "\x02ns" and a pointer.
	if len(b) != 12+21+20*16+10+10+5 {
		t.Fatalf("%d bytes", len(b))
	}
	got, err := Unpack(b)
	if err != nil || !reflect.DeepEqual(got.Answers, m.Answers) || !reflect.DeepEqual(got.Authority, m.Authority) {
		t.Fatalf("round trip: %v\n%+v", err, got)
	}
}

func TestEDNS(t *testing.T) {
	if _, ok := (Message{}).EDNS(); ok {
		t.Fatal("found EDNS in an empty message")
	}
	m := NewQuery(1, "example.com", TypeA, 1232)
	m.Additional[0].TTL = 1<<16 | 0x8000
	if e, ok := m.EDNS(); !ok || e != (EDNS{UDPSize: 1232, Version: 1, DO: true}) {
		t.Fatalf("got %+v %v", e, ok)
	}
}
