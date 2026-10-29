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
