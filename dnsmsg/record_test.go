package dnsmsg

import (
	"net/netip"
	"testing"
)

func TestQuestionRoundTrip(t *testing.T) {
	q := Question{"example.com.", TypeAAAA, ClassINET}
	b, err := q.append(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, end, err := readQuestion(b, 0)
	if err != nil || got != q || end != len(b) {
		t.Fatalf("got %+v %d %v", got, end, err)
	}
	if _, _, err := readQuestion(b[:len(b)-1], 0); err != ErrShort {
		t.Fatalf("cut short: %v", err)
	}
}

func TestTypeNames(t *testing.T) {
	for in, want := range map[string]Type{"a": TypeA, "AAAA": TypeAAAA, "TYPE65": 65} {
		if got, err := ParseType(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if Type(65).String() != "TYPE65" || TypeMX.String() != "MX" {
		t.Error("String")
	}
	if _, err := ParseType("NOPE"); err == nil {
		t.Error("NOPE parsed")
	}
}

func TestReadRRParsesDataAndPointers(t *testing.T) {
	// "example.com." at 0, then an A record and an MX record that both point back at it.
	msg := []byte("\x07example\x03com\x00")
	msg = append(msg, 0xc0, 0, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34)
	mx := len(msg)
	msg = append(msg, 0xc0, 0, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9, 0, 10, 4, 'm', 'a', 'i', 'l', 0xc0, 0)
	a, off, err := readRR(msg, 13)
	if err != nil || off != mx || a.Name != "example.com." || a.TTL != 3600 || a.Addr.String() != "93.184.216.34" {
		t.Fatalf("A: %+v %d %v", a, off, err)
	}
	m, off, err := readRR(msg, mx)
	if err != nil || off != len(msg) || m.Pref != 10 || m.Target != "mail.example.com." {
		t.Fatalf("MX: %+v %d %v", m, off, err)
	}
	if m.String() != "example.com.\t60\tMX\t10 mail.example.com." {
		t.Errorf("String() = %q", m.String())
	}
}

func TestReadRRRejectsBadData(t *testing.T) {
	// An A record with 5 bytes of data.
	msg := []byte{0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4, 5}
	if _, _, err := readRR(msg, 0); err == nil {
		t.Error("5-byte A accepted")
	}
	// Data length running past the end.
	msg = []byte{0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 9, 1}
	if _, _, err := readRR(msg, 0); err != ErrShort {
		t.Errorf("long rdlength: %v", err)
	}
}

func TestRRRoundTripsEveryType(t *testing.T) {
	rrs := []RR{
		{Name: "a.example.", Type: TypeA, Class: ClassINET, TTL: 1, Addr: netip.MustParseAddr("192.0.2.1")},
		{Name: "a.example.", Type: TypeAAAA, Class: ClassINET, TTL: 2, Addr: netip.MustParseAddr("2001:db8::1")},
		{Name: "example.", Type: TypeNS, Class: ClassINET, TTL: 3, Target: "ns1.example."},
		{Name: "www.example.", Type: TypeCNAME, Class: ClassINET, TTL: 4, Target: "a.example."},
		{Name: "example.", Type: TypeMX, Class: ClassINET, TTL: 5, Pref: 10, Target: "mail.example."},
		{Name: "example.", Type: TypeSOA, Class: ClassINET, TTL: 6, SOA: SOA{"ns1.example.", "admin.example.", 7, 8, 9, 10, 11}},
		{Name: "example.", Type: TypeTXT, Class: ClassINET, TTL: 7, Text: []string{"v=spf1 -all", ""}},
		{Name: "example.", Type: 65, Class: ClassINET, TTL: 8, Raw: []byte{1, 2, 3}},
	}
	for _, r := range rrs {
		b, err := r.append(nil)
		if err != nil {
			t.Fatalf("%s: %v", r.Type, err)
		}
		got, end, err := readRR(b, 0)
		if err != nil || end != len(b) || got.String() != r.String() {
			t.Errorf("%s: got %q, want %q (%v)", r.Type, got.String(), r.String(), err)
		}
	}
	if _, err := (RR{Name: "x.", Type: TypeA, Addr: netip.MustParseAddr("::1")}).append(nil); err == nil {
		t.Error("A record with an IPv6 address written")
	}
}
