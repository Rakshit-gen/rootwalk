package dnsmsg

import "testing"

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
