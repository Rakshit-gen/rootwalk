package dnsmsg

import (
	"reflect"
	"testing"
)

// Whatever comes off the network, Unpack must not panic, and anything it
// accepts must survive being packed and unpacked again.
func FuzzUnpack(f *testing.F) {
	q, _ := NewQuery(1, "example.com", TypeMX, 1232).Pack()
	f.Add(q)
	f.Add([]byte("\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x02\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Unpack(b)
		if err != nil {
			return
		}
		again, err := m.Pack()
		if err != nil {
			return // e.g. a name that only fits compressed
		}
		m2, err := Unpack(again)
		if err != nil {
			t.Fatalf("repacked message doesn't parse: %v", err)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("changed on repack:\n%+v\n%+v", m, m2)
		}
	})
}
