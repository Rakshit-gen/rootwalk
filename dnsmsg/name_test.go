package dnsmsg

import "testing"

func TestReadNameFollowsPointers(t *testing.T) {
	// "example.com." at 0, then "www" + pointer to it at 13.
	msg := []byte("\x07example\x03com\x00\x03www\xc0\x00")
	name, end, err := readName(msg, 13)
	if err != nil || name != "www.example.com." || end != len(msg) {
		t.Fatalf("got %q %d %v", name, end, err)
	}
	if name, _, _ := readName([]byte{0}, 0); name != "." {
		t.Fatalf("root = %q", name)
	}
}

func TestReadNameRejectsLoopsAndBadInput(t *testing.T) {
	cases := map[string]struct {
		msg  []byte
		want error
	}{
		"pointer to itself": {[]byte{0xc0, 0x00}, ErrPointer},
		"pointer forwards":  {[]byte{0xc0, 0x02, 0x00}, ErrPointer},
		"two-hop loop":      {[]byte("\x01a\xc0\x04\x01b\xc0\x00"), ErrPointer},
		"cut off label":     {[]byte("\x05ab"), ErrShort},
		"reserved bits":     {[]byte{0x40}, ErrLabel},
		"no end":            {[]byte("\x01a"), ErrShort},
	}
	for name, c := range cases {
		off := 0
		if name == "two-hop loop" {
			off = 4
		}
		if _, _, err := readName(c.msg, off); err != c.want {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestReadNameLimitsLength(t *testing.T) {
	var msg []byte
	for i := 0; i < 5; i++ {
		msg = append(msg, 63)
		msg = append(msg, make([]byte, 63)...)
	}
	msg = append(msg, 0)
	if _, _, err := readName(msg, 0); err != ErrName {
		t.Fatalf("got %v, want ErrName", err)
	}
}

func TestAppendNameRoundTrips(t *testing.T) {
	for _, name := range []string{".", "com.", "www.example.com.", `odd\.label.example.`} {
		b, err := appendName(nil, name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		got, end, err := readName(b, 0)
		if err != nil || got != name || end != len(b) {
			t.Errorf("%q came back as %q (%d of %d, %v)", name, got, end, len(b), err)
		}
	}
	if b, _ := appendName(nil, "example.com"); string(b) != "\x07example\x03com\x00" {
		t.Errorf("no trailing dot: %q", b)
	}
}

func TestAppendNameRejectsBadLabels(t *testing.T) {
	long := string(make([]byte, 64))
	for _, name := range []string{"a..b.", long + ".com."} {
		if _, err := appendName(nil, name); err != ErrLabel {
			t.Errorf("%q: got %v, want ErrLabel", name, err)
		}
	}
}

func TestFqdn(t *testing.T) {
	if Fqdn("example.com") != "example.com." || Fqdn("example.com.") != "example.com." {
		t.Fatal("Fqdn")
	}
}
