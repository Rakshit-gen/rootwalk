package dnsmsg

// Message is a whole DNS message.
type Message struct {
	Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

// Pack writes m, setting the section counts from the slices.
func (m Message) Pack() ([]byte, error) {
	h := m.Header
	h.QDCount, h.ANCount = uint16(len(m.Questions)), uint16(len(m.Answers))
	h.NSCount, h.ARCount = uint16(len(m.Authority)), uint16(len(m.Additional))
	b := h.append(make([]byte, 0, 512))
	var err error
	for _, q := range m.Questions {
		if b, err = q.append(b); err != nil {
			return nil, err
		}
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, r := range sec {
			if b, err = r.append(b); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// Unpack reads a whole message. Bytes after the last record are an error,
// so a message that doesn't add up is never half-trusted.
func Unpack(b []byte) (Message, error) {
	h, err := parseHeader(b)
	if err != nil {
		return Message{}, err
	}
	m := Message{Header: h}
	off := 12
	for i := 0; i < int(h.QDCount); i++ {
		var q Question
		if q, off, err = readQuestion(b, off); err != nil {
			return Message{}, err
		}
		m.Questions = append(m.Questions, q)
	}
	for _, sec := range []struct {
		n   uint16
		dst *[]RR
	}{{h.ANCount, &m.Answers}, {h.NSCount, &m.Authority}, {h.ARCount, &m.Additional}} {
		for i := 0; i < int(sec.n); i++ {
			var r RR
			if r, off, err = readRR(b, off); err != nil {
				return Message{}, err
			}
			*sec.dst = append(*sec.dst, r)
		}
	}
	if off != len(b) {
		return Message{}, ErrTrailing
	}
	return m, nil
}

// NewQuery is a single question with an EDNS0 record advertising udpSize,
// so servers can send answers bigger than 512 bytes over UDP.
func NewQuery(id uint16, name string, t Type, udpSize uint16) Message {
	return Message{
		Header:     Header{ID: id},
		Questions:  []Question{{Fqdn(name), t, ClassINET}},
		Additional: []RR{{Name: ".", Type: TypeOPT, Class: udpSize}},
	}
}
