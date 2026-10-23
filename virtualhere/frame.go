// Package virtualhere exposes a virtual FIDO HID device using the recovered
// Linux VirtualHere 4.8.8 framing. It is an experimental interoperability server.
package virtualhere

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const headerSize = 33
const maxFrame = 1024 * 1024 // This HID-only implementation does not need 50 MiB URBs.
var le = binary.LittleEndian

type message struct {
	kind    byte
	timeout uint32
	context [20]byte
	address uint32
	payload []byte
}

func readMessage(r io.Reader) (message, error) {
	var m message
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return m, err
	}
	c, u := le.Uint32(prefix[:4]), le.Uint32(prefix[4:])
	if u < headerSize || u > maxFrame || c > maxFrame {
		return m, errors.New("invalid frame length")
	}
	size := u
	if c != 0 {
		size = c
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return m, err
	}
	if c != 0 {
		var err error
		body, err = decodeLZ4(body, int(u))
		if err != nil {
			return m, err
		}
	}
	if le.Uint32(body[29:33]) != uint32(len(body)-headerSize) {
		return m, errors.New("payload length mismatch")
	}
	m.kind = body[0]
	m.timeout = le.Uint32(body[1:5])
	copy(m.context[:], body[5:25])
	m.address = le.Uint32(body[25:29])
	m.payload = body[33:]
	return m, nil
}

func writeMessage(w io.Writer, m message) error {
	if len(m.payload) > maxFrame-headerSize {
		return errors.New("reply too large")
	}
	data := make([]byte, 8+headerSize+len(m.payload))
	le.PutUint32(data[4:8], uint32(headerSize+len(m.payload)))
	b := data[8:]
	b[0] = m.kind
	le.PutUint32(b[1:5], m.timeout)
	copy(b[5:25], m.context[:])
	le.PutUint32(b[25:29], m.address)
	le.PutUint32(b[29:33], uint32(len(m.payload)))
	copy(b[33:], m.payload)
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// decodeLZ4 accepts independent raw blocks, including overlapping matches.
func decodeLZ4(src []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	pos := 0
	length := func(n int) (int, error) {
		if n != 15 {
			return n, nil
		}
		for {
			if pos == len(src) {
				return 0, io.ErrUnexpectedEOF
			}
			v := int(src[pos])
			pos++
			n += v
			if n > size {
				return 0, errors.New("LZ4 length overflow")
			}
			if v != 255 {
				return n, nil
			}
		}
	}
	for pos < len(src) {
		token := src[pos]
		pos++
		literal, err := length(int(token >> 4))
		if err != nil {
			return nil, err
		}
		if literal > len(src)-pos || literal > size-len(out) {
			return nil, errors.New("invalid LZ4 literals")
		}
		out = append(out, src[pos:pos+literal]...)
		pos += literal
		if pos == len(src) {
			break
		}
		if len(src)-pos < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		offset := int(le.Uint16(src[pos : pos+2]))
		pos += 2
		if offset == 0 || offset > len(out) {
			return nil, errors.New("invalid LZ4 offset")
		}
		match, err := length(int(token & 15))
		if err != nil {
			return nil, err
		}
		match += 4
		if match > size-len(out) {
			return nil, errors.New("LZ4 output overflow")
		}
		for i := 0; i < match; i++ {
			out = append(out, out[len(out)-offset])
		}
	}
	if len(out) != size {
		return nil, fmt.Errorf("LZ4 output size %d, want %d", len(out), size)
	}
	return out, nil
}

func result(value int32) []byte { p := make([]byte, 4); le.PutUint32(p, uint32(value)); return p }
func fixed(dst []byte, s string) {
	if len(dst) > 0 {
		copy(dst[:len(dst)-1], s)
	}
}
