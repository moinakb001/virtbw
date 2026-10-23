package virtualhere

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestCapturedVendorFrames(t *testing.T) {
	var fixtures []struct {
		Wire     string `json:"wire_hex"`
		Messages []struct {
			Kind    byte   `json:"type"`
			Context string `json:"context"`
			Address uint32 `json:"address"`
			Payload string `json:"payload_hex"`
		} `json:"messages"`
	}
	b, err := os.ReadFile("testdata/vendor_frames.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		wire, _ := hex.DecodeString(f.Wire)
		reader := bytes.NewReader(wire)
		for _, expected := range f.Messages {
			m, err := readMessage(reader)
			if err != nil {
				t.Fatal(err)
			}
			if m.kind != expected.Kind || m.address != expected.Address || hex.EncodeToString(m.context[:]) != expected.Context || hex.EncodeToString(m.payload) != expected.Payload {
				t.Fatal("vendor frame mismatch")
			}
		}
		if reader.Len() != 0 {
			t.Fatal("unconsumed vendor bytes")
		}
	}
}
func TestFrameRoundTripAndBounds(t *testing.T) {
	m := message{kind: 18, timeout: 3000, address: 22, payload: []byte{1, 2, 3}}
	m.context[19] = 0xa5
	var wire bytes.Buffer
	if err := writeMessage(&wire, m); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), wire.Bytes()...)
	got, err := readMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.kind != m.kind || got.timeout != m.timeout || got.context != m.context || !bytes.Equal(got.payload, m.payload) {
		t.Fatal("round trip")
	}
	for n := 0; n < len(data); n++ {
		if _, err := readMessage(bytes.NewReader(data[:n])); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	bad := append([]byte(nil), data...)
	le.PutUint32(bad[4:8], maxFrame+1)
	if _, err := readMessage(bytes.NewReader(bad)); err == nil {
		t.Fatal("accepted oversized frame")
	}
	bad = append([]byte(nil), data...)
	le.PutUint32(bad[37:41], 99)
	if _, err := readMessage(bytes.NewReader(bad)); err == nil {
		t.Fatal("accepted mismatched payload")
	}
}
func TestLZ4OverlapAndMalformedBlocks(t *testing.T) {
	out, err := decodeLZ4([]byte{0x10, 'A', 1, 0, 0x10, 'Z'}, 6)
	if err != nil || string(out) != "AAAAAZ" {
		t.Fatalf("overlap: %q %v", out, err)
	}
	for _, data := range [][]byte{{0x10}, {0x00, 0, 0}, {0x00, 1, 0}, {0xf0, 255}, {0x10, 'A', 1}, {0x1f, 'A', 1, 0, 255}} {
		if _, err := decodeLZ4(data, 8); err == nil {
			t.Fatalf("accepted malformed %x", data)
		}
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}
func TestPartialWriter(t *testing.T) {
	w := new(shortWriter)
	if err := writeMessage(w, message{kind: 10}); err != nil {
		t.Fatal(err)
	}
	m, err := readMessage(w)
	if err != nil || m.kind != 10 {
		t.Fatal(m, err)
	}
	if _, err = readMessage(w); err != io.EOF {
		t.Fatal(err)
	}
}
