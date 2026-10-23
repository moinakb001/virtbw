package virtualhere

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type echoDevice struct{ send func([]byte) }

func (d *echoDevice) SetResponseHandler(f func([]byte)) { d.send = f }
func (d *echoDevice) HandleMessage(p []byte)            { d.send(append([]byte(nil), p...)) }

type testPeer struct {
	t     *testing.T
	conn  net.Conn
	seq   uint32
	stash []message
}

func startTestServer(t *testing.T, factory func() ReportDevice) (*Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(factory)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	return s, listener.Addr().String()
}
func connectPeer(t *testing.T, address string) *testPeer {
	t.Helper()
	socket, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	p := &testPeer{t: t, conn: socket}
	m := p.send(0, make([]byte, 132))
	h := p.receive(1, m.context)
	if len(h.payload) != 724 {
		t.Fatal("hello size")
	}
	return p
}
func (p *testPeer) send(kind byte, payload []byte) message {
	p.t.Helper()
	p.seq++
	m := message{kind: kind, address: deviceAddress, payload: payload, timeout: 3000}
	le.PutUint32(m.context[:4], p.seq)
	m.context[19] = 0xab
	p.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := writeMessage(p.conn, m); err != nil {
		p.t.Fatal(err)
	}
	return m
}
func (p *testPeer) receive(kind byte, ctx [20]byte) message {
	p.t.Helper()
	for i, m := range p.stash {
		if m.kind == kind && m.context == ctx {
			p.stash = append(p.stash[:i], p.stash[i+1:]...)
			return m
		}
	}
	for {
		p.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := readMessage(p.conn)
		if err != nil {
			p.t.Fatal(err)
		}
		if m.kind == kind && m.context == ctx {
			return m
		}
		p.stash = append(p.stash, m)
	}
}
func (p *testPeer) bind() int32 {
	p.send(25, nil)
	return int32(le.Uint32(p.receive(39, [20]byte{}).payload))
}
func (p *testPeer) control(bm, request byte, value, index, length uint16, data []byte) message {
	payload := make([]byte, 16)
	payload[8] = bm
	payload[9] = request
	le.PutUint16(payload[10:12], value)
	le.PutUint16(payload[12:14], index)
	le.PutUint16(payload[14:16], length)
	payload = append(payload, data...)
	m := p.send(13, payload)
	return p.receive(14, m.context)
}
func (p *testPeer) transfer(ep byte, length int, data []byte) message {
	payload := make([]byte, 13)
	le.PutUint32(payload, uint32(ep))
	le.PutUint32(payload[5:9], 1)
	le.PutUint32(payload[9:13], uint32(length))
	return p.send(18, append(payload, data...))
}
func TestBindOwnershipControlAndDisconnect(t *testing.T) {
	_, address := startTestServer(t, func() ReportDevice { return &echoDevice{} })
	a := connectPeer(t, address)
	b := connectPeer(t, address)
	if a.bind() != 1 || a.bind() != -9 || b.bind() != -2 {
		t.Fatal("ownership results")
	}
	response := a.control(0x80, 6, 0x100, 0, 64, nil)
	if len(response.payload) != 80 || le.Uint32(response.payload[12:16]) != 18 || !bytes.Equal(response.payload[16:34], deviceDescriptor) {
		t.Fatal("device descriptor")
	}
	response = a.control(0x81, 6, 0x2200, 0, 255, nil)
	if !bytes.Equal(response.payload[16:16+len(reportDescriptor)], reportDescriptor) {
		t.Fatal("report descriptor")
	}
	response = a.control(0x80, 6, 0x9900, 0, 16, nil)
	if int32(le.Uint32(response.payload[8:12])) != -32 {
		t.Fatal("unsupported descriptor did not stall")
	}
	response = a.control(0x80, 0, 0, 0, 2, nil)
	if !bytes.Equal(response.payload[16:], []byte{1, 0}) {
		t.Fatal("GET_STATUS must be 2 bytes")
	}
	a.control(0, 9, 1, 0, 0, nil)
	response = a.control(0x80, 8, 0, 0, 1, nil)
	if response.payload[16] != 1 {
		t.Fatal("configuration")
	}
	a.conn.Close()
	// Wait for the reader's disconnect cleanup rather than racing ownership.
	deadline := time.Now().Add(time.Second)
	for b.bind() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("ownership not released")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestInterruptFIFOAndEndpointCancellation(t *testing.T) {
	_, address := startTestServer(t, func() ReportDevice { return &echoDevice{} })
	p := connectPeer(t, address)
	if p.bind() != 1 {
		t.Fatal("bind")
	}
	p.control(0, 9, 1, 0, 0, nil)
	one := p.transfer(0x81, 64, nil)
	two := p.transfer(0x81, 80, nil)
	for i := byte(1); i <= 2; i++ {
		out := p.transfer(2, 64, bytes.Repeat([]byte{i}, 64))
		if le.Uint32(p.receive(19, out.context).payload) != 64 {
			t.Fatal("OUT length")
		}
	}
	first := p.receive(19, one.context)
	second := p.receive(19, two.context)
	if !bytes.Equal(first.payload[4:], bytes.Repeat([]byte{1}, 64)) || !bytes.Equal(second.payload[4:68], bytes.Repeat([]byte{2}, 64)) || len(second.payload) != 84 || !bytes.Equal(second.payload[68:], make([]byte, 16)) {
		t.Fatal("report ordering/padding")
	}
	one = p.transfer(0x81, 64, nil)
	two = p.transfer(0x81, 64, nil)
	cancel := p.send(30, result(0x81))
	p.receive(31, cancel.context)
	for _, m := range []message{one, two} {
		if int32(le.Uint32(p.receive(19, m.context).payload)) != -2 {
			t.Fatal("endpoint cancellation")
		}
	}
}
func TestResponseAfterReleaseCannotLeakToNextOwner(t *testing.T) {
	var mu sync.Mutex
	var devices []*echoDevice
	_, address := startTestServer(t, func() ReportDevice {
		d := &echoDevice{}
		mu.Lock()
		devices = append(devices, d)
		mu.Unlock()
		return d
	})
	p := connectPeer(t, address)
	p.bind()
	p.control(0, 9, 1, 0, 0, nil)
	p.send(35, nil)
	p.receive(7, [20]byte{})
	p.bind()
	p.control(0, 9, 1, 0, 0, nil)
	mu.Lock()
	old := devices[0]
	current := devices[1]
	mu.Unlock()
	old.send(bytes.Repeat([]byte{0xee}, 64))
	in := p.transfer(0x81, 64, nil)
	current.send(bytes.Repeat([]byte{0x44}, 64))
	if !bytes.Equal(p.receive(19, in.context).payload[4:], bytes.Repeat([]byte{0x44}, 64)) {
		t.Fatal("old binding leaked response")
	}
}
func TestMalformedRequestClosesOnlyItsConnection(t *testing.T) {
	_, address := startTestServer(t, func() ReportDevice { return &echoDevice{} })
	bad := connectPeer(t, address)
	good := connectPeer(t, address)
	bad.send(18, []byte{1})
	bad.conn.SetReadDeadline(time.Now().Add(time.Second))
	// Consume startup notification first, then require closure.
	for {
		_, err := readMessage(bad.conn)
		if err != nil {
			break
		}
	}
	m := good.send(10, nil)
	good.receive(11, m.context)
}
