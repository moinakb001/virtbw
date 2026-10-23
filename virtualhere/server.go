package virtualhere

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const serverIdentity = "virtbw-virtualhere"
const serverName = "virtbw Virtual FIDO"

// Server exports one software FIDO device. It supports plaintext manual-hub
// connections, one owner, and multiple inventory observers. No vault is read
// by this package and no authentication/TLS or remote administration is offered.
type Server struct {
	factory     func() ReportDevice
	mu          sync.Mutex
	reportMu    sync.Mutex // The backend/terminal approver is shared across bindings.
	connections map[*connection]bool
	owner       *connection
}

type connection struct {
	server              *Server
	conn                net.Conn
	writeMu             sync.Mutex
	mu                  sync.Mutex
	done                chan struct{}
	once                sync.Once
	uuid                [16]byte
	identity, hostname  string
	hello               bool
	configuration, idle byte
	boundAt             time.Time
	pending             []message
	responses           [][]byte
	reportsOut          chan []byte
	bindingDone         chan struct{}
}

func NewServer(factory func() ReportDevice) *Server {
	return &Server{factory: factory, connections: make(map[*connection]bool)}
}

// Serve closes the listener and active connections when ctx is canceled.
// Callers should bind loopback: this experimental HID transport is plaintext.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.factory == nil {
		return errors.New("nil HID device factory")
	}
	stopped := make(chan struct{})
	var workers sync.WaitGroup
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
			s.mu.Lock()
			for c := range s.connections {
				c.close()
			}
			s.mu.Unlock()
		case <-stopped:
		}
	}()
	defer func() {
		listener.Close()
		s.mu.Lock()
		for c := range s.connections {
			c.close()
		}
		s.mu.Unlock()
		workers.Wait()
	}()
	for {
		socket, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		c := &connection{server: s, conn: socket, done: make(chan struct{})}
		if _, err = rand.Read(c.uuid[:]); err != nil {
			socket.Close()
			return err
		}
		s.mu.Lock()
		if len(s.connections) >= 16 {
			s.mu.Unlock()
			socket.Close()
			continue
		}
		s.connections[c] = true
		s.mu.Unlock()
		workers.Add(1)
		go func() { defer workers.Done(); c.run() }()
	}
}

func (c *connection) close() { c.once.Do(func() { close(c.done); c.conn.Close() }) }
func (c *connection) send(m message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := writeMessage(c.conn, m)
	if err != nil {
		c.close()
	}
	return err
}
func (c *connection) reply(request message, kind byte, payload []byte) error {
	return c.send(message{kind: kind, context: request.context, address: request.address, payload: payload})
}
func (c *connection) run() {
	defer func() {
		c.close()
		c.server.release(c)
		c.server.mu.Lock()
		delete(c.server.connections, c)
		c.server.mu.Unlock()
	}()
	for {
		c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		m, err := readMessage(c.conn)
		if err != nil {
			return
		}
		if !c.hello && m.kind != 0 {
			return
		}
		if err = c.handle(m); err != nil {
			return
		}
	}
}
func (c *connection) heartbeats() {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case t := <-ticker.C:
			if c.send(message{kind: 12, payload: result(int32(t.Unix()))}) != nil {
				return
			}
		}
	}
}
func (c *connection) isOwner() bool {
	c.server.mu.Lock()
	defer c.server.mu.Unlock()
	return c.server.owner == c
}
func (s *Server) inventory() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := make([]byte, 571)
	fixed(p[4:68], "virtbw")
	fixed(p[68:132], "virtbw Virtual FIDO")
	le.PutUint32(p[132:136], deviceAddress)
	p[136] = 1
	p[221] = 1
	p[222] = 1
	p[223] = 3 // HID interface class
	fixed(p[306:434], "virtbw")
	p[499] = 2
	le.PutUint32(p[500:504], 2)
	if c := s.owner; c != nil {
		p[136] = 3
		copy(p[137:153], c.uuid[:])
		copy(p[153:157], []byte{127, 0, 0, 1})
		fixed(p[226:290], c.identity)
		fixed(p[434:498], c.hostname)
		fixed(p[539:571], c.boundAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	return p
}
func (s *Server) broadcast() {
	p := s.inventory()
	s.mu.Lock()
	clients := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		if c.hello {
			clients = append(clients, c)
		}
	}
	s.mu.Unlock()
	for _, c := range clients {
		c.send(message{kind: 16, payload: p})
	}
}
func bindReply(code int32) []byte {
	p := make([]byte, 65878)
	le.PutUint32(p, uint32(code))
	p[4] = 1
	copy(p[5:], deviceDescriptor)
	copy(p[23:], configurationDescriptor)
	fixed(p[65558:65686], "virtbw Virtual FIDO")
	fixed(p[65686:65814], "virtbw")
	fixed(p[65814:], serverIdentity)
	return p
}
func (s *Server) bind(c *connection) int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == c {
		return -9
	}
	if s.owner != nil {
		return -2
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configuration = 0
	c.idle = 0
	c.pending = nil
	c.responses = nil
	c.reportsOut = make(chan []byte, 64)
	reportsOut := c.reportsOut
	c.bindingDone = make(chan struct{})
	done := c.bindingDone
	c.boundAt = time.Now()
	s.owner = c
	device := s.factory()
	device.SetResponseHandler(func(report []byte) { c.respond(done, report) })
	go func() {
		defer func() {
			if recover() != nil {
				c.close()
			}
		}()
		for {
			select {
			case <-done:
				return
			case <-c.done:
				return
			case report := <-reportsOut:
				// CTAPHID is not safe for concurrent use. Keep reports ordered.
				s.reportMu.Lock()
				func() {
					defer s.reportMu.Unlock()
					select {
					case <-done:
						return
					default:
						device.HandleMessage(report)
					}
				}()
			}
		}
	}()
	return 1
}
func (s *Server) release(c *connection) bool {
	s.mu.Lock()
	if s.owner != c {
		s.mu.Unlock()
		return false
	}
	c.mu.Lock()
	close(c.bindingDone)
	c.bindingDone = nil
	c.pending = nil
	c.responses = nil
	c.configuration = 0
	c.mu.Unlock()
	s.owner = nil
	s.mu.Unlock()
	s.broadcast()
	return true
}
func (c *connection) respond(binding <-chan struct{}, report []byte) {
	if len(report) != reportSize {
		return
	}
	c.mu.Lock()
	select {
	case <-binding:
		c.mu.Unlock()
		return
	default:
	}
	if len(c.pending) == 0 {
		if len(c.responses) < 256 {
			c.responses = append(c.responses, append([]byte(nil), report...))
		} else {
			c.close()
		}
		c.mu.Unlock()
		return
	}
	m := c.pending[0]
	c.pending = c.pending[1:]
	c.mu.Unlock()
	c.transferReply(m, report, 0)
}
func (c *connection) transferReply(m message, data []byte, status int32) error {
	length := int(le.Uint32(m.payload[9:13]))
	in := m.payload[0]&128 != 0
	p := make([]byte, 4)
	if in {
		p = make([]byte, 4+length)
	}
	actual := length
	if in {
		actual = len(data)
		if actual > length {
			actual = length
		}
		copy(p[4:], data[:actual])
	}
	if status < 0 {
		le.PutUint32(p, uint32(status))
	} else {
		le.PutUint32(p, uint32(actual))
	}
	return c.reply(m, 19, p)
}
func (c *connection) abort(endpoint uint32) {
	c.mu.Lock()
	var aborted []message
	remaining := c.pending[:0]
	for _, m := range c.pending {
		if le.Uint32(m.payload[:4]) == endpoint {
			aborted = append(aborted, m)
		} else {
			remaining = append(remaining, m)
		}
	}
	c.pending = remaining
	c.mu.Unlock()
	for _, m := range aborted {
		c.transferReply(m, nil, -2)
	}
}
func (c *connection) handleControl(m message) error {
	offset := 0
	if m.kind == 13 {
		offset = 8
	}
	if len(m.payload) < offset+8 {
		return errors.New("short control request")
	}
	setup := m.payload[offset : offset+8]
	length := int(le.Uint16(setup[6:8]))
	in := setup[0]&128 != 0
	expected := offset + 8
	if !in {
		expected += length
	}
	if len(m.payload) != expected {
		return errors.New("control length mismatch")
	}
	data, status := []byte(nil), int32(-19)
	if m.address == deviceAddress && c.isOwner() {
		data, status = c.control(setup, m.payload[offset+8:])
	}
	actual := length
	if in {
		actual = len(data)
		if actual > length {
			actual = length
		}
	}
	if status < 0 {
		actual = 0
	} else if m.kind == 13 && in && actual < length && le.Uint32(m.payload[4:8])&2 != 0 {
		status = -121
	}
	if m.kind == 59 {
		p := make([]byte, 4)
		if in {
			p = make([]byte, 4+length)
			copy(p[4:], data[:actual])
		}
		value := int32(actual)
		if status < 0 {
			value = -1
			if status == -19 {
				value = -19
			}
		}
		le.PutUint32(p, uint32(value))
		return c.reply(m, 60, p)
	}
	p := make([]byte, 16)
	if in {
		p = make([]byte, 16+length)
		copy(p[16:], data[:actual])
	}
	copy(p, setup)
	le.PutUint32(p[8:12], uint32(status))
	le.PutUint32(p[12:16], uint32(actual))
	return c.reply(m, 14, p)
}
func (c *connection) handleTransfer(m message) error {
	if len(m.payload) < 13 {
		return errors.New("short transfer request")
	}
	endpoint, kind, length := le.Uint32(m.payload[:4]), le.Uint32(m.payload[5:9]), le.Uint32(m.payload[9:13])
	if length > 65536 {
		return errors.New("HID transfer too large")
	}
	in := endpoint&128 != 0
	expected := 13
	if !in {
		expected += int(length)
	}
	if len(m.payload) != expected {
		return errors.New("transfer length mismatch")
	}
	if m.address != deviceAddress || !c.isOwner() {
		return c.transferReply(m, nil, -19)
	}
	if m.kind != 18 || kind != 1 || (endpoint != 0x81 && endpoint != 2) {
		return c.transferReply(m, nil, -22)
	}
	if length == 0 {
		return c.transferReply(m, nil, 0)
	}
	c.mu.Lock()
	if c.configuration != 1 {
		c.mu.Unlock()
		return c.transferReply(m, nil, -32)
	}
	if in {
		if len(c.responses) > 0 {
			report := c.responses[0]
			c.responses = c.responses[1:]
			c.mu.Unlock()
			return c.transferReply(m, report, 0)
		}
		if len(c.pending) >= 256 {
			c.mu.Unlock()
			return c.transferReply(m, nil, -12)
		}
		c.pending = append(c.pending, m)
		c.mu.Unlock()
		return nil
	}
	if length != reportSize {
		c.mu.Unlock()
		return c.transferReply(m, nil, -22)
	}
	select {
	case c.reportsOut <- append([]byte(nil), m.payload[13:]...):
		c.mu.Unlock()
		return c.transferReply(m, nil, 0)
	default:
		c.mu.Unlock()
		return c.transferReply(m, nil, -12)
	}
}
func (c *connection) handle(m message) error {
	switch m.kind {
	case 0:
		if c.hello || len(m.payload) != 132 {
			return errors.New("invalid hello")
		}
		c.server.mu.Lock()
		c.identity = cstring(m.payload[:64])
		c.hostname = cstring(m.payload[64:128])
		c.hello = true
		c.server.mu.Unlock()
		p := make([]byte, 724)
		p[0] = 8
		fixed(p[1:129], serverName)
		fixed(p[129:166], serverIdentity)
		le.PutUint16(p[166:168], 1)
		copy(p[168:184], c.uuid[:])
		copy(p[184:187], []byte{4, 8, 8})
		fixed(p[188:444], "localhost")
		fixed(p[444:700], "lo")
		p[723] = 1
		if err := c.reply(m, 1, p); err != nil {
			return err
		}
		if err := c.send(message{kind: 24, payload: append([]byte("virtbw experimental VirtualHere transport"), 0)}); err != nil {
			return err
		}
		go c.heartbeats()
		return nil
	case 9:
		return c.reply(m, 16, c.server.inventory())
	case 10:
		return c.reply(m, 11, nil)
	case 15:
		if len(m.payload) != 4 {
			return errors.New("invalid heartbeat")
		}
		return nil
	case 25:
		if len(m.payload) != 0 {
			return errors.New("invalid bind")
		}
		code := int32(-1)
		if m.address == deviceAddress {
			code = c.server.bind(c)
		}
		if err := c.send(message{kind: 39, address: m.address, payload: bindReply(code)}); err != nil {
			return err
		}
		if code == 1 {
			c.server.broadcast()
		}
		return nil
	case 35:
		if m.address == deviceAddress && c.isOwner() {
			c.server.release(c)
			return c.send(message{kind: 7, address: m.address, payload: result(1)})
		}
		return nil
	case 13, 59:
		return c.handleControl(m)
	case 18, 74:
		return c.handleTransfer(m)
	case 20:
		p := make([]byte, 6)
		if c.isOwner() && m.address == deviceAddress {
			le.PutUint32(p, 4)
			le.PutUint16(p[4:], 0x0103)
		} else {
			copy(p, result(-19))
		}
		return c.reply(m, 21, p)
	case 22, 51:
		if !c.isOwner() || m.address != deviceAddress {
			return c.reply(m, 23, result(-19))
		}
		c.abort(0x81)
		c.mu.Lock()
		c.configuration = 0
		c.responses = nil
		c.mu.Unlock()
		return c.reply(m, 23, result(0))
	case 26, 28, 30, 50:
		if len(m.payload) != 4 {
			return errors.New("invalid endpoint operation")
		}
		response := map[byte]byte{26: 27, 28: 29, 30: 31, 50: 32}[m.kind]
		if !c.isOwner() || m.address != deviceAddress {
			return c.reply(m, response, result(-19))
		}
		ep := le.Uint32(m.payload)
		if ep != 0x81 && ep != 2 {
			return c.reply(m, response, result(-22))
		}
		if m.kind == 30 || m.kind == 50 {
			c.abort(ep)
		}
		return c.reply(m, response, result(0))
	case 81:
		p := make([]byte, 8)
		if c.isOwner() {
			le.PutUint64(p, uint64(time.Since(c.boundAt)/time.Second))
		}
		return c.reply(m, 82, p)
	case 85:
		return c.reply(m, 86, result(0))
	case 89:
		return c.reply(m, 90, result(0))
	default:
		return c.send(message{kind: 24, payload: append([]byte(fmt.Sprintf("virtbw: unsupported request %d", m.kind)), 0)})
	}
}
func cstring(p []byte) string {
	for i, b := range p {
		if b == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}
