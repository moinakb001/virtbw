package virtualhere

import "unicode/utf16"

const deviceAddress uint32 = 22
const reportSize = 64

// ReportDevice is implemented by ctap_hid. A fresh instance is required for
// each ownership session so delayed responses cannot reach a different owner.
type ReportDevice interface {
	HandleMessage([]byte)
	SetResponseHandler(func([]byte))
}

// These IDs follow virtbw's existing virtual HID profile. They are not an
// allocated physical-device VID/PID and are not used for authentication.
var deviceDescriptor = []byte{18, 1, 0x10, 1, 0, 0, 0, 64, 0, 0, 0, 0, 1, 0, 1, 2, 3, 1}
var reportDescriptor = []byte{
	0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01,
	0x09, 0x20, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 64, 0x81, 2,
	0x09, 0x21, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 64, 0x91, 2, 0xc0,
}
var hidDescriptor = []byte{9, 33, 0x11, 1, 0, 1, 34, byte(len(reportDescriptor)), 0}
var configurationDescriptor = func() []byte {
	p := []byte{9, 2, 41, 0, 1, 1, 0, 0xc0, 0, 9, 4, 0, 0, 2, 3, 0, 0, 0}
	p = append(p, hidDescriptor...)
	return append(p, 7, 5, 0x81, 3, 64, 0, 5, 7, 5, 2, 3, 64, 0, 5)
}()

func stringDescriptor(index byte) []byte {
	if index == 0 {
		return []byte{4, 3, 9, 4}
	}
	names := []string{"", "virtbw", "virtbw Virtual FIDO", "virtbw"}
	if int(index) >= len(names) {
		return nil
	}
	words := utf16.Encode([]rune(names[index]))
	p := make([]byte, 2+len(words)*2)
	p[0] = byte(len(p))
	p[1] = 3
	for i, w := range words {
		le.PutUint16(p[2+2*i:], w)
	}
	return p
}

// control implements only the standard requests and HID report transport that
// this FIDO profile supports. Unsupported requests stall instead of panicking.
func (c *connection) control(setup []byte, data []byte) ([]byte, int32) {
	bm, request := setup[0], setup[1]
	value, index := le.Uint16(setup[2:4]), le.Uint16(setup[4:6])
	var response []byte
	c.mu.Lock()
	defer c.mu.Unlock()
	if bm&0x60 == 0 {
		switch {
		case bm == 0x80 && request == 6:
			switch byte(value >> 8) {
			case 1:
				if byte(value) == 0 {
					response = deviceDescriptor
				}
			case 2:
				if byte(value) == 0 {
					response = configurationDescriptor
				}
			case 3:
				response = stringDescriptor(byte(value))
			}
			if response == nil {
				return nil, -32
			}
		case bm == 0x81 && request == 6 && index == 0:
			if value == 0x2200 {
				response = reportDescriptor
			} else if value == 0x2100 {
				response = hidDescriptor
			} else {
				return nil, -32
			}
		case request == 0 && value == 0 && (bm == 0x80 || (bm == 0x81 && index == 0) || (bm == 0x82 && (index == 0x81 || index == 2))):
			response = []byte{0, 0}
			if bm == 0x80 {
				response[0] = 1
			}
		case bm == 0 && request == 5 && value <= 127 && index == 0:
		case bm == 0x80 && request == 8 && value == 0 && index == 0:
			response = []byte{c.configuration}
		case bm == 0 && request == 9 && value <= 1 && index == 0:
			c.configuration = byte(value)
		case bm == 0x81 && request == 10 && value == 0 && index == 0:
			response = []byte{0}
		case bm == 1 && request == 11 && value == 0 && index == 0:
		case bm == 2 && request == 1 && value == 0 && (index == 0x81 || index == 2):
		default:
			return nil, -32
		}
	} else if bm&0x7f == 0x21 && index == 0 {
		switch {
		case bm == 0x21 && request == 10:
			c.idle = byte(value >> 8)
		case bm == 0xa1 && request == 2:
			response = []byte{c.idle}
		case bm == 0x21 && request == 11 && value == 1:
		case bm == 0xa1 && request == 3:
			response = []byte{1}
		case bm == 0x21 && request == 9 && value == 0x0200 && len(data) == reportSize:
			select {
			case c.reportsOut <- append([]byte(nil), data...):
			default:
				return nil, -12
			}
		default:
			return nil, -32
		}
	} else {
		return nil, -32
	}
	return response, 0
}
