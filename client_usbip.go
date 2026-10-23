//go:build linux || windows

package virtual_fido

import (
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/u2f"
	"github.com/moinakb001/virtbw/usb"
	"github.com/moinakb001/virtbw/usbip"
)

func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	usbDevice := usb.NewUSBDevice(ctapHIDServer)
	server := usbip.NewUSBIPServer([]usbip.USBIPDevice{usbDevice})
	server.Start()
}
