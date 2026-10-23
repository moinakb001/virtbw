//go:build darwin && driverkit

package virtual_fido

import (
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/mac"
	"github.com/moinakb001/virtbw/u2f"
)

/*
 * DriverKit client (build with -tags driverkit). Requires installation of the Mac USBDriver,
 * which implements a virtual USB device.
 */
func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	mac.Start(ctapHIDServer)
}
