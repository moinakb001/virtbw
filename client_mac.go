//go:build darwin && !driverkit

package virtual_fido

import (
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/machid"
	"github.com/moinakb001/virtbw/u2f"
	"github.com/moinakb001/virtbw/util"
)

// Creates a virtual HID security key with IOHIDUserDevice. The executable must be signed
// with the com.apple.developer.hid.virtual.device entitlement.
func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	util.CheckErr(machid.Start(ctapHIDServer), "Could not start virtual security key")
}
