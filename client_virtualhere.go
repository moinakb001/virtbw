package virtual_fido

import (
	"context"
	"fmt"
	"net"

	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/u2f"
	"github.com/moinakb001/virtbw/virtualhere"
)

// ServeVirtualHere exports the software FIDO key to a locally installed
// VirtualHere client. It does not create a native HID device or invoke usbip.
// The transport is experimental and deliberately restricted to loopback.
func ServeVirtualHere(ctx context.Context, address string, client FIDOClient) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("VirtualHere listen address must be a loopback IP, got %q", host)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := virtualhere.NewServer(func() virtualhere.ReportDevice {
		return ctap_hid.NewCTAPHIDServer(ctap.NewCTAPServer(client), u2f.NewU2FServer(client))
	})
	return server.Serve(ctx, listener)
}
