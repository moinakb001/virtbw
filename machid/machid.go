//go:build darwin && !driverkit

// Package machid exposes the CTAPHID server as a virtual HID security key on macOS using
// IOHIDUserDevice, so that any app on the Mac (not only browsers) can use it.
//
// Creating the device requires the com.apple.developer.hid.virtual.device entitlement;
// see scripts/macos-bundle.sh for building a signed app bundle.
package machid

// #cgo LDFLAGS: -framework IOKit -framework CoreFoundation
// #include "machid.h"
import "C"

import (
	"errors"
	"unsafe"

	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/util"
)

var machidLogger = util.NewLogger("[MACHID] ", util.LogLevelTrace)

// FIDO HID report descriptor: usage page 0xF1D0, 64 byte input and output reports.
var reportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (CTAPHID)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, // End Collection
}

const reportSize = 64

// Reports are handed from the IOKit dispatch queue to a single goroutine, because the
// CTAPHID server is not safe for concurrent use and may block while waiting for approval.
var reports = make(chan []byte, 64)

//export machidReceiveReport
func machidReceiveReport(data unsafe.Pointer, length C.int) {
	report := C.GoBytes(data, length)
	if len(report) == reportSize+1 && report[0] == 0 {
		report = report[1:]
	}
	reports <- report
}

func sendReport(report []byte) {
	if len(report) == 0 {
		return
	}
	if ret := C.machid_send((*C.uint8_t)(unsafe.Pointer(&report[0])), C.int(len(report))); ret != 0 {
		machidLogger.Printf("Could not send report: IOReturn 0x%x\n\n", uint32(ret))
	}
}

// Start creates the virtual security key and serves it until the process exits.
func Start(server *ctap_hid.CTAPHIDServer) error {
	server.SetResponseHandler(sendReport)
	if C.machid_start((*C.uint8_t)(unsafe.Pointer(&reportDescriptor[0])), C.int(len(reportDescriptor))) != 0 {
		return errors.New("could not create virtual HID device: the executable must be signed with the " +
			"com.apple.developer.hid.virtual.device entitlement (see scripts/macos-bundle.sh)")
	}
	for report := range reports {
		server.HandleMessage(report)
	}
	return nil
}
