package virtual_fido

import (
	"io"

	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/u2f"
	"github.com/moinakb001/virtbw/util"
)

type FIDOClient interface {
	u2f.U2FClient
	ctap.CTAPClient
}

func Start(client FIDOClient) {
	// Calls either the Mac or USB/IP client, based on system
	startClient(client)
}

func SetLogLevel(level util.LogLevel) {
	util.SetLogLevel(level)
}

func SetLogOutput(out io.Writer) {
	util.SetLogOutput(out)
}
