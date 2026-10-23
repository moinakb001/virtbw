package ctap

import (
	"bytes"
	"testing"
	"time"
)

func TestAssertionContinuationExpires(t *testing.T) {
	server := NewCTAPServer(&dummyCTAPClient{})
	server.assertions = &assertionContinuation{
		remainingIDs: [][]byte{{1}},
		lastUsed:     time.Now().Add(-31 * time.Second),
	}
	if got := server.HandleMessage([]byte{8}); !bytes.Equal(got, []byte{0x30}) || server.assertions != nil {
		t.Fatalf("expired sequence survived: %x", got)
	}
}
