package bitwarden

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/ctap"
)

type localTestChooser struct {
	forbiddenPrompt
	choose func(string, []string) (int, bool)
}

func (c localTestChooser) ChooseCredential(rp string, labels []string) (int, bool) {
	return c.choose(rp, labels)
}

func TestTrustedVaultLocalSelection(t *testing.T) {
	for _, outcome := range []string{"choose-older", "cancel", "invalid", "lock", "remove"} {
		t.Run(outcome, func(t *testing.T) {
			older, key := newTestPasskey(t, "b64.AQID", "example.test", "same-account", true, "2024-01-01")
			newer, _ := newTestPasskey(t, "b64.BAUG", "example.test", "same-account", true, "2024-02-01")
			vault := &lockingVault{fakeVault: fakeVault{items: []*Item{loginItem("older item", older), loginItem("newer item", newer)}}}
			calls := 0
			chooser := localTestChooser{forbiddenPrompt{t}, func(rp string, labels []string) (int, bool) {
				calls++
				if rp != "example.test" || len(labels) != 2 ||
					!strings.Contains(labels[0], "newer item") || !strings.Contains(labels[0], "2024-02-01") ||
					!strings.Contains(labels[1], "older item") || !strings.Contains(labels[1], "key 010203") {
					t.Fatalf("same-account keys aren't distinguishable: %q", labels)
				}
				switch outcome {
				case "cancel":
					return 0, false
				case "invalid":
					return len(labels), true
				case "lock":
					vault.err = errors.New("locked while choosing")
				case "remove":
					vault.items = []*Item{loginItem("newer item", newer)}
				}
				return 1, true
			}}
			client := NewClient(vault, chooser, Options{CacheTTL: time.Hour, TrustUnlockedVault: true, SelectCredentialLocally: true})
			if client.SupportsMultipleAssertions() {
				t.Fatal("local selection must not enumerate to the browser")
			}
			server := ctap.NewCTAPServer(client)
			hash := crypto.HashSHA256([]byte("terminal-selected assertion"))
			wire := server.HandleMessage(assertionMessage(t, hash, map[string]bool{"uv": true}))
			if calls != 1 {
				t.Fatalf("wanted one selection, got %d", calls)
			}
			if outcome == "choose-older" {
				response := decodeAssertion(t, wire)
				if !bytes.Equal(response.Credential.ID, []byte{1, 2, 3}) || response.NumberOfCredentials != nil || response.AuthData[32] != 5 {
					t.Fatal("did not return only the selected key with UV")
				}
				verifyAssertion(t, response, key, "example.test", hash)
			} else if !bytes.Equal(wire, []byte{0x27}) {
				t.Fatalf("selection should fail closed: %x", wire)
			}
			if got := server.HandleMessage([]byte{8}); !bytes.Equal(got, []byte{0x30}) {
				t.Fatalf("unselected keys leaked via continuation: %x", got)
			}
		})
	}
}

func TestTrustedVaultLocalSelectionSingleMatchIsAutomatic(t *testing.T) {
	cred, key := newTestPasskey(t, "b64.AQID", "example.test", "alice", true, "2024-01-01")
	client := NewClient(&fakeVault{items: []*Item{loginItem("one", cred)}}, forbiddenPrompt{t}, Options{TrustUnlockedVault: true, SelectCredentialLocally: true})
	hash := crypto.HashSHA256([]byte("single key"))
	response := decodeAssertion(t, ctap.NewCTAPServer(client).HandleMessage(assertionMessage(t, hash, map[string]bool{"uv": true})))
	verifyAssertion(t, response, key, "example.test", hash)
}
