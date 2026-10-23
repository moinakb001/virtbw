package bitwarden

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/ctap"
)

func decodeAssertion(t *testing.T, data []byte) *assertionResponse {
	t.Helper()
	var result assertionResponse
	if len(data) < 2 || data[0] != 0 {
		t.Fatalf("assertion failed: %x", data)
	}
	if err := cbor.Unmarshal(data[1:], &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

func TestBrowserAccountEnumeration(t *testing.T) {
	oldest, oldestKey := newTestPasskey(t, "b64.AQID", "example.test", "alice", true, "2024-01-01")
	middle, middleKey := newTestPasskey(t, "b64.BAUG", "example.test", "bob", true, "2024-02-01")
	newest, newestKey := newTestPasskey(t, "b64.BwgJ", "example.test", "carol", true, "2024-03-01")
	otherRP, _ := newTestPasskey(t, "b64.CgsM", "other.test", "hidden", true, "2025-01-01")
	notDiscoverable, _ := newTestPasskey(t, "b64.DQ4P", "example.test", "hidden", false, "2025-01-01")
	vault := &fakeVault{items: []*Item{loginItem("test", oldest, middle, newest, otherRP, notDiscoverable), loginItem("duplicate", middle)}}
	server := ctap.NewCTAPServer(NewClient(vault, forbiddenPrompt{t}, Options{CacheTTL: time.Hour, TrustUnlockedVault: true}))
	hash := crypto.HashSHA256([]byte("multi-account test challenge"))
	request := assertionMessage(t, hash, map[string]bool{"uv": true})
	first := server.HandleMessageForChannel(17, request)
	// The remembered challenge must not alias the caller's request buffer.
	for i := range request {
		request[i] = 0
	}
	for i, expected := range []struct {
		name string
		id   []byte
		key  *ecdsa.PrivateKey
	}{{"carol", []byte{7, 8, 9}, newestKey}, {"bob", []byte{4, 5, 6}, middleKey}, {"alice", []byte{1, 2, 3}, oldestKey}} {
		wire := first
		if i > 0 {
			wire = server.HandleMessageForChannel(17, []byte{8})
		}
		response := decodeAssertion(t, wire)
		if !bytes.Equal(response.Credential.ID, expected.id) || response.User == nil ||
			response.User.Name != expected.name || response.User.DisplayName != expected.name ||
			string(response.User.ID) != "handle-"+expected.name || response.AuthData[32] != 5 {
			t.Fatalf("wrong account/flags at index %d", i)
		}
		if i == 0 {
			if response.NumberOfCredentials == nil || *response.NumberOfCredentials != 3 {
				t.Fatal("first response must report three unique discoverable credentials")
			}
		} else if response.NumberOfCredentials != nil {
			t.Fatal("continuation must omit numberOfCredentials")
		}
		verifyAssertion(t, response, expected.key, "example.test", hash)
	}
	if got := server.HandleMessageForChannel(17, []byte{8}); !bytes.Equal(got, []byte{0x30}) {
		t.Fatalf("exhausted enumeration: %x", got)
	}
}

func TestAssertionContinuationInvalidation(t *testing.T) {
	for _, change := range []string{"lock", "remove", "other-command", "failed-request", "other-channel", "new-connection", "malformed-next"} {
		t.Run(change, func(t *testing.T) {
			older, _ := newTestPasskey(t, "b64.AQID", "example.test", "alice", true, "2024-01-01")
			newer, _ := newTestPasskey(t, "b64.BAUG", "example.test", "bob", true, "2024-02-01")
			vault := &lockingVault{fakeVault: fakeVault{items: []*Item{loginItem("test", older, newer)}}}
			client := NewClient(vault, forbiddenPrompt{t}, Options{CacheTTL: time.Hour, TrustUnlockedVault: true})
			server := ctap.NewCTAPServer(client)
			first := decodeAssertion(t, server.HandleMessageForChannel(17, assertionMessage(t, make([]byte, 32), map[string]bool{"uv": true})))
			if first.NumberOfCredentials == nil || *first.NumberOfCredentials != 2 {
				t.Fatal("missing count")
			}
			switch change {
			case "lock":
				vault.err = errors.New("vault locked")
			case "remove":
				vault.items = []*Item{loginItem("test", newer)}
			case "other-command":
				server.HandleMessageForChannel(17, []byte{4})
			case "failed-request":
				server.HandleMessageForChannel(17, []byte{2, 0xff})
			case "other-channel":
				if got := server.HandleMessageForChannel(18, []byte{8}); !bytes.Equal(got, []byte{0x30}) {
					t.Fatalf("other channel: %x", got)
				}
			case "new-connection":
				server = ctap.NewCTAPServer(client)
			case "malformed-next":
				if got := server.HandleMessageForChannel(17, []byte{8, 0xa0}); !bytes.Equal(got, []byte{3}) {
					t.Fatalf("unexpected args: %x", got)
				}
			}
			got := server.HandleMessageForChannel(17, []byte{8})
			if len(got) != 1 || got[0] == 0 {
				t.Fatalf("stale continuation signed: %x", got)
			}
			vault.err = nil
			if got = server.HandleMessageForChannel(17, []byte{8}); !bytes.Equal(got, []byte{0x30}) {
				t.Fatalf("failed sequence survived: %x", got)
			}
		})
	}
}

func TestEnumerationRequiresDiscoverableVerifiedRequest(t *testing.T) {
	for _, mode := range []string{"allow-list", "no-uv", "silent"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := newTestPasskey(t, "b64.AQID", "example.test", "alice", true, "2024-01-01")
			b, _ := newTestPasskey(t, "b64.BAUG", "example.test", "bob", true, "2024-02-01")
			client := NewClient(&fakeVault{items: []*Item{loginItem("test", a, b)}}, forbiddenPrompt{t}, Options{TrustUnlockedVault: true})
			server := ctap.NewCTAPServer(client)
			options := map[string]bool{"uv": true}
			args := map[int]interface{}{1: "example.test", 2: make([]byte, 32), 5: options}
			switch mode {
			case "allow-list":
				args[3] = []map[string]interface{}{{"type": "public-key", "id": []byte{1, 2, 3}}, {"type": "public-key", "id": []byte{4, 5, 6}}}
			case "no-uv":
				options["uv"] = false
			case "silent":
				options["up"] = false
			}
			encoded, err := cbor.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			response := decodeAssertion(t, server.HandleMessage(append([]byte{2}, encoded...)))
			if response.NumberOfCredentials != nil {
				t.Fatal("non-discovery request enumerated accounts")
			}
			if mode == "no-uv" && (response.User.Name != "" || response.User.DisplayName != "") {
				t.Fatal("unverified request returned names")
			}
			if got := server.HandleMessage([]byte{8}); !bytes.Equal(got, []byte{0x30}) {
				t.Fatalf("unexpected continuation: %x", got)
			}
		})
	}
}
