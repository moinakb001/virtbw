package bitwarden

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/fido_client"
)

type lockingVault struct {
	fakeVault
	err error
}

func (v *lockingVault) ListItems() ([]*Item, error) {
	if v.err != nil {
		v.listCalls++
		return nil, v.err
	}
	return v.fakeVault.ListItems()
}

type forbiddenPrompt struct{ t *testing.T }

func (p forbiddenPrompt) ApproveClientAction(fido_client.ClientAction, fido_client.ClientActionRequestParams) bool {
	p.t.Error("trusted-vault mode prompted for approval")
	return false
}

func (p forbiddenPrompt) ChooseCredential(string, []string) (int, bool) {
	p.t.Error("trusted-vault mode prompted for account selection")
	return 0, false
}

func assertionMessage(t *testing.T, hash []byte, options map[string]bool) []byte {
	t.Helper()
	args, err := cbor.Marshal(map[int]interface{}{1: "example.test", 2: hash, 5: options})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{2}, args...)
}

func TestTrustedVaultVerificationAndLock(t *testing.T) {
	older, _ := newTestPasskey(t, "b64.AQID", "example.test", "older", true, "2024-01-01")
	newer, key := newTestPasskey(t, "b64.BAUG", "example.test", "newer", true, "2024-02-01")
	vault := &lockingVault{fakeVault: fakeVault{items: []*Item{loginItem("test", older, newer)}}}
	client := NewClient(vault, forbiddenPrompt{t}, Options{CacheTTL: time.Hour, TrustUnlockedVault: true})
	server := ctap.NewCTAPServer(client)
	hash := crypto.HashSHA256([]byte("synthetic trusted-vault test"))
	request := assertionMessage(t, hash, map[string]bool{"uv": true})
	response := server.HandleMessage(request)
	if len(response) < 2 || response[0] != 0 {
		t.Fatalf("unlocked vault: %x", response)
	}
	var assertion assertionResponse
	if err := cbor.Unmarshal(response[1:], &assertion); err != nil {
		t.Fatal(err)
	}
	if assertion.AuthData[32] != 5 || !bytes.Equal(assertion.Credential.ID, []byte{4, 5, 6}) || assertion.User == nil {
		t.Fatal("expected UP+UV, newest credential and discoverable user")
	}
	verifyAssertion(t, &assertion, key, "example.test", hash)
	if !client.ApproveAuthenticatorSelection() {
		t.Fatal("unlocked vault must allow prompt-free selection")
	}

	for _, failure := range []error{errors.New("vault is locked"), errors.New("connection refused")} {
		vault.err = failure
		before := vault.listCalls
		response = server.HandleMessage(request)
		if !bytes.Equal(response, []byte{0x27}) || vault.listCalls <= before {
			t.Fatalf("must reject using a fresh read, despite the warm cache: %x", response)
		}
		if client.ApproveAuthenticatorSelection() {
			t.Fatal("locked vault must not approve selection")
		}
		// A platform omitting UV must not bypass the vault's lock either.
		response = server.HandleMessage(assertionMessage(t, hash, nil))
		if len(response) != 1 || response[0] == 0 {
			t.Fatal("request without UV signed using cached keys after lock")
		}
		if client.items != nil || !client.itemsFetched.IsZero() {
			t.Fatal("failed live read retained the vault cache")
		}
	}
	vault.err = nil
	if response = server.HandleMessage(request); len(response) < 2 || response[0] != 0 {
		t.Fatalf("unlock should restore access: %x", response)
	}
	// Real credential creation remains disabled even with this mode enabled.
	if client.ApproveAccountCreation("example.test") {
		t.Fatal("trusted-vault mode allowed registration")
	}
}

func TestVerificationIsExplicitAndDoesNotAcceptPINProof(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		vault := &fakeVault{}
		client := NewClient(vault, forbiddenPrompt{t}, Options{TrustUnlockedVault: trusted})
		server := ctap.NewCTAPServer(client)
		info := server.HandleMessage([]byte{4})
		var response struct {
			Options map[string]bool `cbor:"4,keyasint"`
		}
		if info[0] != 0 || cbor.Unmarshal(info[1:], &response) != nil {
			t.Fatal("invalid GetInfo")
		}
		uv, hasUV := response.Options["uv"]
		if hasUV != trusted || uv != trusted {
			t.Fatal("UV must be advertised only with explicit trust policy")
		}
		if _, ok := response.Options["clientPin"]; ok {
			t.Fatal("mode must not advertise client PIN")
		}
		if !trusted {
			got := server.HandleMessage(assertionMessage(t, make([]byte, 32), map[string]bool{"uv": true}))
			if !bytes.Equal(got, []byte{0x2b}) || vault.listCalls != 0 {
				t.Fatalf("unconfigured UV must fail before vault access: %x", got)
			}
		}
		encoded, err := cbor.Marshal(map[int]interface{}{
			1: "example.test", 2: make([]byte, 32), 6: make([]byte, 16), 7: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := server.HandleMessage(append([]byte{2}, encoded...))
		if !bytes.Equal(got, []byte{0x33}) || vault.listCalls != 0 {
			t.Fatalf("unsupported PIN proof must not authorize UV: %x", got)
		}
	}
}

func TestTrustedVaultDoesNotReuseOldCredentialOrUV(t *testing.T) {
	cred, _ := newTestPasskey(t, "b64.AQID", "example.test", "alice", true, "2024-01-01")
	vault := &fakeVault{items: []*Item{loginItem("test", cred)}}
	server := ctap.NewCTAPServer(NewClient(vault, forbiddenPrompt{t}, Options{CacheTTL: time.Hour, TrustUnlockedVault: true}))
	for _, options := range []map[string]bool{{"uv": true}, {"uv": false}, {"uv": false, "up": false}} {
		response := server.HandleMessage(assertionMessage(t, make([]byte, 32), options))
		var assertion assertionResponse
		if response[0] != 0 || cbor.Unmarshal(response[1:], &assertion) != nil {
			t.Fatal("assertion failed")
		}
		if (assertion.AuthData[32]&4 != 0) != options["uv"] {
			t.Fatal("UV flag was reused from an earlier request")
		}
		if up, specified := options["up"]; specified && !up && assertion.AuthData[32]&1 != 0 {
			t.Fatal("silent request reported presence")
		}
	}
	vault.items = nil // removed from the live vault after a successful login
	response := server.HandleMessage(assertionMessage(t, make([]byte, 32), map[string]bool{"uv": true}))
	if !bytes.Equal(response, []byte{0x2e}) {
		t.Fatalf("removed credential used from cache: %x", response)
	}
}
