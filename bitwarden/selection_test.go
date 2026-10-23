package bitwarden

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/fido_client"
)

// Captured from the browser's CTAP 2.0 GetTouchRequest, not a real registration.
const chromiumTouchHex = "01a4015820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85502a1626964662e64756d6d7903a26269644101646e616d656564756d6d790481a263616c672664747970656a7075626c69632d6b6579"

type selectionApprover struct {
	allow   bool
	actions []fido_client.ClientAction
}

func (a *selectionApprover) ApproveClientAction(action fido_client.ClientAction, _ fido_client.ClientActionRequestParams) bool {
	a.actions = append(a.actions, action)
	return a.allow
}

func TestChromiumSelectionProbe(t *testing.T) {
	request, err := hex.DecodeString(chromiumTouchHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		vault := &fakeVault{}
		approver := &selectionApprover{allow: allow}
		client := NewClient(vault, approver, Options{})
		server := ctap.NewCTAPServer(client)
		response := server.HandleMessage(request)
		if len(approver.actions) != 1 || approver.actions[0] != fido_client.ClientActionFIDOSelect {
			t.Fatal("selection must request its own approval")
		}
		if vault.listCalls != 0 || len(vault.items) != 0 {
			t.Fatal("selection accessed vault")
		}
		if !allow {
			if !bytes.Equal(response, []byte{0x27}) {
				t.Fatalf("denied selection: %x", response)
			}
			continue
		}
		var result struct {
			Format    string                 `cbor:"1,keyasint"`
			Data      []byte                 `cbor:"2,keyasint"`
			Statement map[string]interface{} `cbor:"3,keyasint"`
		}
		if response[0] != 0 || cbor.Unmarshal(response[1:], &result) != nil || result.Format != "none" || len(result.Statement) != 0 {
			t.Fatalf("invalid selection attestation: %x", response)
		}
		hash := sha256.Sum256([]byte(".dummy"))
		if len(result.Data) < 87 || !bytes.Equal(result.Data[:32], hash[:]) || result.Data[32] != 0x41 || binary.BigEndian.Uint32(result.Data[33:37]) != 0 || binary.BigEndian.Uint16(result.Data[53:55]) != 32 {
			t.Fatal("invalid authenticator data or unexpected UV flag")
		}
		if !bytes.Equal(result.Data[37:53], make([]byte, 16)) {
			t.Fatal("none attestation should have an anonymous AAGUID")
		}
		var publicKey map[int]cbor.RawMessage
		if cbor.Unmarshal(result.Data[87:], &publicKey) != nil {
			t.Fatal("bad COSE key")
		}
		var x, y []byte
		var algorithm, curve int
		cbor.Unmarshal(publicKey[-2], &x)
		cbor.Unmarshal(publicKey[-3], &y)
		cbor.Unmarshal(publicKey[3], &algorithm)
		cbor.Unmarshal(publicKey[-1], &curve)
		if algorithm != -7 || curve != 1 || len(x) != 32 || len(y) != 32 || !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
			t.Fatal("selection key is not ES256/P-256")
		}
		if source := client.GetAssertionSource(".dummy", nil); source != nil {
			t.Fatal("dummy credential persisted")
		}
	}
}

func TestSelectionProbeCannotAuthorizeRegistration(t *testing.T) {
	request, _ := hex.DecodeString(chromiumTouchHex)
	for _, tc := range []struct {
		name  string
		key   int
		value interface{}
	}{
		{"real-rp", 2, map[string]interface{}{"id": "example.test"}},
		{"other-hash", 1, make([]byte, 32)},
		{"other-user", 3, map[string]interface{}{"id": []byte{2}, "name": "dummy"}},
		{"resident", 7, map[string]interface{}{"rk": true}},
		{"verification", 7, map[string]interface{}{"uv": true}},
		{"silent", 7, map[string]interface{}{"up": false}},
		{"pin", 8, []byte{}},
		{"extensions", 6, map[string]interface{}{"hmac-secret": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var args map[int]cbor.RawMessage
			if err := cbor.Unmarshal(request[1:], &args); err != nil {
				t.Fatal(err)
			}
			value, err := cbor.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			args[tc.key] = value
			encoded, err := cbor.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			approver := &selectionApprover{allow: true}
			server := ctap.NewCTAPServer(NewClient(&fakeVault{}, approver, Options{}))
			response := server.HandleMessage(append([]byte{1}, encoded...))
			if response[0] == 0 || len(approver.actions) != 0 {
				t.Fatal("ordinary registration was treated as selection")
			}
		})
	}
}
