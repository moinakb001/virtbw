package virtualhere

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/moinakb001/virtbw/bitwarden"
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/ctap_hid"
	"github.com/moinakb001/virtbw/fido_client"
	"github.com/moinakb001/virtbw/u2f"
)

type testVault struct{ items []*bitwarden.Item }

func (v testVault) ListItems() ([]*bitwarden.Item, error) { return v.items, nil }
func (v testVault) Sync() error                           { return nil }

type testApprover bool

func (a testApprover) ApproveClientAction(fido_client.ClientAction, fido_client.ClientActionRequestParams) bool {
	return bool(a)
}

type testKeyChooser struct{ testApprover }

func (a testKeyChooser) ChooseCredential(string, []string) (int, bool) { return 1, true }

// hid exchanges a complete CTAPHID message through actual framed TCP transfers,
// including fragmentation, interrupt-IN polling and interleaved keepalives.
func (p *testPeer) hid(cid []byte, command byte, data []byte, controlOut bool) []byte {
	p.t.Helper()
	total := len(data)
	for seq := -1; len(data) > 0; seq++ {
		report := make([]byte, 64)
		copy(report, cid)
		offset := 5
		if seq < 0 {
			report[4] = command
			binary.BigEndian.PutUint16(report[5:7], uint16(total))
			offset = 7
		} else {
			report[4] = byte(seq)
		}
		n := copy(report[offset:], data)
		data = data[n:]
		if controlOut {
			r := p.control(0x21, 9, 0x200, 0, 64, report)
			if le.Uint32(r.payload[8:12]) != 0 {
				p.t.Fatal("SET_REPORT failed")
			}
		} else {
			out := p.transfer(2, 64, report)
			if le.Uint32(p.receive(19, out.context).payload) != 64 {
				p.t.Fatal("interrupt OUT failed")
			}
		}
	}
	var result []byte
	wanted, seq := -1, 0
	for wanted < 0 || len(result) < wanted {
		in := p.transfer(0x81, 64, nil)
		r := p.receive(19, in.context)
		if le.Uint32(r.payload) != 64 {
			p.t.Fatal("interrupt IN failed")
		}
		report := r.payload[4:]
		if !bytes.Equal(report[:4], cid) {
			p.t.Fatal("wrong CTAPHID channel")
		}
		if report[4] == 0xbb { // CTAPHID_KEEPALIVE
			continue
		}
		if wanted < 0 {
			if report[4] != command {
				p.t.Fatalf("CTAPHID command %#x, want %#x", report[4], command)
			}
			wanted = int(binary.BigEndian.Uint16(report[5:7]))
			result = append(result, report[7:]...)
		} else {
			if report[4] != byte(seq) {
				p.t.Fatal("CTAPHID continuation out of order")
			}
			seq++
			result = append(result, report[5:]...)
		}
	}
	return result[:wanted]
}

func TestRealFIDOThroughVirtualHere(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		name := "terminal-approval"
		if trusted {
			name = "trusted-vault-UV"
		}
		t.Run(name, func(t *testing.T) { testRealFIDOThroughVirtualHere(t, trusted, false) })
	}
	t.Run("trusted-vault-terminal-choice", func(t *testing.T) { testRealFIDOThroughVirtualHere(t, true, true) })
}

func testRealFIDOThroughVirtualHere(t *testing.T, trusted, localChoice bool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	user, handle := "synthetic-test", base64.RawURLEncoding.EncodeToString([]byte("test-user"))
	id := []byte("virtualhere-synthetic-credential")
	cred := bitwarden.Fido2Credential{
		CredentialID: "b64." + base64.RawURLEncoding.EncodeToString(id),
		KeyType:      "public-key", KeyAlgorithm: "ECDSA", KeyCurve: "P-256",
		KeyValue: base64.RawURLEncoding.EncodeToString(der), RPID: "example.test",
		UserHandle: &handle, UserName: &user, UserDisplayName: &user,
		Counter: "0", Discoverable: "true", CreationDate: "2024-02-01",
	}
	vault := testVault{[]*bitwarden.Item{{Type: bitwarden.ItemTypeLogin, Login: &bitwarden.Login{Fido2Credentials: []bitwarden.Fido2Credential{cred}}}}}
	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondDER, err := x509.MarshalPKCS8PrivateKey(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	secondUser, secondHandle := "second-account", base64.RawURLEncoding.EncodeToString([]byte("second-user"))
	if trusted {
		second := cred
		second.CredentialID = "b64." + base64.RawURLEncoding.EncodeToString([]byte("second-credential"))
		second.KeyValue = base64.RawURLEncoding.EncodeToString(secondDER)
		second.UserName, second.UserDisplayName, second.UserHandle = &secondUser, &secondUser, &secondHandle
		second.CreationDate = "2024-01-01"
		vault.items[0].Login.Fido2Credentials = append(vault.items[0].Login.Fido2Credentials, second)
	}
	// Trusted mode only invokes the account chooser when local selection is on.
	var approver fido_client.ClientRequestApprover = testApprover(!trusted)
	if localChoice {
		approver = testKeyChooser{testApprover(false)}
	}
	client := bitwarden.NewClient(vault, approver, bitwarden.Options{TrustUnlockedVault: trusted, SelectCredentialLocally: localChoice})
	_, address := startTestServer(t, func() ReportDevice {
		return ctap_hid.NewCTAPHIDServer(ctap.NewCTAPServer(client), u2f.NewU2FServer(client))
	})
	p := connectPeer(t, address)
	if p.bind() != 1 {
		t.Fatal("bind failed")
	}
	p.control(0, 9, 1, 0, 0, nil)
	nonce := []byte("testinit")
	init := p.hid([]byte{255, 255, 255, 255}, 0x86, nonce, false)
	if len(init) != 17 || !bytes.Equal(init[:8], nonce) || init[16]&4 == 0 {
		t.Fatalf("INIT: %x", init)
	}
	cid := init[8:12]
	ping := bytes.Repeat([]byte("fragmented ping "), 20)
	if !bytes.Equal(p.hid(cid, 0x81, ping, false), ping) {
		t.Fatal("fragmented PING mismatch")
	}
	info := p.hid(cid, 0x90, []byte{4}, true)
	var decoded struct {
		Versions []string        `cbor:"1,keyasint"`
		Options  map[string]bool `cbor:"4,keyasint"`
	}
	if info[0] != 0 || cbor.Unmarshal(info[1:], &decoded) != nil || len(decoded.Versions) == 0 || decoded.Options["uv"] != trusted {
		t.Fatalf("GetInfo: %x", info)
	}
	// Browser selection precedes the actual assertion. Exercise the fragmented
	// dummy registration over the same transport and then sign with the vault.
	emptyHash := sha256.Sum256(nil)
	touchArgs, err := cbor.Marshal(map[int]interface{}{
		1: emptyHash[:], 2: map[string]interface{}{"id": ".dummy"},
		3: map[string]interface{}{"id": []byte{1}, "name": "dummy"},
		4: []map[string]interface{}{{"type": "public-key", "alg": -7}},
		7: map[string]bool{"uv": trusted},
	})
	if err != nil {
		t.Fatal(err)
	}
	touch := p.hid(cid, 0x90, append([]byte{1}, touchArgs...), true)
	var touchResult map[int]interface{}
	if touch[0] != 0 || cbor.Unmarshal(touch[1:], &touchResult) != nil || touchResult[1] != "none" {
		t.Fatalf("browser selection: %x", touch)
	}
	if data, ok := touchResult[2].([]byte); !ok || len(data) < 37 || (data[32]&4 != 0) != trusted {
		t.Fatal("selection response verification flag mismatch")
	}
	challenge := sha256.Sum256([]byte("synthetic VirtualHere assertion test"))
	// No allowList: reproduce external discoverable-passkey login with UV.
	args, err := cbor.Marshal(map[int]interface{}{1: "example.test", 2: challenge[:], 5: map[string]bool{"uv": trusted}})
	if err != nil {
		t.Fatal(err)
	}
	assertion := p.hid(cid, 0x90, append([]byte{2}, args...), false)
	var response struct {
		AuthData  []byte                 `cbor:"2,keyasint"`
		Signature []byte                 `cbor:"3,keyasint"`
		User      map[string]interface{} `cbor:"4,keyasint"`
		Count     *int                   `cbor:"5,keyasint"`
	}
	if assertion[0] != 0 || cbor.Unmarshal(assertion[1:], &response) != nil || len(response.AuthData) < 37 {
		t.Fatalf("GetAssertion: %x", assertion)
	}
	rpHash := sha256.Sum256([]byte("example.test"))
	if !bytes.Equal(response.AuthData[:32], rpHash[:]) || response.AuthData[32]&1 == 0 {
		t.Fatal("wrong RP hash or missing user presence")
	}
	if (response.AuthData[32]&4 != 0) != trusted || response.User["id"] == nil {
		t.Fatal("missing discoverable user or incorrect verification flag")
	}
	digest := sha256.Sum256(append(append([]byte(nil), response.AuthData...), challenge[:]...))
	selectedKey := key
	if localChoice {
		selectedKey = secondKey
	}
	if !ecdsa.VerifyASN1(&selectedKey.PublicKey, digest[:], response.Signature) {
		t.Fatal("assertion signature does not verify")
	}
	if localChoice {
		if response.User["name"] != secondUser || response.Count != nil {
			t.Fatal("terminal selection did not return only the chosen account")
		}
		if got := p.hid(cid, 0x90, []byte{8}, false); !bytes.Equal(got, []byte{0x30}) {
			t.Fatalf("unselected key exposed: %x", got)
		}
	}
	if trusted && !localChoice {
		if response.Count == nil || *response.Count != 2 {
			t.Fatal("browser not told there are two accounts")
		}
		next := p.hid(cid, 0x90, []byte{8}, true)
		// Reset the struct so omitted continuation fields stay nil.
		response.Count, response.User = nil, nil
		if next[0] != 0 || cbor.Unmarshal(next[1:], &response) != nil || response.Count != nil ||
			response.User["name"] != secondUser || !bytes.Equal(response.User["id"].([]byte), []byte("second-user")) {
			t.Fatalf("GetNextAssertion account: %x", next)
		}
		if len(response.AuthData) != 37 || response.AuthData[32] != 5 || !bytes.Equal(response.AuthData[:32], rpHash[:]) {
			t.Fatal("continuation lost RP or UV/presence flags")
		}
		digest = sha256.Sum256(append(append([]byte(nil), response.AuthData...), challenge[:]...))
		if !ecdsa.VerifyASN1(&secondKey.PublicKey, digest[:], response.Signature) {
			t.Fatal("second signature does not verify")
		}
		if got := p.hid(cid, 0x90, []byte{8}, false); !bytes.Equal(got, []byte{0x30}) {
			t.Fatalf("exhausted enumeration: %x", got)
		}
		// A second HID channel must not consume the first one's pending list.
		p.hid(cid, 0x90, append([]byte{2}, args...), false)
		other := p.hid([]byte{255, 255, 255, 255}, 0x86, []byte("othercid"), false)
		if got := p.hid(other[8:12], 0x90, []byte{8}, false); !bytes.Equal(got, []byte{0x30}) {
			t.Fatalf("cross-channel continuation: %x", got)
		}
	}
}
