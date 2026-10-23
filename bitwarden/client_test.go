package bitwarden

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/ctap"
	"github.com/moinakb001/virtbw/fido_client"
)

type fakeVault struct {
	items     []*Item
	listCalls int
}

func (vault *fakeVault) ListItems() ([]*Item, error) {
	vault.listCalls++
	return vault.items, nil
}

func (vault *fakeVault) Sync() error {
	return nil
}

type fakeApprover struct {
	approve bool
	asked   []fido_client.ClientActionRequestParams
	choice  int
	choices [][]string
}

func (approver *fakeApprover) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	approver.asked = append(approver.asked, params)
	return approver.approve
}

type fakeChooser struct {
	fakeApprover
}

func (chooser *fakeChooser) ChooseCredential(relyingParty string, userNames []string) (int, bool) {
	chooser.choices = append(chooser.choices, userNames)
	return chooser.choice, chooser.approve
}

func newTestPasskey(t *testing.T, id string, rpID string, userName string, discoverable bool, created string) (Fido2Credential, *ecdsa.PrivateKey) {
	key := crypto.GenerateECDSAKey()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	handle := base64.RawURLEncoding.EncodeToString([]byte("handle-" + userName))
	return Fido2Credential{
		CredentialID:    id,
		KeyType:         "public-key",
		KeyAlgorithm:    "ECDSA",
		KeyCurve:        "P-256",
		KeyValue:        base64.RawURLEncoding.EncodeToString(der),
		RPID:            rpID,
		UserHandle:      &handle,
		UserName:        &userName,
		UserDisplayName: &userName,
		Counter:         "0",
		Discoverable:    flexString(fmt.Sprint(discoverable)),
		CreationDate:    created,
	}, key
}

func loginItem(name string, creds ...Fido2Credential) *Item {
	return &Item{ID: name, Type: ItemTypeLogin, Name: name, Login: &Login{Fido2Credentials: creds}}
}

type assertionResponse struct {
	Credential struct {
		ID []byte `cbor:"id"`
	} `cbor:"1,keyasint"`
	AuthData  []byte `cbor:"2,keyasint"`
	Signature []byte `cbor:"3,keyasint"`
	User      *struct {
		ID []byte `cbor:"id"`
	} `cbor:"4,keyasint"`
}

func getAssertion(t *testing.T, server *ctap.CTAPServer, rpID string, clientDataHash []byte, allowList [][]byte) (byte, *assertionResponse) {
	args := map[int]any{1: rpID, 2: clientDataHash}
	if allowList != nil {
		var descriptors []map[string]any
		for _, id := range allowList {
			descriptors = append(descriptors, map[string]any{"type": "public-key", "id": id})
		}
		args[3] = descriptors
	}
	encoded, err := cbor.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	response := server.HandleMessage(append([]byte{0x02}, encoded...))
	if response[0] != 0 {
		return response[0], nil
	}
	var decoded assertionResponse
	if err := cbor.Unmarshal(response[1:], &decoded); err != nil {
		t.Fatal(err)
	}
	return 0, &decoded
}

func verifyAssertion(t *testing.T, response *assertionResponse, key *ecdsa.PrivateKey, rpID string, clientDataHash []byte) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(response.AuthData[:32], rpIDHash[:]) {
		t.Fatal("authenticator data has wrong RP ID hash")
	}
	signed := append(append([]byte{}, response.AuthData...), clientDataHash...)
	if !crypto.VerifyECDSA(&key.PublicKey, signed, response.Signature) {
		t.Fatal("signature does not verify with the passkey's public key")
	}
}

func TestGetAssertionWithAllowList(t *testing.T) {
	cred, key := newTestPasskey(t, "9b3c8f0e-3d56-4b8a-9f2c-6c1e7a5d4b21", "example.com", "alice", false, "2024-01-01T00:00:00.000Z")
	other, _ := newTestPasskey(t, "b64.AQIDBA", "example.com", "bob", true, "2024-02-01T00:00:00.000Z")
	vault := &fakeVault{items: []*Item{loginItem("Example", cred), loginItem("Example 2", other)}}
	approver := &fakeApprover{approve: true}
	server := ctap.NewCTAPServer(NewClient(vault, approver, Options{}))

	id, _ := parseCredentialID(cred.CredentialID)
	clientDataHash := crypto.HashSHA256([]byte("client data"))
	status, response := getAssertion(t, server, "example.com", clientDataHash, [][]byte{id})
	if status != 0 {
		t.Fatalf("status %#x", status)
	}
	if !bytes.Equal(response.Credential.ID, id) {
		t.Fatal("wrong credential returned")
	}
	if response.User != nil {
		t.Fatal("user returned for allow list request")
	}
	verifyAssertion(t, response, key, "example.com", clientDataHash)
	if len(approver.asked) != 1 || approver.asked[0].UserName != "alice" {
		t.Fatalf("unexpected approvals %#v", approver.asked)
	}
}

func TestGetAssertionDiscoverable(t *testing.T) {
	nonDiscoverable, _ := newTestPasskey(t, "11111111-1111-4111-8111-111111111111", "example.com", "carol", false, "2025-01-01T00:00:00.000Z")
	cred, key := newTestPasskey(t, "22222222-2222-4222-8222-222222222222", "example.com", "alice", true, "2024-01-01T00:00:00.000Z")
	otherSite, _ := newTestPasskey(t, "33333333-3333-4333-8333-333333333333", "other.com", "dave", true, "2024-01-01T00:00:00.000Z")
	vault := &fakeVault{items: []*Item{loginItem("A", nonDiscoverable), loginItem("B", cred), loginItem("C", otherSite)}}
	server := ctap.NewCTAPServer(NewClient(vault, &fakeApprover{approve: true}, Options{}))

	clientDataHash := crypto.HashSHA256([]byte("client data"))
	status, response := getAssertion(t, server, "example.com", clientDataHash, nil)
	if status != 0 {
		t.Fatalf("status %#x", status)
	}
	if response.User == nil || string(response.User.ID) != "handle-alice" {
		t.Fatalf("expected alice's user handle, got %#v", response.User)
	}
	verifyAssertion(t, response, key, "example.com", clientDataHash)
}

func TestGetAssertionChoosesAccount(t *testing.T) {
	older, olderKey := newTestPasskey(t, "11111111-1111-4111-8111-111111111111", "example.com", "alice", true, "2024-01-01T00:00:00.000Z")
	newer, _ := newTestPasskey(t, "22222222-2222-4222-8222-222222222222", "example.com", "bob", true, "2024-06-01T00:00:00.000Z")
	vault := &fakeVault{items: []*Item{loginItem("A", older), loginItem("B", newer)}}
	chooser := &fakeChooser{fakeApprover{approve: true, choice: 1}}
	server := ctap.NewCTAPServer(NewClient(vault, chooser, Options{}))

	clientDataHash := crypto.HashSHA256([]byte("client data"))
	status, response := getAssertion(t, server, "example.com", clientDataHash, nil)
	if status != 0 {
		t.Fatalf("status %#x", status)
	}
	if len(chooser.choices) != 1 || fmt.Sprint(chooser.choices[0]) != "[bob alice]" {
		t.Fatalf("unexpected choices %#v", chooser.choices)
	}
	if string(response.User.ID) != "handle-alice" {
		t.Fatal("chosen account was not used")
	}
	verifyAssertion(t, response, olderKey, "example.com", clientDataHash)
}

func TestGetAssertionDenied(t *testing.T) {
	cred, _ := newTestPasskey(t, "22222222-2222-4222-8222-222222222222", "example.com", "alice", true, "")
	vault := &fakeVault{items: []*Item{loginItem("A", cred)}}
	server := ctap.NewCTAPServer(NewClient(vault, &fakeApprover{approve: false}, Options{}))
	if status, _ := getAssertion(t, server, "example.com", make([]byte, 32), nil); status != 0x27 {
		t.Fatalf("expected operation denied, got %#x", status)
	}
	if status, _ := getAssertion(t, server, "nothing.com", make([]byte, 32), nil); status != 0x2E {
		t.Fatalf("expected no credentials, got %#x", status)
	}
}

func TestMakeCredentialRefused(t *testing.T) {
	vault := &fakeVault{}
	approver := &fakeApprover{approve: true}
	server := ctap.NewCTAPServer(NewClient(vault, approver, Options{}))
	args := map[int]any{
		1: make([]byte, 32),
		2: map[string]any{"id": "example.com", "name": "Example"},
		3: map[string]any{"id": []byte{1}, "name": "alice", "displayName": "Alice"},
		4: []map[string]any{{"type": "public-key", "alg": -7}},
	}
	encoded, _ := cbor.Marshal(args)
	response := server.HandleMessage(append([]byte{0x01}, encoded...))
	if response[0] != 0x27 {
		t.Fatalf("expected operation denied, got %#x", response[0])
	}
	if len(approver.asked) != 0 {
		t.Fatal("user was asked to approve a credential that cannot be stored")
	}
}

func TestItemCache(t *testing.T) {
	vault := &fakeVault{}
	client := NewClient(vault, &fakeApprover{}, Options{CacheTTL: 1 << 62})
	client.GetAssertionSource("example.com", nil)
	client.GetAssertionSource("example.com", nil)
	if vault.listCalls != 1 {
		t.Fatalf("expected one list call, got %d", vault.listCalls)
	}
	client.Sync()
	client.GetAssertionSource("example.com", nil)
	if vault.listCalls != 2 {
		t.Fatalf("expected cache to be dropped after sync, got %d calls", vault.listCalls)
	}
}

func TestParseCredentialID(t *testing.T) {
	id, err := parseCredentialID("9B3C8F0E-3D56-4B8A-9F2C-6C1E7A5D4B21")
	if err != nil || len(id) != 16 || id[0] != 0x9b || id[15] != 0x21 {
		t.Fatalf("bad GUID parse %x %v", id, err)
	}
	id, err = parseCredentialID("b64.AQIDBA")
	if err != nil || !bytes.Equal(id, []byte{1, 2, 3, 4}) {
		t.Fatalf("bad b64 parse %x %v", id, err)
	}
	if _, err := parseCredentialID("not-a-guid"); err == nil {
		t.Fatal("expected error")
	}
}

// Shape of `bw --response list items` output, including the CLI's string counters.
const cliListResponse = `{"success":true,"data":{"object":"list","data":[
 {"object":"item","id":"item-1","type":1,"name":"Example","reprompt":0,
  "login":{"uris":[{"match":null,"uri":"https://example.com"}],"username":"alice","password":null,"totp":null,
   "fido2Credentials":[{"credentialId":"9b3c8f0e-3d56-4b8a-9f2c-6c1e7a5d4b21","keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256","keyValue":"KEY","rpId":"example.com","userHandle":"aGFuZGxl","userName":"alice","counter":"7","rpName":"Example","userDisplayName":"Alice","discoverable":"true","creationDate":"2024-01-01T00:00:00.000Z"}]}},
 {"object":"item","id":"item-2","type":2,"name":"Note","secureNote":{"type":0},"login":null}
]}}`

func checkListedItems(t *testing.T, items []*Item) {
	if len(items) != 2 || items[0].ID != "item-1" || items[1].Login != nil {
		t.Fatalf("unexpected items %#v", items)
	}
	cred := items[0].Login.Fido2Credentials[0]
	if cred.counter() != 7 || !cred.discoverable() || strVal(cred.UserName) != "alice" {
		t.Fatalf("unexpected credential %#v", cred)
	}
}

func TestCLIVault(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output.json")
	if err := os.WriteFile(output, []byte(cliListResponse), 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "bw")
	body := fmt.Sprintf("#!/bin/sh\necho \"$BW_SESSION $@\" > %s/args\ncat %s\n", dir, output)
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	vault := &CLIVault{Path: script, Session: "session-key"}
	items, err := vault.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	checkListedItems(t, items)
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if string(args) != "session-key --response --nointeraction list items\n" {
		t.Fatalf("unexpected bw invocation %q", args)
	}

	os.WriteFile(output, []byte(`{"success":false,"message":"Vault is locked."}`), 0600)
	if _, err := vault.ListItems(); err == nil || err.Error() != "bitwarden: Vault is locked." {
		t.Fatalf("expected locked error, got %v", err)
	}
}

func TestServeVault(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/list/object/items":
			w.Write([]byte(cliListResponse))
		case "/sync":
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	vault := &ServeVault{URL: server.URL}
	items, err := vault.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	checkListedItems(t, items)
	if err := vault.Sync(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(requests) != "[GET /list/object/items POST /sync]" {
		t.Fatalf("unexpected requests %v", requests)
	}
}
