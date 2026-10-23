// Package bitwarden implements a read-only virtual FIDO client that signs in with the
// passkeys stored in a Bitwarden vault. Passkeys are looked up through the Bitwarden CLI;
// nothing is ever written back to the vault or stored anywhere else, so creating new
// credentials (FIDO2 or U2F) is refused.
package bitwarden

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/moinakb001/virtbw/cose"
	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/fido_client"
	"github.com/moinakb001/virtbw/identities"
	"github.com/moinakb001/virtbw/util"
	"github.com/moinakb001/virtbw/webauthn"
)

var bitwardenLogger = util.NewLogger("[BITWARDEN] ", util.LogLevelEnabled)
var bitwardenDebugLogger = util.NewLogger("[BITWARDEN] ", util.LogLevelDebug)

// CredentialChooser can optionally be implemented by the request approver. When several
// passkeys match a login request it is asked to pick one instead of a yes/no approval.
// It returns the index of the chosen account, or false to deny the login.
type CredentialChooser interface {
	ChooseCredential(relyingParty string, userNames []string) (int, bool)
}

type Options struct {
	// How long the list of vault items is reused before asking Bitwarden again.
	CacheTTL time.Duration
}

// Client is a virtual_fido.FIDOClient backed by a Bitwarden vault.
type Client struct {
	vault    Vault
	approver fido_client.ClientRequestApprover
	options  Options

	// Only used for U2F key handles, which cannot be created in read-only mode; a random
	// key makes every foreign key handle fail to open.
	sealingKey []byte

	lock         sync.Mutex
	items        []*Item
	itemsFetched time.Time

	// Passkeys found by the latest GetAssertionSource, so ApproveAccountLogin can let the
	// user choose between accounts.
	pendingSource     *identities.CredentialSource
	pendingCandidates []*passkey
}

// passkey is a credential in the vault together with the item it is stored in.
type passkey struct {
	item       *Item
	credential *Fido2Credential
	source     *identities.CredentialSource
}

func NewClient(vault Vault, approver fido_client.ClientRequestApprover, options Options) *Client {
	return &Client{
		vault:      vault,
		approver:   approver,
		options:    options,
		sealingKey: crypto.GenerateSymmetricKey(),
	}
}

func (client *Client) fetchItems(force bool) ([]*Item, error) {
	if !force && !client.itemsFetched.IsZero() && time.Since(client.itemsFetched) < client.options.CacheTTL {
		return client.items, nil
	}
	items, err := client.vault.ListItems()
	if err != nil {
		return nil, fmt.Errorf("could not list vault items: %w", err)
	}
	client.items = items
	client.itemsFetched = time.Now()
	return items, nil
}

// passkeys returns the usable passkeys in the vault, optionally only those for one
// relying party, most recently created first.
func (client *Client) passkeys(relyingPartyID string, force bool) ([]*passkey, error) {
	items, err := client.fetchItems(force)
	if err != nil {
		return nil, err
	}
	var passkeys []*passkey
	for _, item := range items {
		if item.Type != ItemTypeLogin || item.Login == nil {
			continue
		}
		for i := range item.Login.Fido2Credentials {
			cred := &item.Login.Fido2Credentials[i]
			if relyingPartyID != "" && cred.RPID != relyingPartyID {
				continue
			}
			source, err := cred.credentialSource()
			if err != nil {
				bitwardenLogger.Printf("Skipping passkey in item %q (%s): %s\n", item.Name, item.ID, err)
				continue
			}
			passkeys = append(passkeys, &passkey{item: item, credential: cred, source: source})
		}
	}
	sort.SliceStable(passkeys, func(i, j int) bool {
		return passkeys[i].credential.CreationDate > passkeys[j].credential.CreationDate
	})
	return passkeys, nil
}

// Sync pulls the latest vault data from the Bitwarden server and drops cached items.
func (client *Client) Sync() error {
	client.lock.Lock()
	defer client.lock.Unlock()
	client.items = nil
	client.itemsFetched = time.Time{}
	return client.vault.Sync()
}

// Passkeys lists every usable passkey in the vault.
func (client *Client) Passkeys() ([]identities.CredentialSource, error) {
	client.lock.Lock()
	defer client.lock.Unlock()
	passkeys, err := client.passkeys("", true)
	if err != nil {
		return nil, err
	}
	sources := make([]identities.CredentialSource, len(passkeys))
	for i, passkey := range passkeys {
		sources[i] = *passkey.source
	}
	return sources, nil
}

// -----------------------------
// FIDO2 Methods
// -----------------------------

func (client *Client) SupportsResidentKey() bool {
	return true
}

// NewCredentialSource is never reached because ApproveAccountCreation always refuses.
func (client *Client) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	return nil
}

func (client *Client) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	client.lock.Lock()
	defer client.lock.Unlock()

	client.pendingSource = nil
	client.pendingCandidates = nil
	passkeys, err := client.passkeys(relyingPartyID, false)
	if err != nil {
		bitwardenLogger.Printf("ERROR: %s\n", err)
		return nil
	}
	var candidates []*passkey
	for _, passkey := range passkeys {
		if len(allowList) == 0 {
			if passkey.credential.discoverable() {
				candidates = append(candidates, passkey)
			}
			continue
		}
		for _, allowed := range allowList {
			if bytes.Equal(allowed.ID, passkey.source.ID) {
				candidates = append(candidates, passkey)
				break
			}
		}
	}
	bitwardenDebugLogger.Printf("Found %d matching passkeys for %s\n", len(candidates), relyingPartyID)
	if len(candidates) == 0 {
		return nil
	}
	// The CTAP server signs with the returned source after ApproveAccountLogin, which may
	// replace its contents with the account the user picked.
	source := *candidates[0].source
	client.pendingSource = &source
	client.pendingCandidates = candidates
	return &source
}

func (client *Client) ApproveAccountCreation(relyingParty string) bool {
	bitwardenLogger.Printf("Refusing to create a passkey for %q: the Bitwarden backend is read-only\n", relyingParty)
	return false
}

func (client *Client) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	client.lock.Lock()
	var candidates []*passkey
	if credentialSource == client.pendingSource {
		candidates = client.pendingCandidates
	}
	client.pendingSource = nil
	client.pendingCandidates = nil
	client.lock.Unlock()

	if chooser, ok := client.approver.(CredentialChooser); ok && len(candidates) > 1 {
		userNames := make([]string, len(candidates))
		for i, candidate := range candidates {
			userNames[i] = candidate.source.User.Name
		}
		index, ok := chooser.ChooseCredential(credentialSource.RelyingParty.ID, userNames)
		if !ok || index < 0 || index >= len(candidates) {
			return false
		}
		*credentialSource = *candidates[index].source
		return true
	}
	params := fido_client.ClientActionRequestParams{
		RelyingParty: credentialSource.RelyingParty.ID,
		UserName:     credentialSource.User.Name,
	}
	return client.approver.ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, params)
}

// Only used for new credentials, which are never created.
func (client *Client) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	return nil
}

// -----------------------
// PIN Methods
// -----------------------

// A PIN would have to be stored somewhere, so it is not supported.
func (client *Client) SupportsPIN() bool {
	return false
}

func (client *Client) PINHash() []byte {
	return nil
}

func (client *Client) SetPINHash(pin []byte) {}

func (client *Client) PINRetries() int32 {
	return 0
}

func (client *Client) SetPINRetries(retries int32) {}

func (client *Client) PINKeyAgreement() *crypto.ECDHKey {
	return nil
}

func (client *Client) PINToken() []byte {
	return nil
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client *Client) SealingEncryptionKey() []byte {
	return client.sealingKey
}

func (client *Client) NewPrivateKey() *ecdsa.PrivateKey {
	return crypto.GenerateECDSAKey()
}

func (client *Client) NewAuthenticationCounterId() uint32 {
	return uint32(time.Now().Unix())
}

func (client *Client) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	bitwardenLogger.Printf("Refusing U2F registration: the Bitwarden backend is read-only\n")
	return false
}

func (client *Client) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	return false
}
