package ctap

import (
	"time"

	"github.com/moinakb001/virtbw/identities"
	"github.com/moinakb001/virtbw/webauthn"
)

// Optional backend support for returning accounts to the browser instead of
// choosing one locally. Sources must already be authorized by backend policy.
type multipleAssertionClient interface {
	SupportsMultipleAssertions() bool
	GetAssertionSources(relyingPartyID string) []*identities.CredentialSource
}

type assertionContinuation struct {
	args         getAssertionArgs
	flags        authDataFlags
	remainingIDs [][]byte
	lastUsed     time.Time
}

func (server *CTAPServer) rememberAssertions(args getAssertionArgs, flags authDataFlags, sources []*identities.CredentialSource) {
	// Keep only IDs, never cached private keys, across browser requests.
	args.ClientDataHash = append([]byte(nil), args.ClientDataHash...)
	state := &assertionContinuation{args: args, flags: flags, lastUsed: time.Now()}
	for _, source := range sources {
		state.remainingIDs = append(state.remainingIDs, append([]byte(nil), source.ID...))
	}
	server.assertions = state
}

func (server *CTAPServer) handleGetNextAssertion(data []byte) []byte {
	state := server.assertions
	server.assertions = nil // any failure invalidates the sequence
	if len(data) != 0 {
		return []byte{byte(ctap1ErrInvalidLength)}
	}
	if state == nil || len(state.remainingIDs) == 0 || time.Since(state.lastUsed) > 30*time.Second {
		return []byte{byte(ctap2ErrNotAllowed)}
	}
	// Read this credential again so locking the vault or deleting a passkey
	// after the first response prevents further signatures.
	source := server.client.GetAssertionSource(state.args.RPID, []webauthn.PublicKeyCredentialDescriptor{
		{Type: "public-key", ID: state.remainingIDs[0]},
	})
	if source == nil {
		return []byte{byte(ctap2ErrNoCredentials)}
	}
	if !server.client.ApproveAccountLogin(source) {
		return []byte{byte(ctap2ErrOperationDenied)}
	}
	response := assertionResponseBytes(state.args, source, state.flags, 0)
	state.remainingIDs = state.remainingIDs[1:]
	if len(state.remainingIDs) > 0 {
		state.lastUsed = time.Now()
		server.assertions = state
	}
	return response
}
