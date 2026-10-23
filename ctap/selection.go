package ctap

import (
	"bytes"
	"crypto/sha256"

	"github.com/moinakb001/virtbw/cose"
	"github.com/moinakb001/virtbw/crypto"
	"github.com/moinakb001/virtbw/identities"
	"github.com/moinakb001/virtbw/util"
)

// Optional backend capability: existing CTAP clients keep their normal
// MakeCredential behavior unless they explicitly support selection-only probes.
type authenticatorSelector interface {
	ApproveAuthenticatorSelection() bool
}

// Chromium's CTAP 2.0 GetTouchRequest uses this non-resident dummy registration
// when a device has no PIN. Do not treat arbitrary registration as selection.
// See device/fido/make_credential_task.cc, MakeCredentialTask::GetTouchRequest.
func isSelectionProbe(a makeCredentialArgs) bool {
	emptyHash := sha256.Sum256(nil)
	return a.RP != nil && a.RP.ID == ".dummy" && a.RP.Name == "" &&
		a.User != nil && bytes.Equal(a.User.ID, []byte{1}) && a.User.Name == "dummy" && a.User.DisplayName == "" &&
		bytes.Equal(a.ClientDataHash, emptyHash[:]) &&
		len(a.PubKeyCredParams) == 1 && a.PubKeyCredParams[0].Type == "public-key" &&
		a.PubKeyCredParams[0].Algorithm == cose.COSE_ALGORITHM_ID_ES256 &&
		len(a.ExcludeList) == 0 && len(a.Extensions) == 0 &&
		a.PINUVAuthParam == nil && a.PINUVAuthProtocol == 0 &&
		(a.Options == nil || (!a.Options.ResidentKey && a.Options.UserPresence == nil))
}

func (server *CTAPServer) selectionResponse(selector authenticatorSelector, requireUV bool) []byte {
	flags := authDataFlagUserPresent
	if requireUV {
		if status := server.verifyUser(".dummy"); status != ctap1ErrSuccess {
			return []byte{byte(status)}
		}
		flags |= authDataFlagUserVerified
	}
	if !selector.ApproveAuthenticatorSelection() {
		return []byte{byte(ctap2ErrOperationDenied)}
	}
	// A valid, disposable non-resident credential satisfies Chromium's touch
	// probe. Nothing is saved, and its private key is discarded. The "none"
	// attestation has an empty statement. UV is only set when the backend's
	// configured verification policy succeeded for this request.
	source := &identities.CredentialSource{
		ID:         crypto.RandomBytes(32),
		PrivateKey: &cose.SupportedCOSEPrivateKey{ECDSA: crypto.GenerateECDSAKey()},
	}
	attested := makeAttestedCredentialData(source)
	copy(attested[:len(aaguid)], make([]byte, len(aaguid))) // anonymous "none" attestation
	data := makeAuthData(".dummy", source, attested, flags)
	response := map[int]interface{}{1: "none", 2: data, 3: map[string]interface{}{}}
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}
