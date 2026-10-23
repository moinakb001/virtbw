package bitwarden

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/moinakb001/virtbw/cose"
	"github.com/moinakb001/virtbw/identities"
	"github.com/moinakb001/virtbw/webauthn"
)

// Bitwarden stores credential IDs either as a GUID (passkeys it created, raw ID is the
// 16 GUID bytes) or as "b64.<base64url raw ID>" (imported passkeys).
const credentialIDBase64Prefix = "b64."

func parseCredentialID(encoded string) ([]byte, error) {
	if strings.HasPrefix(encoded, credentialIDBase64Prefix) {
		return decodeBase64(encoded[len(credentialIDBase64Prefix):])
	}
	if len(encoded) != 36 || encoded[8] != '-' || encoded[13] != '-' || encoded[18] != '-' || encoded[23] != '-' {
		return nil, fmt.Errorf("credential ID %q is not a GUID", encoded)
	}
	return hex.DecodeString(strings.ReplaceAll(encoded, "-", ""))
}

// decodeBase64 accepts base64url (what Bitwarden writes) as well as standard base64,
// with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

func parsePrivateKey(keyValue string) (*ecdsa.PrivateKey, error) {
	der, err := decodeBase64(keyValue)
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("invalid PKCS#8 key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("only ECDSA P-256 passkeys are supported")
	}
	return ecdsaKey, nil
}

// credentialSource converts a stored passkey into the form the CTAP server signs with.
func (cred *Fido2Credential) credentialSource() (*identities.CredentialSource, error) {
	if cred.KeyType != "" && cred.KeyType != "public-key" {
		return nil, fmt.Errorf("unsupported key type %q", cred.KeyType)
	}
	id, err := parseCredentialID(cred.CredentialID)
	if err != nil {
		return nil, err
	}
	privateKey, err := parsePrivateKey(cred.KeyValue)
	if err != nil {
		return nil, err
	}
	var userHandle []byte
	if cred.UserHandle != nil {
		if userHandle, err = decodeBase64(*cred.UserHandle); err != nil {
			return nil, fmt.Errorf("invalid user handle: %w", err)
		}
	}
	return &identities.CredentialSource{
		Type:       "public-key",
		ID:         id,
		PrivateKey: &cose.SupportedCOSEPrivateKey{ECDSA: privateKey},
		RelyingParty: &webauthn.PublicKeyCredentialRPEntity{
			ID:   cred.RPID,
			Name: strVal(cred.RPName),
		},
		User: &webauthn.PublicKeyCrendentialUserEntity{
			ID:          userHandle,
			Name:        strVal(cred.UserName),
			DisplayName: strVal(cred.UserDisplayName),
		},
		SignatureCounter: int32(cred.counter()),
	}, nil
}
