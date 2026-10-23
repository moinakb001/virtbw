package bitwarden

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Cipher type of login items in the Bitwarden CLI.
const ItemTypeLogin = 1

// Item is a vault item as exposed by the Bitwarden CLI (`bw list items`, `bw serve`).
// Only the fields needed to find and use passkeys are decoded.
type Item struct {
	ID    string `json:"id"`
	Type  int    `json:"type"`
	Name  string `json:"name"`
	Login *Login `json:"login"`
}

type Login struct {
	Fido2Credentials []Fido2Credential `json:"fido2Credentials"`
}

// Fido2Credential is a passkey stored in a login item, in the CLI's export format.
// See Fido2CredentialExport in bitwarden/clients.
type Fido2Credential struct {
	CredentialID    string     `json:"credentialId"`
	KeyType         string     `json:"keyType"`
	KeyAlgorithm    string     `json:"keyAlgorithm"`
	KeyCurve        string     `json:"keyCurve"`
	KeyValue        string     `json:"keyValue"`
	RPID            string     `json:"rpId"`
	UserHandle      *string    `json:"userHandle"`
	UserName        *string    `json:"userName"`
	Counter         flexString `json:"counter"`
	RPName          *string    `json:"rpName"`
	UserDisplayName *string    `json:"userDisplayName"`
	Discoverable    flexString `json:"discoverable"`
	CreationDate    string     `json:"creationDate"`
}

func (cred *Fido2Credential) counter() uint32 {
	counter, err := strconv.ParseUint(string(cred.Counter), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(counter)
}

func (cred *Fido2Credential) discoverable() bool {
	return cred.Discoverable == "true"
}

// flexString accepts a JSON string, number or boolean, since the CLI exports passkey
// counters and the discoverable flag as strings but other tools may not.
type flexString string

func (s *flexString) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch v := value.(type) {
	case nil:
		*s = ""
	case string:
		*s = flexString(v)
	case bool, float64:
		*s = flexString(fmt.Sprint(v))
	default:
		return fmt.Errorf("unexpected JSON value %s", data)
	}
	return nil
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
