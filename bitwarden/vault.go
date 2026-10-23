package bitwarden

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Vault is where the Bitwarden FIDO client looks up passkeys. It is only ever read from.
// Items are returned in the Bitwarden CLI's decrypted JSON format.
type Vault interface {
	ListItems() ([]*Item, error)
	// Sync pulls the latest vault data from the Bitwarden server into the local CLI cache.
	Sync() error
}

// cliResponse is the envelope returned by `bw --response` and by `bw serve`.
type cliResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type listResponse struct {
	Data []*Item `json:"data"`
}

func decodeResponse(raw []byte) (json.RawMessage, error) {
	var response cliResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("could not decode Bitwarden response %q: %w", truncate(raw), err)
	}
	if !response.Success {
		return nil, fmt.Errorf("bitwarden: %s", response.Message)
	}
	return response.Data, nil
}

func decodeItemList(data json.RawMessage) ([]*Item, error) {
	var list listResponse
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("could not decode item list: %w", err)
	}
	return list.Data, nil
}

func truncate(data []byte) string {
	const max = 200
	if len(data) > max {
		return string(data[:max]) + "..."
	}
	return string(data)
}

// CLIVault reads the vault by running the `bw` command line tool. The vault must be
// unlocked, with BW_SESSION set in the environment or passed as Session.
type CLIVault struct {
	// Path to the bw executable. Defaults to "bw" on $PATH.
	Path string
	// Session key printed by `bw unlock`. Defaults to $BW_SESSION.
	Session string
}

func (vault *CLIVault) run(args ...string) (json.RawMessage, error) {
	path := vault.Path
	if path == "" {
		path = "bw"
	}
	cmd := exec.Command(path, append([]string{"--response", "--nointeraction"}, args...)...)
	cmd.Env = os.Environ()
	if vault.Session != "" {
		cmd.Env = append(cmd.Env, "BW_SESSION="+vault.Session)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr == nil {
			runErr = errors.New("no output")
		}
		return nil, fmt.Errorf("bw %s: %w: %s", args[0], runErr, strings.TrimSpace(stderr.String()))
	}
	return decodeResponse(stdout.Bytes())
}

func (vault *CLIVault) ListItems() ([]*Item, error) {
	data, err := vault.run("list", "items")
	if err != nil {
		return nil, err
	}
	return decodeItemList(data)
}

func (vault *CLIVault) Sync() error {
	_, err := vault.run("sync")
	return err
}

// ServeVault reads the vault through the local REST API started by `bw serve`. The vault
// must be unlocked.
type ServeVault struct {
	// Base URL of the API. Defaults to http://localhost:8087.
	URL    string
	Client *http.Client
}

func (vault *ServeVault) do(method string, path string) (json.RawMessage, error) {
	base := vault.URL
	if base == "" {
		base = "http://localhost:8087"
	}
	request, err := http.NewRequest(method, strings.TrimSuffix(base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	client := vault.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("bw serve %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("bw serve %s %s: %w", method, path, err)
	}
	return decodeResponse(raw)
}

func (vault *ServeVault) ListItems() ([]*Item, error) {
	data, err := vault.do(http.MethodGet, "/list/object/items")
	if err != nil {
		return nil, err
	}
	return decodeItemList(data)
}

func (vault *ServeVault) Sync() error {
	_, err := vault.do(http.MethodPost, "/sync")
	return err
}
