package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	virtual_fido "github.com/moinakb001/virtbw"
	"github.com/moinakb001/virtbw/bitwarden"
	"github.com/moinakb001/virtbw/fido_client"
	"github.com/moinakb001/virtbw/util"
	"github.com/spf13/cobra"
)

var backend string
var bwPath string
var serveURL string
var cacheTTL time.Duration
var syncOnStart bool
var verbose bool
var transport string
var listenAddress string
var trustUnlockedVault bool

var stdin = bufio.NewReader(os.Stdin)

func readLine(prompt string) string {
	fmt.Println(prompt)
	fmt.Print("--> ")
	response, err := stdin.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s\n", err)
		return "n"
	}
	return strings.TrimSpace(response)
}

type terminalApprover struct{}

func (approver terminalApprover) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	if action == fido_client.ClientActionFIDOSelect {
		response := strings.ToLower(readLine("Select this security key for the browser? No login is approved yet. (y/N)"))
		return response == "y" || response == "yes"
	}
	if action != fido_client.ClientActionFIDOGetAssertion {
		return false
	}
	response := strings.ToLower(readLine(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", params.RelyingParty, params.UserName)))
	return response == "" || response == "y" || response == "yes"
}

func (approver terminalApprover) ChooseCredential(relyingParty string, userNames []string) (int, bool) {
	lines := []string{fmt.Sprintf("Choose a passkey for %q (enter its number, or n to cancel):", relyingParty)}
	for i, name := range userNames {
		lines = append(lines, fmt.Sprintf("  %d) %s", i+1, name))
	}
	response := readLine(strings.Join(lines, "\n"))
	choice, err := strconv.Atoi(response)
	if err != nil || choice < 1 || choice > len(userNames) {
		return 0, false
	}
	return choice - 1, true
}

func createClient() *bitwarden.Client {
	virtual_fido.SetLogOutput(os.Stdout)
	if verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}
	var vault bitwarden.Vault
	switch backend {
	case "cli":
		vault = &bitwarden.CLIVault{Path: bwPath}
	case "serve":
		vault = &bitwarden.ServeVault{URL: serveURL}
	default:
		fmt.Fprintf(os.Stderr, "Unknown backend %q, expected \"cli\" or \"serve\"\n", backend)
		os.Exit(1)
	}
	return bitwarden.NewClient(vault, terminalApprover{}, bitwarden.Options{
		CacheTTL: cacheTTL, TrustUnlockedVault: trustUnlockedVault, SelectCredentialLocally: true,
	})
}

func syncVault(client *bitwarden.Client) {
	if !syncOnStart {
		return
	}
	if err := client.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "Could not sync vault: %s\n", err)
		os.Exit(1)
	}
}

func listPasskeys(cmd *cobra.Command, args []string) {
	client := createClient()
	syncVault(client)
	sources, err := client.Passkeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("------- %d passkeys in Bitwarden vault -------\n", len(sources))
	for _, source := range sources {
		fmt.Printf("(%s): '%s' for website '%s'\n", hex.EncodeToString(source.ID[:4]), source.User.Name, source.RelyingParty.ID)
	}
}

func start(cmd *cobra.Command, args []string) error {
	if transport != "native" && transport != "virtualhere" {
		return fmt.Errorf("unknown transport %q, expected native or virtualhere", transport)
	}
	client := createClient()
	syncVault(client)
	sources, err := client.Passkeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Found %d passkeys in Bitwarden vault (read-only)\n", len(sources))
	if trustUnlockedVault {
		fmt.Println("Authorization: live unlocked Bitwarden vault. UV and presence use this trust policy. Multiple matching passkeys require a terminal selection; one match proceeds automatically.")
	}
	if transport == "virtualhere" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		fmt.Printf("Starting experimental VirtualHere transport at %s. Add this address as a manual hub and use virtbw Virtual FIDO.\n", listenAddress)
		return virtual_fido.ServeVirtualHere(ctx, listenAddress, client)
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		virtual_fido.Start(client)
		wg.Done()
	}()
	go func() {
		time.Sleep(500 * time.Millisecond)
		prog := platformUSBIPExec()
		if prog != nil {
			prog.Stdin = os.Stdin
			prog.Stdout = os.Stdout
			prog.Stderr = os.Stderr
			if err := prog.Run(); err != nil {
				fmt.Printf("Error: %s\n", err)
			}
		}
		wg.Done()
	}()
	wg.Wait()
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "virtbw",
	Short: "Virtual FIDO device backed by Bitwarden passkeys",
	Long: `virtbw attaches a virtual FIDO2 USB device that logs in with the passkeys stored in
your Bitwarden vault. The vault is only read, never modified: new passkeys cannot
be registered through the device.

The vault must be unlocked first, either with BW_SESSION exported for the "cli"
backend or with "bw serve" running for the "serve" backend.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&backend, "backend", "cli", `How to reach the vault: "cli" runs bw, "serve" uses the "bw serve" API`)
	rootCmd.PersistentFlags().StringVar(&bwPath, "bw", "bw", "Path to the Bitwarden CLI (cli backend)")
	rootCmd.PersistentFlags().StringVar(&serveURL, "serve-url", "http://localhost:8087", `URL of "bw serve" (serve backend)`)
	rootCmd.PersistentFlags().DurationVar(&cacheTTL, "cache-ttl", 30*time.Second, "How long vault items are reused before reading the vault again")
	rootCmd.PersistentFlags().BoolVar(&syncOnStart, "sync", true, "Sync the vault with the Bitwarden server on start")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&transport, "transport", "native", "Device transport: native or virtualhere (experimental)")
	rootCmd.PersistentFlags().StringVar(&listenAddress, "listen", "127.0.0.1:7575", "Loopback IP:port for VirtualHere (trial clients require port 7575)")
	rootCmd.PersistentFlags().BoolVar(&trustUnlockedVault, "trust-unlocked-vault", false, "Report UV based on live unlocked vault access; only prompt to choose between multiple matching passkeys")
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Attach virtual FIDO device",
		RunE:  start,
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List passkeys in the Bitwarden vault",
		Run:   listPasskeys,
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
