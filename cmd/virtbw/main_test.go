package main

import (
	"bufio"
	"strings"
	"testing"

	"github.com/moinakb001/virtbw/fido_client"
)

func TestLoginApprovalFailsClosedOnInputError(t *testing.T) {
	original := stdin
	t.Cleanup(func() { stdin = original })
	for _, tc := range []struct {
		input string
		want  bool
	}{{"", false}, {"yes", false}, {"n\n", false}, {"\n", true}, {"yes\n", true}} {
		stdin = bufio.NewReader(strings.NewReader(tc.input))
		got := (terminalApprover{}).ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, fido_client.ClientActionRequestParams{})
		if got != tc.want {
			t.Errorf("input %q: got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestSelectionRequiresExplicitApproval(t *testing.T) {
	original := stdin
	t.Cleanup(func() { stdin = original })
	for _, tc := range []struct {
		input string
		want  bool
	}{{"", false}, {"y", false}, {"\n", false}, {"n\n", false}, {"y\n", true}, {"yes\n", true}} {
		stdin = bufio.NewReader(strings.NewReader(tc.input))
		if got := (terminalApprover{}).ApproveClientAction(fido_client.ClientActionFIDOSelect, fido_client.ClientActionRequestParams{}); got != tc.want {
			t.Errorf("selection input %q: got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestTerminalPasskeyChoice(t *testing.T) {
	original := stdin
	t.Cleanup(func() { stdin = original })
	for _, tc := range []struct {
		input string
		index int
		ok    bool
	}{
		{"1\n", 0, true}, {"2\n", 1, true}, {"n\n", 0, false},
		{"\n", 0, false}, {"0\n", 0, false}, {"3\n", 0, false},
		{"", 0, false}, {"2", 0, false},
	} {
		stdin = bufio.NewReader(strings.NewReader(tc.input))
		index, ok := (terminalApprover{}).ChooseCredential("example.test", []string{"first key", "second key"})
		if index != tc.index || ok != tc.ok {
			t.Errorf("%q: got (%d, %v)", tc.input, index, ok)
		}
	}
}

func TestCLIUsesLocalSelectionWithTrustedVault(t *testing.T) {
	original := trustUnlockedVault
	t.Cleanup(func() { trustUnlockedVault = original })
	trustUnlockedVault = true
	client := createClient()
	if !client.SupportsUserVerification() || client.SupportsMultipleAssertions() {
		t.Fatal("CLI must retain vault-based UV and use terminal account selection")
	}
}
