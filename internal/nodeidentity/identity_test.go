// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodeidentity

import (
	"errors"
	"strings"
	"testing"
)

// Review R2-17. A node name with a Cyrillic letter looks like the real one when
// it is printed; the refusal shows every non-ASCII character escaped.
func TestAMismatchShowsLookalikeCharactersEscaped(t *testing.T) {
	err := Compare("pve1", "pv\u0435"+"1") // Cyrillic ie, then the digit
	if err == nil {
		t.Fatal("a lookalike name was accepted")
	}
	if !strings.Contains(err.Error(), "pv\\u04351") || strings.ContainsRune(err.Error(), '\u0435') {
		t.Errorf("the refusal does not show the lookalike escaped: %v", err)
	}
}

func TestCompareAcceptsTheNameOfThisHostExactly(t *testing.T) {
	if err := Compare("pve-node-01", "pve-node-01"); err != nil {
		t.Fatalf("the host's own name was refused: %v", err)
	}
	// No name given is a name left out: the default is the host's own.
	if err := Compare("pve-node-01", ""); err != nil {
		t.Fatalf("an absent name was refused: %v", err)
	}
}

func TestCompareRefusesAnotherNodeAndSaysHowToFixIt(t *testing.T) {
	err := Compare("pve-node-01", "pve-node-02")
	var mismatch *MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a *MismatchError", err)
	}
	for _, want := range []string{
		"this host is PVE node pve-node-01",
		"pve-node-02",
		"CERTISTACK_NODE or --node",
		"set CERTISTACK_NODE=pve-node-01",
		"point CERTISTACK_SSH_HOST at node pve-node-02",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %s", want, err)
		}
	}
	for _, unwanted := range []string{"no domain", "case-sensitive"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("the message carries a hint that does not apply (%q): %s", unwanted, err)
		}
	}
}

func TestCompareHintsTheShortNameForAFullyQualifiedOne(t *testing.T) {
	err := Compare("pve-node-01", "pve-node-01.lab.example.invalid")
	if err == nil {
		t.Fatal("a fully qualified name was accepted")
	}
	for _, want := range []string{"set CERTISTACK_NODE=pve-node-01", "no domain", "short node name pve-node-01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %s", want, err)
		}
	}
}

func TestCompareRefusesADifferentCaseAndSaysNamesAreCaseSensitive(t *testing.T) {
	err := Compare("pve-node-01", "PVE-NODE-01")
	if err == nil {
		t.Fatal("a name that differs only in case was accepted: PVE's API is case-sensitive")
	}
	for _, want := range []string{"case-sensitive", "set CERTISTACK_NODE=pve-node-01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %s", want, err)
		}
	}
}

func TestMismatchErrorHasTheParts(t *testing.T) {
	mismatch := &MismatchError{Local: "pve1", Named: "pve1.example.com"}
	if want := "PVE node pve1, but CERTISTACK_NODE names node pve1.example.com"; mismatch.Reached() != want {
		t.Errorf("Reached = %q, want %q", mismatch.Reached(), want)
	}
	fix := mismatch.Fix("/etc/certistack/controller.env")
	for _, want := range []string{"CERTISTACK_NODE=pve1", "/etc/certistack/controller.env", "CERTISTACK_SSH_HOST", "no domain"} {
		if !strings.Contains(fix, want) {
			t.Errorf("Fix lacks %q: %s", want, fix)
		}
	}
}

func TestVerifyFailsClosedWhenTheLocalNameCannotBeRead(t *testing.T) {
	previous := localName
	t.Cleanup(func() { localName = previous })
	localName = func() (string, error) { return "", errors.New("read /etc/pve/local: permission denied") }
	err := Verify("pve1")
	if err == nil || !strings.Contains(err.Error(), "could not read this host's PVE node name") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a refusal that says the name could not be read", err)
	}
	// No name given: nothing to compare, nothing to read.
	if err := Verify(""); err != nil {
		t.Fatalf("an absent name read the host: %v", err)
	}
}

func TestVerifyComparesWithTheNameLocalReturns(t *testing.T) {
	previous := localName
	t.Cleanup(func() { localName = previous })
	localName = func() (string, error) { return "pve-node-01", nil }
	if err := Verify("pve-node-01"); err != nil {
		t.Fatal(err)
	}
	if err := Verify("pve-node-02"); err == nil {
		t.Fatal("another node's name was accepted")
	}
}

func TestNameFromLinkTarget(t *testing.T) {
	for _, tc := range []struct {
		target, want string
		bad          bool
	}{
		{"nodes/pve-node-01", "pve-node-01", false},
		{"nodes/pve-node-01/", "pve-node-01", false},
		{"/etc/pve/nodes/pve1", "pve1", false},
		{"", "", true},
		{"nodes/", "", true},
		{"/", "", true},
		{"nodes/bad name", "", true},
	} {
		got, err := NameFromLinkTarget(tc.target)
		if tc.bad != (err != nil) || got != tc.want {
			t.Errorf("NameFromLinkTarget(%q) = %q, %v", tc.target, got, err)
		}
	}
}

func TestShortHostName(t *testing.T) {
	for in, want := range map[string]string{"pve1": "pve1", "pve1.example.com": "pve1", "pve1.": "pve1", "": ""} {
		if got := ShortHostName(in); got != want {
			t.Errorf("ShortHostName(%q) = %q, want %q", in, got, want)
		}
	}
}
