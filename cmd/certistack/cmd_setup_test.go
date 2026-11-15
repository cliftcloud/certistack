// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/nodesetup"
)

// readIfExists is the file's content, or "" if there is no such file.
func readIfExists(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// maskDir replaces a temporary directory in output, so a golden file is the
// same on every run, and writes the separators that follow it as slashes, so
// that a Windows run (backslashes) matches the same golden.
func maskDir(output, dir string) string {
	if os.PathSeparator == '\\' {
		// A path inside a YAML or JSON string has each backslash doubled.
		output = strings.ReplaceAll(output, strings.ReplaceAll(dir, `\`, `\\`), "<dir>")
	}
	output = strings.ReplaceAll(output, dir, "<dir>")
	if os.PathSeparator == '\\' {
		// Only the paths that began with the directory: its name was replaced, the rest of each path is a file name.
		output = regexp.MustCompile(`<dir>(\\[^\s;,)"]*)`).ReplaceAllStringFunc(output, func(m string) string {
			return strings.ReplaceAll(strings.ReplaceAll(m, `\\`, "/"), `\`, "/")
		})
		// Windows has no file modes: `check` says the environment file's mode only where it can read one, and the
		// goldens are the Linux text.
		output = strings.ReplaceAll(output, "controller.env, the ", "controller.env, mode 0600, the ")
	}
	return output
}

func TestTrustNodeWritesTheLineAfterTypedYes(t *testing.T) {
	key := fixedHostKey(t, 7)
	asked := withHostKey(t, key, nil)
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "secure", "known_hosts")

	out, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve-node-01.example.com", "--known-hosts", knownHosts)
	if err != nil {
		t.Fatalf("trust-node: %v\n%s", err, out)
	}
	if want := []string{"pve-node-01.example.com:22"}; strings.Join(*asked, ",") != strings.Join(want, ",") {
		t.Errorf("fetched %v, want %v", *asked, want)
	}
	line := nodesetup.KnownHostsLine("pve-node-01.example.com", 22, key.Key)
	if got := readIfExists(t, knownHosts); got != line+"\n" {
		t.Errorf("known_hosts = %q, want %q", got, line+"\n")
	}
	assertGolden(t, "setup_trust_node_interactive.golden", maskDir(out, dir))
	if runtime.GOOS != "windows" {
		fileInfo, _ := os.Stat(knownHosts)
		dirInfo, _ := os.Stat(filepath.Dir(knownHosts))
		if fileInfo.Mode().Perm() != 0o600 || dirInfo.Mode().Perm() != 0o700 {
			t.Errorf("file mode %04o, directory mode %04o; want 0600 and 0700", fileInfo.Mode().Perm(), dirInfo.Mode().Perm())
		}
	}
}

func TestTrustNodeWritesNothingWithoutAnExplicitYes(t *testing.T) {
	key := fixedHostKey(t, 7)
	for _, answer := range []string{"", "no\n", "y\n", "Yes\n", "YES\n", "yes please\n", "\n"} {
		withHostKey(t, key, nil)
		knownHosts := filepath.Join(t.TempDir(), "known_hosts")
		out, err := runRootWithInput(t, answer, "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts)
		if err == nil || !strings.Contains(err.Error(), "not confirmed") {
			t.Errorf("answer %q: error = %v", answer, err)
		}
		if got := readIfExists(t, knownHosts); got != "" {
			t.Errorf("answer %q: known_hosts was written: %q", answer, got)
		}
		if !strings.Contains(out, key.Fingerprint) {
			t.Errorf("answer %q: the fingerprint was not shown:\n%s", answer, out)
		}
	}
}

func TestTrustNodeAcceptsYesWithoutANewlineAtTheEndOfInput(t *testing.T) {
	withHostKey(t, fixedHostKey(t, 7), nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := runRootWithInput(t, "yes", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts); err != nil {
		t.Fatal(err)
	}
	if readIfExists(t, knownHosts) == "" {
		t.Error("a typed yes at the end of input was not accepted")
	}
}

func TestTrustNodeFingerprintTrustsWithoutAPrompt(t *testing.T) {
	key := fixedHostKey(t, 7)
	for _, extra := range [][]string{nil, {"--yes"}} {
		withHostKey(t, key, nil)
		dir := t.TempDir()
		knownHosts := filepath.Join(dir, "known_hosts")
		args := append([]string{"setup", "trust-node", "--host", "pve-node-01.example.com", "--port", "2222", "--known-hosts", knownHosts, "--fingerprint", key.Fingerprint}, extra...)
		// Standard input is empty: nothing could answer a prompt.
		out, err := runRootWithInput(t, "", args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", extra, err, out)
		}
		want := nodesetup.KnownHostsLine("pve-node-01.example.com", 2222, key.Key) + "\n"
		if got := readIfExists(t, knownHosts); got != want || !strings.HasPrefix(want, "[pve-node-01.example.com]:2222 ssh-ed25519 ") {
			t.Errorf("%v: known_hosts = %q, want %q", extra, got, want)
		}
		if strings.Contains(out, `Type "yes"`) {
			t.Errorf("%v: prompted although the fingerprint was given:\n%s", extra, out)
		}
		if len(extra) == 0 {
			assertGolden(t, "setup_trust_node_fingerprint.golden", maskDir(out, dir))
		}
	}
}

func TestTrustNodeRefusesAFingerprintThatDoesNotMatch(t *testing.T) {
	key, other := fixedHostKey(t, 7), fixedHostKey(t, 8)
	withHostKey(t, key, nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	for _, extra := range [][]string{nil, {"--yes"}} {
		out, err := runRootWithInput(t, "yes\n", append([]string{"setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts, "--fingerprint", other.Fingerprint}, extra...)...)
		if err == nil || !strings.Contains(err.Error(), "not the "+other.Fingerprint+" you expected") || !strings.Contains(err.Error(), "nothing was written") {
			t.Fatalf("%v: error = %v", extra, err)
		}
		if got := readIfExists(t, knownHosts); got != "" {
			t.Errorf("%v: a key that did not match the fingerprint was written: %q", extra, got)
		}
		if strings.Contains(out, "will be written") || strings.Contains(out, `Type "yes"`) {
			t.Errorf("%v: offered to write a key that did not match:\n%s", extra, out)
		}
	}
}

// A fingerprint of another key type (the node's ECDSA one, say) must not read as
// an attack alone: the refusal says the command compares only the ED25519 host
// key and how to read that one (hardening F, CR1-03).
func TestTrustNodeMismatchSaysOnlyTheED25519KeyIsCompared(t *testing.T) {
	key, other := fixedHostKey(t, 7), fixedHostKey(t, 8)
	withHostKey(t, key, nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	_, err := runRootWithInput(t, "", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts, "--fingerprint", other.Fingerprint)
	if err == nil {
		t.Fatal("a fingerprint that does not match the offered key was accepted")
	}
	for _, want := range []string{
		"only the ED25519 host key",
		"ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub",
		// The safety wording stays.
		"nothing was written",
		"otherwise something other than the node is answering",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

// --yes is never enough to trust a key nobody has compared: it is refused
// before the node is contacted.
func TestTrustNodeYesAloneNeverTrustsAnUnseenKey(t *testing.T) {
	asked := withHostKey(t, fixedHostKey(t, 7), nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	_, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--yes does not trust a key by itself") {
		t.Fatalf("error = %v", err)
	}
	if len(*asked) != 0 {
		t.Errorf("the node was contacted: %v", *asked)
	}
	if got := readIfExists(t, knownHosts); got != "" {
		t.Errorf("known_hosts was written: %q", got)
	}
}

func TestTrustNodeRefusesABadFingerprintFormat(t *testing.T) {
	asked := withHostKey(t, fixedHostKey(t, 7), nil)
	for _, bad := range []string{"aa:bb:cc", "SHA256:short", "MD5:aa:bb", strings.Repeat("A", 43), "SHA256:" + strings.Repeat("A", 43) + "="} {
		_, err := runRootWithInput(t, "", "setup", "trust-node", "--host", "pve.example", "--known-hosts", filepath.Join(t.TempDir(), "k"), "--fingerprint", bad)
		if err == nil || !strings.Contains(err.Error(), "is not an SHA-256 fingerprint") {
			t.Errorf("%q: error = %v", bad, err)
		}
	}
	if len(*asked) != 0 {
		t.Errorf("the node was contacted for a malformed fingerprint: %v", *asked)
	}
}

func TestTrustNodeLeavesAnAlreadyTrustedHostAlone(t *testing.T) {
	key := fixedHostKey(t, 7)
	asked := withHostKey(t, key, nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	existing := "# mine\n" + nodesetup.KnownHostsLine("pve.example", 22, key.Key) + "\n"
	if err := os.WriteFile(knownHosts, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	// No input: it must not ask.
	out, err := runRootWithInput(t, "", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "already holds exactly this key") || strings.Contains(out, "Type \"yes\"") {
		t.Errorf("output:\n%s", out)
	}
	if got := readIfExists(t, knownHosts); got != existing {
		t.Errorf("known_hosts changed: %q", got)
	}
	if len(*asked) != 1 {
		t.Errorf("asked %v", *asked)
	}
}

func TestTrustNodeNeverOverwritesAChangedHostKey(t *testing.T) {
	old, now := fixedHostKey(t, 7), fixedHostKey(t, 8)
	withHostKey(t, now, nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	existing := nodesetup.KnownHostsLine("pve.example", 22, old.Key) + "\n"
	if err := os.WriteFile(knownHosts, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	// Even with the matching fingerprint and --yes.
	_, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts, "--fingerprint", now.Fingerprint, "--yes")
	if err == nil || !strings.Contains(err.Error(), "already holds a different ED25519 key") || !strings.Contains(err.Error(), old.Fingerprint) || !strings.Contains(err.Error(), "ssh-keygen -R pve.example -f "+knownHosts) {
		t.Fatalf("error = %v", err)
	}
	if got := readIfExists(t, knownHosts); got != existing {
		t.Errorf("known_hosts changed: %q", got)
	}
}

func TestTrustNodeKeepsEarlierLinesAndOtherHosts(t *testing.T) {
	key, other := fixedHostKey(t, 7), fixedHostKey(t, 9)
	withHostKey(t, key, nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	existing := nodesetup.KnownHostsLine("other.example", 22, other.Key) // no trailing newline
	if err := os.WriteFile(knownHosts, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts); err != nil {
		t.Fatal(err)
	}
	want := existing + "\n" + nodesetup.KnownHostsLine("pve.example", 22, key.Key) + "\n"
	if got := readIfExists(t, knownHosts); got != want {
		t.Errorf("known_hosts = %q, want %q", got, want)
	}
}

func TestTrustNodeDefaultsToTheEnvironmentsKnownHostsFile(t *testing.T) {
	key := fixedHostKey(t, 7)
	withHostKey(t, key, nil)
	target := filepath.Join(t.TempDir(), "from-env", "known_hosts")
	t.Setenv("CERTISTACK_SSH_KNOWN_HOSTS", target)
	if _, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example"); err != nil {
		t.Fatal(err)
	}
	if readIfExists(t, target) == "" {
		t.Error("CERTISTACK_SSH_KNOWN_HOSTS was not the default")
	}
	// A flag beats the environment.
	flagged := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", flagged); err != nil {
		t.Fatal(err)
	}
	if readIfExists(t, flagged) == "" {
		t.Error("--known-hosts did not beat the environment")
	}
	// The documented default when neither is set.
	command := setupTrustNodeCmd()
	if !strings.Contains(command.Long, defaultSetupKnownHosts) || defaultSetupKnownHosts != "/secure/certistack/known_hosts" {
		t.Errorf("the default path %q is not documented in the help", defaultSetupKnownHosts)
	}
}

func TestTrustNodeReportsAnUnreachableNode(t *testing.T) {
	withHostKey(t, nodesetup.HostKey{}, errors.New("connect to pve.example:22: connection refused"))
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	_, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", knownHosts)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %v", err)
	}
	if readIfExists(t, knownHosts) != "" {
		t.Error("known_hosts was written")
	}
}

func TestTrustNodeValidatesItsFlags(t *testing.T) {
	asked := withHostKey(t, fixedHostKey(t, 7), nil)
	for _, args := range [][]string{
		{"setup", "trust-node"},
		{"setup", "trust-node", "--host", "a,b"},
		{"setup", "trust-node", "--host", "root@pve"},
		{"setup", "trust-node", "--host", "pve", "--port", "0"},
		{"setup", "trust-node", "--host", "pve", "--port", "70000"},
		{"setup", "trust-node", "--host", "pve", "--known-hosts", ""},
		{"setup", "trust-node", "--host", "pve", "extra"},
	} {
		if _, err := runRootWithInput(t, "yes\n", args...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	if len(*asked) != 0 {
		t.Errorf("a node was contacted for refused flags: %v", *asked)
	}
}

// An interrupt while the prompt waits ends the command: it is not stuck on a
// terminal read.
func TestTrustNodeEndsWhenInterruptedAtThePrompt(t *testing.T) {
	withHostKey(t, fixedHostKey(t, 7), nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	reader, writer := newBlockedInput()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runTrustNode(ctx, &out, reader, trustNodeRequest{Host: "pve.example", Port: 22, KnownHosts: knownHosts})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want an interruption", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trust-node stayed on the prompt after an interrupt")
	}
	if readIfExists(t, knownHosts) != "" {
		t.Error("known_hosts was written")
	}
}

func TestSetupHelpNamesTheThreeHelpers(t *testing.T) {
	out, err := runRootWithInput(t, "", "setup", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"trust-node", "pve-ca", "rbac"} {
		if !strings.Contains(out, want) {
			t.Errorf("setup --help does not list %q:\n%s", want, out)
		}
	}
	help, err := runRootWithInput(t, "", "setup", "trust-node", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--host", "--port", "--known-hosts", "--fingerprint", "--yes", "never trusts a key by itself"} {
		if !strings.Contains(help, want) {
			t.Errorf("setup trust-node --help does not mention %q", want)
		}
	}
}
