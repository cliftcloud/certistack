// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// indentedFences lists the fenced blocks of a Markdown text whose fences may
// be indented (as inside a numbered list), each body with its fence's indent
// removed.
func indentedFences(text string) []string {
	var blocks []string
	var body []string
	indent := ""
	open := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case open && strings.HasPrefix(trimmed, "```"):
			blocks = append(blocks, strings.Join(body, "\n")+"\n")
			open, body = false, nil
		case open:
			body = append(body, strings.TrimPrefix(line, indent))
		case strings.HasPrefix(trimmed, "```"):
			open = true
			indent = line[:len(line)-len(trimmed)]
		}
	}
	return blocks
}

// The manual alternative of step 2 of docs/manual-setup.md (formerly
// docs/getting-started.md) collected a node's
// key with `ssh-keyscan ... > known_hosts`: the redirect truncates the file, so
// adding a second node discarded the first node's approved entry, and a scan
// that failed left the file empty. The procedure scans into a temporary file,
// shows its fingerprint to compare with the node's, and only then appends
// (audit F134).
func TestGettingStartedManualHostKeyStepKeepsEarlierNodes(t *testing.T) {
	needTools(t, "mktemp", "cat", "grep")
	const hostsPath = "/secure/certistack/known_hosts"
	var scan, appendBlock string
	for _, block := range indentedFences(readRepoText(t, "docs", "manual-setup.md")) {
		switch {
		case strings.Contains(block, "ssh-keyscan"):
			scan = block
		case strings.Contains(block, ">> "+hostsPath):
			appendBlock = block
		}
	}
	if scan == "" {
		t.Fatal("manual-setup.md has no ssh-keyscan block")
	}
	if regexp.MustCompile(`[^>]>\s*` + regexp.QuoteMeta(hostsPath)).MatchString(scan) {
		t.Errorf("the ssh-keyscan block redirects into %s with >, which truncates the node entries approved before:\n%s", hostsPath, scan)
	}
	if appendBlock == "" {
		t.Fatalf("no block appends the scanned key to %s with >>", hostsPath)
	}

	const earlier = "pve-node-00.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEarlierNodeEarlierNodeEarlierNodeEarlierN\n"
	const scanned = "pve-node-01.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIScannedNodeScannedNodeScannedNodeScannedNod\n"
	run := func(t *testing.T, scanMode string, withAppend bool) (known string, out string, err error, leftover []string) {
		t.Helper()
		dir := t.TempDir()
		stubs := filepath.Join(dir, "stubs")
		tmp := filepath.Join(dir, "tmp")
		for _, d := range []string{stubs, tmp} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		hosts := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(hosts, []byte(earlier), 0o600); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, filepath.Join(stubs, "ssh-keyscan"), "#!/bin/sh\ncase \"$STUB_SCAN\" in\n  ok) printf '%s' '"+scanned+"' ;;\n  empty) exit 0 ;;\n  fail) echo 'ssh-keyscan: connect failed' >&2; exit 1 ;;\nesac\n")
		writeExecutable(t, filepath.Join(stubs, "ssh-keygen"), "#!/bin/sh\n[ \"$1\" = -lf ] || exit 64\ngrep -q ssh-ed25519 \"$2\" 2>/dev/null || { echo \"$2 is not a public key file.\" >&2; exit 255; }\necho '256 SHA256:stubfingerprint pve-node-01.example.com (ED25519)'\n")
		script := scan
		if withAppend {
			script += appendBlock
		}
		script = strings.ReplaceAll(script, hostsPath, hosts)
		out, err = runStep(t, dir, shellEnv(t, stubs, tmp, map[string]string{"STUB_SCAN": scanMode}), script)
		data, readErr := os.ReadFile(hosts)
		if readErr != nil {
			t.Fatal(readErr)
		}
		entries, _ := os.ReadDir(tmp)
		for _, e := range entries {
			leftover = append(leftover, e.Name())
		}
		return string(data), out, err, leftover
	}

	t.Run("a second node is appended after the first", func(t *testing.T) {
		known, out, err, leftover := run(t, "ok", true)
		if err != nil {
			t.Fatalf("the procedure failed: %v\n%s", err, out)
		}
		if known != earlier+scanned {
			t.Errorf("known_hosts = %q, want the earlier entry followed by the scanned one", known)
		}
		if len(leftover) != 0 {
			t.Errorf("the procedure left %v in the temporary directory", leftover)
		}
	})
	t.Run("a scan that finds no key changes nothing", func(t *testing.T) {
		known, out, err, _ := run(t, "empty", true)
		if err == nil {
			t.Errorf("an empty scan went through to the append step\n%s", out)
		}
		if known != earlier {
			t.Errorf("known_hosts = %q after an empty scan, want it unchanged", known)
		}
	})
	t.Run("a failed scan changes nothing", func(t *testing.T) {
		known, out, err, _ := run(t, "fail", true)
		if err == nil {
			t.Errorf("a failed scan went through to the append step\n%s", out)
		}
		if known != earlier {
			t.Errorf("known_hosts = %q after a failed scan, want it unchanged", known)
		}
	})
	t.Run("the scan step alone never touches known_hosts", func(t *testing.T) {
		known, out, err, _ := run(t, "ok", false)
		if err != nil {
			t.Fatalf("the scan step failed: %v\n%s", err, out)
		}
		if known != earlier {
			t.Errorf("known_hosts = %q after only the scan step, want it unchanged until the fingerprints are compared", known)
		}
	})
}
