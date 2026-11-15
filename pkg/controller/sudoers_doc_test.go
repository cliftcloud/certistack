// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// documentedSudoersCommands are the commands of the sudoers rule that
// docs/manual-setup.md gives for a non-root SSH account.
func documentedSudoersCommands(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "manual-setup.md"))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "certistack ALL=(root) NOPASSWD: "
	var rules []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			rules = append(rules, strings.TrimPrefix(line, prefix))
		}
	}
	if len(rules) != 1 {
		t.Fatalf("docs/manual-setup.md has %d sudoers rule lines starting %q, want one", len(rules), prefix)
	}
	var commands []string
	for _, command := range strings.Split(rules[0], ",") {
		commands = append(commands, strings.TrimSpace(command))
	}
	return commands
}

// sudoCommand is the program an ssh call runs under sudo: the word after
// '/usr/bin/sudo' '-n' on its quoted command line.
var sudoCommand = regexp.MustCompile(`'/usr/bin/sudo' '-n' '([^']+)'`)

// The sudoers rule in the manual setup page allows every command the
// controller runs under sudo while it stages a worker, runs it, reads a file
// and removes the workspace, and lists nothing the controller does not use.
// A command added to the controller without the guide fails here, and so does
// one the guide lists after the controller stopped using it.
func TestDocumentedSudoersRuleIsTheCommandsTheControllerRunsUnderSudo(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	documented := documentedSudoersCommands(t)

	cfg := nodeAccessConfig(t)
	cfg.UseSudo = true
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'node-check'") {
			return []byte(`{"layers":[]}`), nil, true
		}
		return nil, nil, false
	}}
	executor := &Executor{runner: fake}
	if _, err := executor.Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ReadNodeFile(context.Background(), cfg, "/etc/pve/pve-root-ca.pem", 0); err != nil {
		t.Fatal(err)
	}
	// The lease is renewed on a timer, too slow for this test: one renewal.
	workspace := "/var/lib/certistack/workers/6f1c7d0e-2b0a-4c53-9a43-0d5f1a7d8c11"
	if err := executor.renewWorkerLease(context.Background(), cfg, "/var/lib/certistack/workers", workspace, workspace+"/controller.lease"); err != nil {
		t.Fatal(err)
	}

	used := map[string]bool{}
	var ran int
	for _, call := range fake.calls {
		if call.name != "ssh" {
			continue
		}
		match := sudoCommand.FindStringSubmatch(strings.Join(call.args, " "))
		if match == nil {
			continue
		}
		ran++
		covered := false
		for _, entry := range documented {
			if ok, _ := path.Match(entry, match[1]); ok {
				used[entry] = true
				covered = true
			}
		}
		if !covered {
			t.Errorf("the controller runs %s under sudo, which the sudoers rule in docs/manual-setup.md does not allow (%s)", match[1], strings.Join(documented, ", "))
		}
	}
	if ran < 6 {
		t.Fatalf("only %d command(s) ran under sudo; the test no longer exercises the controller", ran)
	}
	for _, entry := range documented {
		if !used[entry] {
			t.Errorf("the sudoers rule in docs/manual-setup.md allows %s, which the controller did not run under sudo", entry)
		}
	}
}
