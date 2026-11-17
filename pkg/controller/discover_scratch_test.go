// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// discoverCommand runs the full controller Discover path with a fake SSH
// runner and returns the node-discover command it sent.
func discoverCommand(t *testing.T, scratch string) string {
	t.Helper()
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "audit@pve!token")
	t.Setenv("PVE_TOKEN_SECRET", "audit-pve-secret")
	t.Setenv("PBS_REPOSITORY", "audit@pbs!token@pbs.example:8007:store")
	t.Setenv("PBS_PASSWORD", "audit-pbs-secret")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeCommandRunner{}
	if _, err := (&Executor{runner: fake}).Discover(context.Background(), RunOptions{
		NodeName:   "audit-node",
		ScratchDir: scratch,
		StateDir:   "/var/lib/certistack",
		SSH:        SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	}, initplan.Request{Node: "audit-node", VMIDs: []int{100}}); err != nil {
		t.Fatal(err)
	}
	var command string
	workspaceRemoved := false
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		if call.name == "ssh" && strings.Contains(joined, "'node-discover'") {
			command = joined
		}
		if call.name == "ssh" && strings.Contains(joined, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
			workspaceRemoved = true
		}
	}
	if command == "" {
		t.Fatal("the controller sent no node-discover command")
	}
	if !workspaceRemoved {
		t.Fatal("the disposable worker workspace was not removed")
	}
	return command
}

// Init's scratch directory, the chosen one or the default a run would use,
// reaches node-discover, so the worker restores each backup's configuration
// there and not into a temporary directory of its own.
func TestRemoteInitSendsItsScratchDirectoryToTheNode(t *testing.T) {
	const selected = "/mnt/scratch/selected-init-scratch"
	if command := discoverCommand(t, selected); !strings.Contains(command, "'--scratch' '"+selected+"'") {
		t.Fatalf("the selected scratch directory was not sent: %s", command)
	}
	// Left out, it is the default a run would use, checked like any other.
	if command := discoverCommand(t, ""); !strings.Contains(command, "'--scratch' '/var/lib/certistack/scratch'") {
		t.Fatalf("the default scratch directory was not sent: %s", command)
	}
	// An unsafe directory is refused before anything is staged.
	fake := &fakeCommandRunner{}
	for _, bad := range []string{"relative/scratch", "/tmp"} {
		if _, err := (&Executor{runner: fake}).Discover(context.Background(), RunOptions{NodeName: "audit-node", ScratchDir: bad, StateDir: "/var/lib/certistack", SSH: SSHConfig{Host: "pve.example", User: "root", Port: 22}}, initplan.Request{Node: "audit-node"}); err == nil {
			t.Errorf("scratch %q was accepted", bad)
		}
	}
	if len(fake.calls) != 0 {
		t.Errorf("an unsafe scratch directory reached the node: %v", fake.calls)
	}
}
