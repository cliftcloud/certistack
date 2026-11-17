//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// The known_hosts file is the controller's only trust in the node: whoever can
// write it can add a host key of their own for the node, answer as the
// worker, and make the report say whatever they like. It and the identity
// follow OpenSSH's StrictModes rule wherever they are read: no group or other
// write, and owned by the user or root (the owner half is tested in
// internal/sysutil, where an owner can be faked).
func TestSSHFilesOthersCanWriteAreRefused(t *testing.T) {
	stub := &nodeStub{}
	withNode(t, stub)
	for _, mode := range []os.FileMode{0o666, 0o620, 0o602} {
		c := readyController(t)
		if err := os.Chmod(c.knownHosts, mode); err != nil {
			t.Fatal(err)
		}
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "✗ 2. SSH files") || !strings.Contains(out, "can be written by group or other users") || !strings.Contains(out, "chmod 600 "+c.knownHosts) {
			t.Errorf("check with a known_hosts file of mode %04o:\n%s", mode, out)
		}
		cfg := controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, KnownHostsFile: c.knownHosts}
		if err := controller.ValidateSSH(cfg); err == nil || !strings.Contains(err.Error(), "chmod 600 "+c.knownHosts) {
			t.Errorf("a run's SSH check with a known_hosts file of mode %04o = %v", mode, err)
		}
	}
	if len(stub.staged) != 0 || stub.machineCalls != 0 {
		t.Fatal("check went on to the node with a known_hosts file others can write")
	}

	// The identity: ssh refuses one others can read; one others can write is
	// refused by every command too.
	c := readyController(t)
	if err := os.Chmod(c.identity, 0o620); err != nil {
		t.Fatal(err)
	}
	cfg := controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, KnownHostsFile: c.knownHosts, IdentityFile: c.identity}
	if err := controller.ValidateSSH(cfg); err == nil || !strings.Contains(err.Error(), "the SSH identity "+c.identity+" can be written by group or other users") {
		t.Errorf("a run's SSH check with an identity of mode 0620 = %v", err)
	}

	// The controls: what setup writes passes (0600), and so does 0644.
	for _, mode := range []os.FileMode{0o600, 0o644} {
		c := readyController(t)
		if err := os.Chmod(c.knownHosts, mode); err != nil {
			t.Fatal(err)
		}
		if err := controller.ValidateSSH(controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, KnownHostsFile: c.knownHosts}); err != nil {
			t.Errorf("known_hosts of mode %04o: %v", mode, err)
		}
	}
}

// setup trust-node adds a line to an existing known_hosts file: one that others
// can write is refused before the node is asked, and nothing is written.
func TestTrustNodeRefusesAKnownHostsFileOthersCanWrite(t *testing.T) {
	asked := withHostKey(t, fixedHostKey(t, 7), nil)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(knownHosts, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := runRootWithInput(t, "yes\n", "setup", "trust-node", "--host", "pve-node-01.example.com", "--known-hosts", knownHosts)
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+knownHosts) {
		t.Fatalf("trust-node with a known_hosts file others can write = %v", err)
	}
	if got := readIfExists(t, knownHosts); got != "" {
		t.Fatalf("known_hosts was written: %q", got)
	}
	if len(*asked) != 0 {
		t.Fatalf("the node was asked for its key (%v) before the file was refused", *asked)
	}
}
