//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// A named pipe in place of the known_hosts file or the SSH identity is refused
// before anything reads it, as a file that is not a regular file: reading it
// would wait for a writer, hanging check at layer 2 with no bound, and ssh
// waits the same way.
func TestSSHFilesThatAreNamedPipesAreRefusedAtOnce(t *testing.T) {
	stub := &nodeStub{}
	withNode(t, stub)
	c := readyController(t)
	if err := os.Remove(c.knownHosts); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(c.knownHosts, 0o600); err != nil {
		t.Skipf("cannot make a named pipe here: %v", err)
	}
	type outcome struct {
		out string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		out, err := runRootWithInput(t, "", "check", "--env-file", c.env)
		done <- outcome{out, err}
	}()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("check did not return: it waits on the named pipe at the known_hosts path")
	}
	if got.err == nil || !strings.Contains(got.out, "✗ 2. SSH files") || !strings.Contains(got.out, c.knownHosts+" is not a regular file") {
		t.Fatalf("check with a named pipe for known_hosts = %v:\n%s", got.err, got.out)
	}
	if len(stub.staged) != 0 || stub.machineCalls != 0 {
		t.Fatal("check went on to the node after refusing the SSH files")
	}

	cfg := controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, KnownHostsFile: c.knownHosts}
	if err := controller.ValidateSSH(cfg); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("a run's SSH check with a named pipe for known_hosts = %v, want a refusal", err)
	}

	// The identity, likewise.
	identity := readyController(t)
	if err := os.Remove(identity.identity); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(identity.identity, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := failsAt(t, identity)
	if !strings.Contains(out, identity.identity+" is not a regular file") {
		t.Errorf("check with a named pipe for the identity:\n%s", out)
	}
	cfg = controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, KnownHostsFile: identity.knownHosts, IdentityFile: identity.identity}
	if err := controller.ValidateSSH(cfg); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("a run's SSH check with a named pipe for the identity = %v, want a refusal", err)
	}
}
