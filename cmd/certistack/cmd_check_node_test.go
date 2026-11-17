// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodesetup"
)

// Layer 3 is the SSH connection, and the node it reaches must be the node the
// environment file names: the temporary worker runs on the one and addresses
// PVE as the other, and the failure that follows is late and cryptic.
func TestCheckLayer3StopsWhenSSHReachesAnotherNodeThanTheOneNamed(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{nodeName: "pve-node-02"}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	for _, want := range []string{
		"✗ 3. SSH connection",
		"ssh to root@pve-node-01.example.com:2222 works and reaches PVE node pve-node-02, but CERTISTACK_NODE names node pve-node-01",
		"Fix: Set CERTISTACK_NODE=pve-node-02 in " + c.env + ", or point CERTISTACK_SSH_HOST at node pve-node-01.",
		"- 4. Node tools", "not checked: an earlier layer failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if len(stub.staged) != 0 {
		t.Error("a worker was staged on a node that is not the one named")
	}
}

func TestCheckLayer3SaysNodeNamesAreCaseSensitive(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{nodeName: "PVE-NODE-01"}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	for _, want := range []string{"✗ 3. SSH connection", "Set CERTISTACK_NODE=PVE-NODE-01 in " + c.env, "PVE node names are case-sensitive"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckLayer3FailsClosedWhenTheNodesNameCannotBeRead(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{nodeNameError: errors.New("read the node's name: /etc/pve/local: exit status 1; host name: exit status 127")}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	for _, want := range []string{
		"✗ 3. SSH connection",
		"could not check which PVE node this is",
		"exit status 127",
		"Fix: ", "/etc/pve/local",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✓ 3.") || len(stub.staged) != 0 {
		t.Errorf("a check that could not be made passed:\n%s", out)
	}
}

// The name is only asked once SSH works and the node is the right architecture:
// a layer that fails earlier says its own thing.
func TestCheckAsksTheNodesNameAfterSSHWorks(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{sshError: errors.New("ssh failed: exit status 255: something new")}
	withNode(t, stub)
	failsAt(t, c)
	if stub.nameCalls != 0 {
		t.Errorf("the node's name was asked %d times although ssh failed", stub.nameCalls)
	}

	ok := readyController(t)
	stub = &nodeStub{}
	withNode(t, stub)
	if out, err := runRootWithInput(t, "", "check", "--env-file", ok.env); err != nil {
		t.Fatalf("a node that is the one named failed: %v\n%s", err, out)
	}
	if stub.nameCalls != 1 {
		t.Errorf("the node's name was asked %d times, want once", stub.nameCalls)
	}
}

// ssh looks the node up in known_hosts by exactly the spelling in
// CERTISTACK_SSH_HOST. With an address there and the node recorded under its
// name (or the reverse), layer 3 says so, with the command for the spelling the
// file uses.
func TestCheckLayer3SaysTheNodeMayBeRecordedUnderTheOtherSpelling(t *testing.T) {
	c := readyController(t)
	env, err := os.ReadFile(c.env)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(env), "CERTISTACK_SSH_HOST=pve-node-01.example.com", "CERTISTACK_SSH_HOST=192.0.2.7", 1)
	if changed == string(env) {
		t.Fatal("the host was not replaced")
	}
	if err := os.WriteFile(c.env, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	// Layer 2 passes: the address has a line, which is not the node's key.
	if err := os.WriteFile(c.knownHosts, []byte(nodesetup.KnownHostsLine("192.0.2.7", 2222, fixedHostKey(t, 6).Key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &nodeStub{sshError: errors.New("SSH command on 192.0.2.7: ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.")}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	for _, want := range []string{
		"✗ 3. SSH connection",
		"exactly the spelling in CERTISTACK_SSH_HOST, an IP address (192.0.2.7) here",
		"under its host name",
		"certistack setup trust-node --host 192.0.2.7 --port 2222 --known-hosts " + quotedPath(c.knownHosts),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if len(stub.staged) != 0 {
		t.Error("the node's layers were tried after SSH failed")
	}
}
