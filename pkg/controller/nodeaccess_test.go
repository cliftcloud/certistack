// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func nodeAccessConfig(t *testing.T) SSHConfig {
	t.Helper()
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	identity := filepath.Join(dir, "id_ed25519")
	for _, file := range []string{knownHosts, identity} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return SSHConfig{Host: "pve.example", User: "certistack", Port: 2222, IdentityFile: identity, KnownHostsFile: knownHosts}
}

// Reading the CA uses the connection a run uses: strict host-key checking, the
// pinned known_hosts file, the identity and the port, and the path is one
// quoted argument.
func TestReadNodeFileUsesTheStrictRunConnection(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		return []byte("-----BEGIN CERTIFICATE-----\n"), nil, true
	}}
	got, err := (&Executor{runner: fake}).ReadNodeFile(context.Background(), cfg, "/etc/pve/pve-root-ca.pem", 1<<20)
	if err != nil || string(got) != "-----BEGIN CERTIFICATE-----\n" {
		t.Fatalf("ReadNodeFile = %q, %v", got, err)
	}
	if len(fake.calls) != 1 || fake.calls[0].name != "ssh" {
		t.Fatalf("calls = %+v", fake.calls)
	}
	joined := strings.Join(fake.calls[0].args, " ")
	for _, want := range []string{
		"BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=" + cfg.KnownHostsFile, "IdentitiesOnly=yes",
		"-p 2222", "-i " + cfg.IdentityFile, "certistack@pve.example", "'/usr/bin/cat' '/etc/pve/pve-root-ca.pem'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh arguments lack %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "sudo") {
		t.Errorf("sudo was used without UseSudo: %s", joined)
	}
}

func TestReadNodeFileUsesPasswordlessSudoOnlyWhenAsked(t *testing.T) {
	cfg := nodeAccessConfig(t)
	cfg.UseSudo = true
	fake := &fakeCommandRunner{hook: func(string, string) ([]byte, error, bool) { return []byte("data"), nil, true }}
	if _, err := (&Executor{runner: fake}).ReadNodeFile(context.Background(), cfg, "/etc/pve/pve-root-ca.pem", 0); err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(fake.calls[0].args, " "); !strings.Contains(joined, "'/usr/bin/sudo' '-n' '/usr/bin/cat' '/etc/pve/pve-root-ca.pem'") {
		t.Errorf("ssh arguments: %s", joined)
	}
}

// A connection that fails is not retried: the operator is told at once.
func TestReadNodeFileFailsOnceWithSSHsOwnWords(t *testing.T) {
	cfg := nodeAccessConfig(t)
	failure := errors.New("ssh failed: exit status 255: Host key verification failed.")
	fake := &fakeCommandRunner{hook: func(string, string) ([]byte, error, bool) { return nil, failure, true }}
	_, err := (&Executor{runner: fake}).ReadNodeFile(context.Background(), cfg, "/etc/pve/pve-root-ca.pem", 0)
	if err == nil || !strings.Contains(err.Error(), "Host key verification failed") || !strings.Contains(err.Error(), "SSH command on pve.example") {
		t.Fatalf("error = %v", err)
	}
	if len(fake.calls) != 1 {
		t.Errorf("ssh was run %d times, want once", len(fake.calls))
	}
}

func TestReadNodeFileRefusesWhatItShouldNot(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(string, string) ([]byte, error, bool) { return []byte(strings.Repeat("x", 100)), nil, true }}
	executor := &Executor{runner: fake}
	if _, err := executor.ReadNodeFile(context.Background(), cfg, "/etc/pve/ca.pem", 10); err == nil || !strings.Contains(err.Error(), "larger than 10 bytes") {
		t.Errorf("an oversized file: %v", err)
	}
	for _, bad := range []string{"relative.pem", "/etc/../shadow", "/etc/pve/a b\n", "/"} {
		if _, err := executor.ReadNodeFile(context.Background(), cfg, bad, 0); err == nil {
			t.Errorf("accepted path %q", bad)
		}
	}
}

func TestNodeMachineAsksUnameOnceAndTrimsTheAnswer(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(string, string) ([]byte, error, bool) { return []byte("x86_64\n"), nil, true }}
	machine, err := (&Executor{runner: fake}).NodeMachine(context.Background(), cfg)
	if err != nil || machine != "x86_64" {
		t.Fatalf("NodeMachine = %q, %v", machine, err)
	}
	if joined := strings.Join(fake.calls[0].args, " "); !strings.Contains(joined, "'/usr/bin/uname' '-m'") || !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Errorf("ssh arguments: %s", joined)
	}
}

func TestCheckArchitectureNamesTheMismatch(t *testing.T) {
	cfg := SSHConfig{Host: "pve.example"}
	own := unameMachines[runtime.GOARCH][0]
	if err := CheckArchitecture(cfg, own); err != nil {
		t.Errorf("the controller's own architecture was refused: %v", err)
	}
	err := CheckArchitecture(cfg, "riscv64")
	if err == nil || !strings.Contains(err.Error(), `reports architecture "riscv64"`) {
		t.Errorf("error = %v", err)
	}
}

// Check stages the worker as Plan does, runs node-check with the staged
// environment, returns its JSON and removes the workspace; no secret reaches a
// command line.
func TestExecutorCheckRunsNodeCheckAndRemovesTheWorkspace(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	cfg.User = "root"
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'node-check'") {
			return []byte(`{"layers":[{"name":"node_tools","status":"passed"}]}`), nil, true
		}
		return nil, nil, false
	}}
	output, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", StateDir: "/var/lib/certistack", SSH: cfg}, "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(string(output), `"node_tools"`) {
		t.Fatalf("output = %q", output)
	}
	var checkCall, removed string
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, "super-secret") {
			t.Errorf("a secret reached a command line: %s %s", call.name, joined)
		}
		if strings.Contains(joined, "'node-check'") {
			checkCall = joined
		}
		if strings.Contains(joined, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
			removed = joined
		}
	}
	for _, want := range []string{"'--env-file' '/var/lib/certistack/workers/", "/runtime.env'"} {
		if !strings.Contains(checkCall, want) {
			t.Errorf("node-check command lacks %s: %s", want, checkCall)
		}
	}
	if strings.Contains(checkCall, "node-run") || strings.Contains(checkCall, "systemd-run") {
		t.Errorf("checking started a worker run: %s", checkCall)
	}
	if strings.Contains(checkCall, "--through") {
		t.Errorf("a full check asked the worker to stop early: %s", checkCall)
	}
	if removed == "" {
		t.Error("the check's workspace was not removed")
	}
}

func TestExecutorCheckRefusesWithoutANode(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{}
	if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{SSH: cfg}, ""); err == nil || len(fake.calls) != 0 {
		t.Fatalf("error = %v, calls = %d", err, len(fake.calls))
	}
}

// A check with no PVE token yet has the worker stop after the tools: the layer
// is named on the worker's command line, and a name that could be anything else
// is refused before the node is contacted.
func TestExecutorCheckCanStopAfterALayer(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "not-set@pve!placeholder")
	t.Setenv("PVE_TOKEN_SECRET", "placeholder")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'node-check'") {
			return []byte(`{"layers":[]}`), nil, true
		}
		return nil, nil, false
	}}
	executor := &Executor{runner: fake}
	if _, err := executor.Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg}, "node_tools"); err != nil {
		t.Fatal(err)
	}
	var checkCall string
	for _, call := range fake.calls {
		if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-check'") {
			checkCall = joined
		}
	}
	if !strings.Contains(checkCall, "'--through' 'node_tools'") {
		t.Errorf("node-check command lacks --through: %s", checkCall)
	}
	calls := len(fake.calls)
	for _, bad := range []string{"node_tools; reboot", "../x", "PVE", "a b"} {
		if _, err := executor.Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg}, bad); err == nil {
			t.Errorf("accepted layer %q", bad)
		}
	}
	if len(fake.calls) != calls {
		t.Error("a refused layer name reached the node")
	}
}

// The node's PVE name is what PVE's own link, /etc/pve/local, points at
// (nodes/<name>); the host name is the answer only where there is no such link.
func TestNodeNameReadsPVEsLinkOnceOverTheStrictConnection(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'/usr/bin/readlink' '/etc/pve/local'") {
			return []byte("nodes/pve-node-01\n"), nil, true
		}
		return nil, nil, false
	}}
	name, err := (&Executor{runner: fake}).NodeName(context.Background(), cfg)
	if err != nil || name != "pve-node-01" {
		t.Fatalf("NodeName = %q, %v", name, err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("ssh was run %d times, want once", len(fake.calls))
	}
	if joined := strings.Join(fake.calls[0].args, " "); !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Errorf("ssh arguments: %s", joined)
	}
}

func TestNodeNameFallsBackToTheShortHostNameWhereThereIsNoLink(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		switch {
		case strings.Contains(joined, "'/usr/bin/readlink'"):
			return nil, errors.New("exit status 1"), true
		case strings.Contains(joined, "'/usr/bin/hostname'"):
			return []byte("pve1.example.com\n"), nil, true
		}
		return nil, nil, false
	}}
	name, err := (&Executor{runner: fake}).NodeName(context.Background(), cfg)
	if err != nil || name != "pve1" {
		t.Fatalf("NodeName = %q, %v", name, err)
	}
}

func TestNodeNameFailsClosedWhenTheNodeGivesNone(t *testing.T) {
	cfg := nodeAccessConfig(t)
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		return nil, errors.New("exit status 1"), true
	}}
	if name, err := (&Executor{runner: fake}).NodeName(context.Background(), cfg); err == nil {
		t.Fatalf("NodeName = %q with no source of a name", name)
	}
	garbage := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		return []byte("nodes/bad name\n"), nil, true
	}}
	if name, err := (&Executor{runner: garbage}).NodeName(context.Background(), cfg); err == nil {
		t.Fatalf("NodeName = %q for a link that names no node", name)
	}
}

// The staged worker is told which node the controller addresses, so that it
// refuses to run on any other: the check cannot be skipped by a controller that
// failed to look.
func TestExecutorCheckTellsTheWorkerWhichNodeItAddresses(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	cfg.User = "root"
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'node-check'") {
			return []byte(`{"layers":[]}`), nil, true
		}
		return nil, nil, false
	}}
	if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", StateDir: "/var/lib/certistack", SSH: cfg}, ""); err != nil {
		t.Fatal(err)
	}
	var checkCall string
	for _, call := range fake.calls {
		if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-check'") {
			checkCall = joined
		}
	}
	if !strings.Contains(checkCall, "'--node' 'pve-01'") {
		t.Errorf("node-check command does not name the node: %s", checkCall)
	}
}

// A check with a plan has the worker judge the plan's sandbox network: the
// range, the probe address, the VNet and the lifecycle are on the worker's
// command line, each one quoted argument, and a value that is not what that
// field holds is refused before the node is contacted.
func TestExecutorCheckGivesTheWorkerThePlansSandboxNetwork(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	newFake := func() *fakeCommandRunner {
		return &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
			if name == "ssh" && strings.Contains(joined, "'node-check'") {
				return []byte(`{"layers":[]}`), nil, true
			}
			return nil, nil, false
		}}
	}
	checkCommand := func(fake *fakeCommandRunner) string {
		for _, call := range fake.calls {
			if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-check'") {
				return joined
			}
		}
		return ""
	}

	fake := newFake()
	opts := RunOptions{NodeName: "pve-01", SSH: cfg, Sandbox: &config.Network{IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1", VNetID: "csVnet1", Lifecycle: "preprovisioned"}}
	if _, err := (&Executor{runner: fake}).Check(context.Background(), opts, ""); err != nil {
		t.Fatal(err)
	}
	command := checkCommand(fake)
	for _, want := range []string{"'--sandbox-range' '192.0.2.0/24'", "'--sandbox-probe' '192.0.2.1'", "'--sandbox-vnet' 'csVnet1'", "'--sandbox-lifecycle' 'preprovisioned'"} {
		if !strings.Contains(command, want) {
			t.Errorf("node-check command lacks %s: %s", want, command)
		}
	}

	// No plan, no flags.
	fake = newFake()
	if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg}, ""); err != nil {
		t.Fatal(err)
	}
	if command := checkCommand(fake); strings.Contains(command, "--sandbox") {
		t.Errorf("a check without a plan named a sandbox network: %s", command)
	}

	// A value that is not an address, an identifier or a lifecycle never reaches the node.
	for name, network := range map[string]config.Network{
		"range with a shell word":  {IPRange: "192.0.2.0/24; reboot", ProbeIP: "192.0.2.1", VNetID: "csVnet1"},
		"probe that is not an IP":  {IPRange: "192.0.2.0/24", ProbeIP: "$(id)", VNetID: "csVnet1"},
		"vnet with a path":         {IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1", VNetID: "../x"},
		"lifecycle that is a flag": {IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1", VNetID: "csVnet1", Lifecycle: "--env-file"},
		"range empty, probe given": {ProbeIP: "192.0.2.1"},
		"an IPv6 range":            {IPRange: "fd00::/64", ProbeIP: "fd00::1"},
		// Review R2-01: the one reader of the range refuses these spellings
		// (the pattern above only reads their shape).
		"prefix length /08":               {IPRange: "10.0.0.0/08", ProbeIP: "10.42.15.1", VNetID: "csVnet1"},
		"prefix length /024":              {IPRange: "10.42.15.0/024", ProbeIP: "10.42.15.1", VNetID: "csVnet1"},
		"range with host bits set":        {IPRange: "10.42.15.5/24", ProbeIP: "10.42.15.1", VNetID: "csVnet1"},
		"a prefix length past 32":         {IPRange: "10.42.15.0/99", ProbeIP: "10.42.15.1", VNetID: "csVnet1"},
		"probe with a leading zero octet": {IPRange: "10.42.15.0/24", ProbeIP: "10.42.15.01", VNetID: "csVnet1"},
	} {
		fake := newFake()
		network := network
		if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg, Sandbox: &network}, ""); err == nil || len(fake.calls) != 0 {
			t.Errorf("%s: error %v after %d call(s)", name, err, len(fake.calls))
		}
	}
}

// A check of a plan with no wire probe tells the worker, which then does not
// require nft; any other check does not.
func TestExecutorCheckTellsTheWorkerThePlanHasNoWireProbes(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	nodeCheck := func(opts RunOptions) string {
		fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
			if name == "ssh" && strings.Contains(joined, "'node-check'") {
				return []byte(`{"layers":[]}`), nil, true
			}
			return nil, nil, false
		}}
		opts.NodeName, opts.SSH = "pve-01", cfg
		if _, err := (&Executor{runner: fake}).Check(context.Background(), opts, ""); err != nil {
			t.Fatal(err)
		}
		for _, call := range fake.calls {
			if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-check'") {
				return joined
			}
		}
		t.Fatal("no node-check command was run")
		return ""
	}
	if command := nodeCheck(RunOptions{NoWireProbes: true}); !strings.Contains(command, "'--no-wire-probes'") {
		t.Errorf("the worker was not told the plan has no wire probe: %s", command)
	}
	network := &config.Network{IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1", VNetID: "csVnet1"}
	if command := nodeCheck(RunOptions{NoWireProbes: true, Sandbox: network}); !strings.Contains(command, "'--no-wire-probes'") || !strings.Contains(command, "'--sandbox-range'") {
		t.Errorf("a plan's network and its lack of wire probes did not both reach the worker: %s", command)
	}
	if command := nodeCheck(RunOptions{}); strings.Contains(command, "--no-wire-probes") {
		t.Errorf("a check that says nothing about the plan told the worker it has no wire probes: %s", command)
	}
}
