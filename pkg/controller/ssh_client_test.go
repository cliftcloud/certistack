// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A worker runs under sudo or as a transient service, neither of
// which keeps SSH_CONNECTION, so the controller reads the address its session
// reaches the node from, in the session itself, and gives it to node-check,
// node-plan and node-run. The sandbox range may not hold it: the node would send
// the replies of the SSH connection into the sandbox.

func sshConnectionHook(answer string, queries *[]string) func(name, joined string) ([]byte, error, bool) {
	return func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "SSH_CONNECTION") {
			*queries = append(*queries, joined)
			return []byte(answer), nil, true
		}
		if name == "ssh" && strings.Contains(joined, "'node-check'") {
			return []byte(`{"layers":[]}`), nil, true
		}
		return nil, nil, false
	}
}

func TestCheckGivesTheWorkerTheAddressTheSessionReachesTheNodeFrom(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	cfg := nodeAccessConfig(t)
	cfg.UseSudo = true
	network := &config.Network{IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1", VNetID: "csVnet1"}
	for _, tc := range []struct {
		name, answer string
		want         string // the value of --ssh-client, or "" for no flag
	}{
		{"an IPv4 client", "203.0.113.7 51234 192.0.2.10 22\n", "203.0.113.7"},
		{"a mapped IPv4 client", "::ffff:203.0.113.7 51234 192.0.2.10 22", "203.0.113.7"},
		{"an IPv6 client is not a sandbox's business", "2001:db8::7 51234 2001:db8::10 22", ""},
		{"no SSH_CONNECTION", "", ""},
		{"garbage", "$(reboot) 1 2 3", ""},
		{"a loopback client", "127.0.0.1 51234 127.0.0.1 22", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			fake := &fakeCommandRunner{hook: sshConnectionHook(tc.answer, &queries)}
			if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg, Sandbox: network}, ""); err != nil {
				t.Fatal(err)
			}
			if len(queries) != 1 {
				t.Fatalf("the controller asked for SSH_CONNECTION %d times: %v", len(queries), queries)
			}
			// It asks in the SSH session itself: sudo would drop the variable.
			if strings.Contains(queries[0], "sudo") {
				t.Errorf("the query runs under sudo: %s", queries[0])
			}
			var command string
			for _, call := range fake.calls {
				if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-check'") {
					command = joined
				}
			}
			flag := "'--ssh-client' '" + tc.want + "'"
			switch {
			case tc.want == "" && strings.Contains(command, "--ssh-client"):
				t.Errorf("node-check was given an SSH client for %q: %s", tc.answer, command)
			case tc.want != "" && !strings.Contains(command, flag):
				t.Errorf("node-check lacks %s: %s", flag, command)
			}
		})
	}
	// A check with no plan has no sandbox to judge and asks nothing.
	var queries []string
	fake := &fakeCommandRunner{hook: sshConnectionHook("203.0.113.7 1 2 3", &queries)}
	if _, err := (&Executor{runner: fake}).Check(context.Background(), RunOptions{NodeName: "pve-01", SSH: cfg}, ""); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 0 {
		t.Errorf("a check without a plan asked for the SSH client: %v", queries)
	}
}

func TestPlanGivesTheWorkerTheAddressTheSessionReachesTheNodeFrom(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absPlan, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var queries []string
	fake := &fakeCommandRunner{
		nodePlanOutput: `{"plan_id":"acme-erp-full-stack-dr","node":"pve-01","steps":[]}`,
		hook: func(name, joined string) ([]byte, error, bool) {
			if name == "ssh" && strings.Contains(joined, "SSH_CONNECTION") {
				queries = append(queries, joined)
				return []byte("203.0.113.7 51234 192.0.2.10 22\n"), nil, true
			}
			return nil, nil, false
		},
	}
	if _, err := (&Executor{runner: fake}).Plan(context.Background(), RunOptions{
		PlanPath:       absPlan,
		NodeName:       "pve-01",
		StateDir:       "/var/lib/certistack",
		OverlayStorage: "certistack-scratch",
		SSH:            SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	}); err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var planCall string
	for _, call := range fake.calls {
		if joined := strings.Join(call.args, " "); strings.Contains(joined, "'node-plan'") {
			planCall = joined
		}
	}
	if len(queries) != 1 || !strings.Contains(planCall, "'--ssh-client' '203.0.113.7'") {
		t.Errorf("queries %v; node-plan command: %s", queries, planCall)
	}
}

// The run itself (not only the command builder) reads the address its session
// reaches the node from and puts it on the worker's command line: in the
// supervisor script the worker is started by, as the other words of node-run are.
func TestRunGivesTheWorkerTheAddressTheSessionReachesTheNodeFrom(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var queries []string
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: workerReportFor(t, opts)},
		journalPhase: "cleaned",
		hook: func(name, joined string) ([]byte, error, bool) {
			if name == "ssh" && strings.Contains(joined, "SSH_CONNECTION") {
				queries = append(queries, joined)
				return []byte("203.0.113.7 51234 192.0.2.10 22\n"), nil, true
			}
			return nil, nil, false
		},
	}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 {
		t.Fatalf("the run asked for SSH_CONNECTION %d times: %v", len(queries), queries)
	}
	var nodeRun string
	for _, call := range fake.calls {
		if joined := strings.Join(call.args, " "); strings.Contains(joined, "node-run") && strings.Contains(joined, "--env-file") {
			nodeRun = joined
		}
	}
	if !strings.Contains(nodeRun, "--ssh-client") {
		t.Errorf("the worker's command line carries no --ssh-client:\n%.400s", nodeRun)
	}
	if !strings.Contains(nodeRun, "203.0.113.7") {
		t.Errorf("the worker's command line does not carry the address of the session's client:\n%.400s", nodeRun)
	}
}

// node-run's command carries the flag too; none when the client is not known.
func TestNodeRunCommandCarriesTheSSHClient(t *testing.T) {
	with := strings.Join(buildNodeRunCommand("/w", RunOptions{NodeName: "pve1", ScratchDir: "/s", StateDir: "/var/lib/certistack", sshClient: "203.0.113.7"}), " ")
	if !strings.Contains(with, "--ssh-client 203.0.113.7") {
		t.Errorf("node-run command lacks the SSH client: %s", with)
	}
	without := strings.Join(buildNodeRunCommand("/w", RunOptions{NodeName: "pve1", ScratchDir: "/s", StateDir: "/var/lib/certistack"}), " ")
	if strings.Contains(without, "--ssh-client") {
		t.Errorf("node-run command names an SSH client it does not know: %s", without)
	}
}

// The network goes to the worker with its mode and peers, so that the peers of
// a vxlan zone are judged against the range.
func TestSandboxCheckArgumentsCarryTheVXLANPeers(t *testing.T) {
	arguments, err := sandboxCheckArguments(&config.Network{Mode: "vxlan", Peers: "203.0.113.9, 198.51.100.9", IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, " ")
	for _, want := range []string{"--sandbox-mode vxlan", "--sandbox-peers 198.51.100.9,203.0.113.9"} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments lack %q: %s", want, joined)
		}
	}
	simple, err := sandboxCheckArguments(&config.Network{Mode: "simple", Peers: "203.0.113.9", IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(simple, " "), "peers") {
		t.Errorf("a simple network was given peers: %v", simple)
	}
	if _, err := sandboxCheckArguments(&config.Network{Mode: "vxlan", Peers: "not-an-ip; reboot", IPRange: "192.0.2.0/24", ProbeIP: "192.0.2.1"}); err == nil {
		t.Error("peers that are not addresses reached the worker's command line")
	}
}
