// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The workers a controller starts run under sudo or as a
// transient service, and neither keeps SSH_CONNECTION, so the controller reads
// the address its session reaches the node from and gives it to the worker with
// --ssh-client. The worker's sandbox check then refuses a range that holds it.

func TestNodeCommandsTakeTheSSHClientTheControllerReads(t *testing.T) {
	t.Cleanup(func() { preflight.SetSSHClient("") })
	onPVENode(t, "pve1")
	spyOnNode(t)
	for _, command := range nodeSideCommands() {
		switch command.name {
		case "node-run", "node-plan", "node-check":
		default:
			continue
		}
		t.Run(command.name, func(t *testing.T) {
			preflight.SetSSHClient("")
			t.Setenv("SSH_CONNECTION", "")
			args := append(command.args(t, t.TempDir(), "pve1"), "--ssh-client", "198.51.100.7")
			_, _ = runRootWithInput(t, "", args...) // each fails or finishes in its own way after the flag is read
			if addr, ok := preflight.SSHClientAddress(); !ok || addr != netip.MustParseAddr("198.51.100.7") {
				t.Errorf("after %s --ssh-client 198.51.100.7 the worker knows %v, %v", command.name, addr, ok)
			}
		})
	}
}

// node-check judges the plan's VXLAN peers and the SSH client with the range.
func TestNodeCheckJudgesTheVXLANPeersAndTheSSHClient(t *testing.T) {
	t.Cleanup(func() { preflight.SetSSHClient("") })
	preflight.SetSSHClient("")
	t.Setenv("SSH_CONNECTION", "")
	env := filepath.Join(t.TempDir(), "runtime.env")
	body := strings.Join([]string{
		"PVE_URL=https://10.42.20.5:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=worker-secret",
		"PBS_REPOSITORY=ro@pbs!t@10.42.10.5:8007:ds",
		"PBS_PASSWORD=pbs-secret",
	}, "\n") + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nodeCheckProbes
	t.Cleanup(func() { nodeCheckProbes = previous })
	nodeCheckProbes = nodecheck.Probes{
		LookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		PVEVersion: func(context.Context, nodecheck.Settings) (string, error) { return "9.0.3", nil },
		PBSBackups: func(context.Context, nodecheck.Settings) ([]pbs.VMBackups, error) { return nil, nil },
		// What the real reader does with the SSH client: it holds the address
		// the controller told the worker.
		NodeNetworks: func() (preflight.NodeNetworks, error) {
			nodeNetworks := preflight.NodeNetworks{}
			if addr, ok := preflight.SSHClientAddress(); ok {
				nodeNetworks.Held = append(nodeNetworks.Held, preflight.HeldAddress{Address: addr, Kind: preflight.HeldSSHClient})
			}
			return nodeNetworks, nil
		},
	}
	layers := func(args ...string) nodecheck.Report {
		t.Helper()
		out, err := runRootWithInput(t, "", append([]string{"node-check", "--env-file", env}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		var report nodecheck.Report
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return report
	}
	base := []string{"--sandbox-range", "198.51.100.0/24", "--sandbox-probe", "198.51.100.250", "--sandbox-vnet", "csVnet1"}

	peers := layers(append(base, "--sandbox-mode", "vxlan", "--sandbox-peers", "203.0.113.4,198.51.100.9")...)
	if failed := peers.Failed(); failed == nil || failed.Code != nodecheck.CodeSandboxNetwork || !strings.Contains(failed.Detail, "198.51.100.9") || !strings.Contains(failed.Detail, "VXLAN peer") {
		t.Fatalf("a peer inside the range: %+v", peers)
	}
	if clean := layers(append(base, "--sandbox-mode", "vxlan", "--sandbox-peers", "203.0.113.4")...); clean.Failed() != nil {
		t.Fatalf("a peer outside the range: %+v", clean)
	}

	ssh := layers(append(base, "--ssh-client", "198.51.100.7")...)
	if failed := ssh.Failed(); failed == nil || failed.Code != nodecheck.CodeSandboxNetwork || !strings.Contains(failed.Detail, "198.51.100.7") || !strings.Contains(failed.Detail, "SSH") {
		t.Fatalf("the SSH client inside the range: %+v", ssh)
	}
	preflight.SetSSHClient("")
	if clean := layers(append(base, "--ssh-client", "203.0.113.7")...); clean.Failed() != nil {
		t.Fatalf("an SSH client outside the range: %+v", clean)
	}
}
