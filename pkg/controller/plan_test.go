// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A controller's plan stages the worker as a run does, has node-plan work
// the plan out on the node, returns its JSON, and removes the workspace:
// nothing is kept, and no secret reaches a command line.
func TestExecutorPlanRunsNodePlanAndRemovesTheWorkspace(t *testing.T) {
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
	fake := &fakeCommandRunner{nodePlanOutput: `{"plan_id":"acme-erp-full-stack-dr","node":"pve-01","steps":[]}`}
	output, err := (&Executor{runner: fake}).Plan(context.Background(), RunOptions{
		PlanPath:       absPlan,
		NodeName:       "pve-01",
		StateDir:       "/var/lib/certistack",
		OverlayStorage: "certistack-scratch",
		SSH:            SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(string(output), `"plan_id":"acme-erp-full-stack-dr"`) {
		t.Fatalf("output = %q", output)
	}
	var planCall, removed string
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, "super-secret") {
			t.Errorf("a secret reached a command line: %s %s", call.name, joined)
		}
		if strings.Contains(joined, "'node-plan'") {
			planCall = joined
		}
		if strings.Contains(joined, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
			removed = joined
		}
	}
	for _, want := range []string{"'--plan' '/var/lib/certistack/workers/", "/plan.yaml'", "'--node' 'pve-01'", "'--overlay-storage' 'certistack-scratch'", "/runtime.env'"} {
		if !strings.Contains(planCall, want) {
			t.Errorf("node-plan command lacks %s: %s", want, planCall)
		}
	}
	if strings.Contains(planCall, "node-run") || strings.Contains(planCall, "systemd-run") {
		t.Errorf("planning started a worker run: %s", planCall)
	}
	if removed == "" {
		t.Error("the plan's workspace was not removed")
	}
}
