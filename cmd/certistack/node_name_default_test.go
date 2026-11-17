// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
)

// The node name defaults to the host's own PVE name. `plan` on the node itself
// asks PVE's link /etc/pve/local, as init and doctor do, rather than taking the
// host name up to the first dot (which is not the node's name on a host that was
// renamed after install, or whose name differs in case). node-run refuses an
// empty --node, which would pass the identity check and then run as the node
// "localhost".

func TestPlanOnTheNodeWithoutNodeAsksPVEForTheNodeName(t *testing.T) {
	onPVENode(t, "pve-real")
	previousName, previousPlan := localNodeName, computeNodePlan
	t.Cleanup(func() { localNodeName, computeNodePlan = previousName, previousPlan })
	localNodeName = func() string { return "pve-real" }
	var planned string
	computeNodePlan = func(_ *cobra.Command, _ *config.Plan, node, _, _, _, _ string) (*orchestrator.RunPlan, error) {
		planned = node
		return &orchestrator.RunPlan{PlanID: "p", Node: node, Mode: "release"}, nil
	}
	plan := filepath.Join("..", "..", "examples", "minimal-single-vm.yaml")
	if _, err := runRootWithInput(t, "", "plan", plan); err != nil {
		t.Fatal(err)
	}
	if planned != "pve-real" {
		t.Errorf("the plan was worked out for node %q, want the node PVE names for this host, pve-real (this host's name is %q)", planned, hostShortName())
	}
}

func hostShortName() string {
	host, _ := os.Hostname()
	short, _, _ := strings.Cut(host, ".")
	return short
}

func TestNodeRunRefusesAnEmptyNodeName(t *testing.T) {
	onPVENode(t, "pve-real")
	spy := spyOnNode(t)
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(plan, []byte("not a plan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRootWithInput(t, "", "node-run", "--plan", plan, "--node", "", "--env-file", writeEnvFile(t, "PVE_URL=https://pve.example:8006\n"),
		"--state-dir", filepath.Join(dir, "state"), "--scratch", filepath.Join(dir, "scratch"))
	if err == nil || !strings.Contains(err.Error(), "--node") || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want a refusal that says --node is empty", err)
	}
	if spy.lockTaken {
		t.Error("the worker went on to take the host lock with no node name")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "state")); statErr == nil {
		t.Error("the worker created its state directory with no node name")
	}
}
