// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/pkg/controller"
)

// writeCheckedPlan is a plan that validates, in the controller's directory.
func writeCheckedPlan(t *testing.T, c controllerDir) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.dir, "my-first-plan.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// With a plan, the node's worker is given the plan's network and judges its
// range as the check's last layer; without one it is given nothing.
func TestCheckGivesTheNodesWorkerThePlansNetwork(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{}
	withNode(t, stub)
	plan := writeCheckedPlan(t, c)
	if out, err := runRootWithInput(t, "", "check", "--env-file", c.env, plan); err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if len(stub.staged) != 1 || stub.staged[0].Sandbox == nil {
		t.Fatalf("the worker was not given the plan's network: %+v", stub.staged)
	}
	network := stub.staged[0].Sandbox
	if network.IPRange != "192.0.2.0/24" || network.ProbeIP != "192.0.2.1" || network.VNetID == "" {
		t.Errorf("network = %+v, want the plan's range, probe address and VNet", network)
	}

	stub = &nodeStub{}
	withNode(t, stub)
	if _, err := runRootWithInput(t, "", "check", "--env-file", c.env); err != nil {
		t.Fatal(err)
	}
	if len(stub.staged) != 1 || stub.staged[0].Sandbox != nil {
		t.Errorf("a check without a plan gave the worker a network: %+v", stub.staged)
	}
}

// A range over a network the node uses is layer 8's failure, with the node's
// own words and what to change in the plan.
func TestCheckLayer8RefusesARangeOverTheNodesNetworks(t *testing.T) {
	c := readyController(t)
	refusal := "network.ip_range 192.0.2.0/24 overlaps the node's real network 192.0.2.0/24 (on interface vmbr4): once the probe address is on the sandbox bridge, the node would route 192.0.2.0/24's traffic into the sandbox."
	withNode(t, &nodeStub{sandbox: &nodecheck.Layer{Name: nodecheck.LayerSandbox, Status: nodecheck.StatusFailed, Code: nodecheck.CodeSandboxNetwork, Detail: refusal}})
	plan := writeCheckedPlan(t, c)
	out, _ := failsAt(t, c, plan)
	for _, want := range []string{"✓ 7. Plan", "✗ 8. Sandbox network", "overlaps the node's real network 192.0.2.0/24 (on interface vmbr4)",
		"Fix: Change network.ip_range (and network.probe_ip, which must lie inside it) in " + plan, "ip -4 route", "192.0.2.0/24", "fix layer 8 (Sandbox network)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckLayer8RefusesARangeHoldingAServerTheRunNeeds(t *testing.T) {
	c := readyController(t)
	withNode(t, &nodeStub{sandbox: &nodecheck.Layer{Name: nodecheck.LayerSandbox, Status: nodecheck.StatusFailed, Code: nodecheck.CodeSandboxRange,
		Detail: "network.ip_range 192.0.2.0/24 contains the PBS server (pbs.example.com, 192.0.2.9). Choose a network.ip_range that does not contain the PVE API or the PBS server"}})
	out, _ := failsAt(t, c, writeCheckedPlan(t, c))
	for _, want := range []string{"✗ 8. Sandbox network", "contains the PBS server", "PVE_URL", "PBS_REPOSITORY"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Routes the node would not give: the check passes with a warning that says the
// range was not compared, and exits zero.
func TestCheckLayer8WarnsWhenTheNodesRoutesCannotBeRead(t *testing.T) {
	c := readyController(t)
	warning := "could not check the node's routes (open /proc/net/route: permission denied): network.ip_range 192.0.2.0/24 was not compared with the networks the node really uses. Before you run, list them with `ip -4 route` on the node and confirm that none overlaps 192.0.2.0/24."
	withNode(t, &nodeStub{sandbox: &nodecheck.Layer{Name: nodecheck.LayerSandbox, Status: nodecheck.StatusUnchecked, Detail: warning}})
	out, err := runRootWithInput(t, "", "check", "--env-file", c.env, writeCheckedPlan(t, c))
	if err != nil {
		t.Fatalf("an unchecked layer failed the check: %v\n%s", err, out)
	}
	for _, want := range []string{"! 8. Sandbox network", "could not check the node's routes", "Every layer passed, but layer 8 (Sandbox network) could not be checked", "Now run: certistack plan"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✓ 8.") {
		t.Errorf("an unchecked layer was shown as passed:\n%s", out)
	}
}

// A plan that does not validate cannot have its network judged, and would be
// refused by plan: layer 8 says so and points at validate.
func TestCheckLayer8RefusesAPlanThatDoesNotValidate(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{}
	withNode(t, stub)
	plan := filepath.Join(c.dir, "bad-plan.yaml")
	if err := os.WriteFile(plan, []byte("plan_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := failsAt(t, c, plan)
	for _, want := range []string{"✓ 7. Plan", "✗ 8. Sandbox network", "the plan does not validate", "certistack validate " + plan} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// Layers 4 to 6 were still tried: the node's worker does not need a plan.
	if len(stub.staged) != 1 || stub.staged[0].Sandbox != nil {
		t.Errorf("worker options = %+v", stub.staged)
	}
}

// A worker that gives no verdict on a network it was given is not a pass.
func TestCheckLayer8RefusesAWorkerThatDidNotJudgeTheNetwork(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{}
	withNode(t, stub)
	checkOnNode = func(_ context.Context, opts controller.RunOptions, _ string) ([]byte, error) {
		return json.Marshal(passingReport()) // three layers, none for the sandbox
	}
	out, _ := failsAt(t, c, writeCheckedPlan(t, c))
	if !strings.Contains(out, "✗ 8. Sandbox network") || !strings.Contains(out, "did not report this layer") {
		t.Errorf("output:\n%s", out)
	}
}

// An earlier layer that fails lists layer 8 as not checked.
func TestCheckListsLayer8AsNotCheckedAfterAnEarlierFailure(t *testing.T) {
	c := readyController(t)
	report := passingReport()
	report.Layers[1] = nodecheck.Layer{Name: nodecheck.LayerPVE, Status: nodecheck.StatusFailed, Code: nodecheck.CodePVEAuth, Detail: "PVE answered but rejected the token (HTTP 401)"}
	withNode(t, &nodeStub{report: report})
	out, _ := failsAt(t, c, writeCheckedPlan(t, c))
	if !strings.Contains(out, "- 7. Plan") || !strings.Contains(out, "- 8. Sandbox network") || !strings.Contains(out, "not checked: an earlier layer failed") {
		t.Errorf("output:\n%s", out)
	}
}
