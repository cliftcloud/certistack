// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func planWithSandbox(t *testing.T, checks *SandboxChecks) *RunPlan {
	t.Helper()
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	o.opts.Sandbox = checks
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func stepOf(p *RunPlan, kind string) *PlanStep {
	for i := range p.Steps {
		if p.Steps[i].Kind == kind {
			return &p.Steps[i]
		}
	}
	return nil
}

// Both sandbox checks are the plan's first steps, before anything that reads
// the node or PVE, and a plan that passes them is the plan it was.
func TestPlanListsTheSandboxChecksFirst(t *testing.T) {
	p := planWithSandbox(t, &SandboxChecks{
		Range:   func(context.Context) error { return nil },
		Network: func(context.Context) (string, error) { return "", nil },
	})
	if len(p.Refusals) > 0 {
		t.Fatalf("refusals: %v", p.Refusals)
	}
	if len(p.Steps) < 2 || p.Steps[0].Kind != "sandbox-range" || p.Steps[1].Kind != "sandbox-network" {
		t.Fatalf("first steps = %+v", p.Steps[:min(2, len(p.Steps))])
	}
	for _, step := range p.Steps[:2] {
		if step.Action != PlanCheck || step.Status != StatusOK || step.Target != "10.100.0.0/24" || step.Phase != "checks" {
			t.Errorf("step = %+v, want an ok check of 10.100.0.0/24", step)
		}
	}
	if stepOf(p, "sdn-zone") == nil {
		t.Error("the run's own steps are missing after the checks")
	}
}

// A range that holds the PVE API or the PBS server: the check fails, says why,
// and the steps after it are not reached, as a run stops before it creates
// anything.
func TestPlanRefusesARangeHoldingAServerTheRunNeeds(t *testing.T) {
	const refusal = "network.ip_range 10.100.0.0/24 contains the PBS server (10.100.0.5). Choose a network.ip_range that does not contain the PVE API or the PBS server"
	p := planWithSandbox(t, &SandboxChecks{
		Range:   func(context.Context) error { return errors.New(refusal) },
		Network: func(context.Context) (string, error) { return "", nil },
	})
	step := stepOf(p, "sandbox-range")
	if step == nil || step.Action != PlanCheck || step.Status != StatusFailed || !strings.Contains(step.Detail, refusal) {
		t.Fatalf("sandbox-range step = %+v", step)
	}
	if len(p.Refusals) != 1 || p.Refusals[0] != refusal {
		t.Errorf("refusals = %v, want only the range's", p.Refusals)
	}
	for _, later := range []string{"sdn-zone", "sdn-subnet", "host-address", "pve-vm"} {
		step := stepOf(p, later)
		if step == nil {
			t.Errorf("no %s step", later)
		} else if step.Action != PlanDelete && step.Action != PlanKeep && step.Status != StatusNotReached {
			t.Errorf("%s step has status %q, want %q", later, step.Status, StatusNotReached)
		}
	}
}

// A range over the node's own networks: the same.
func TestPlanRefusesARangeOverlappingTheNodesNetworks(t *testing.T) {
	const refusal = "network.ip_range 10.100.0.0/24 overlaps the node's real network 10.100.0.0/24 (on interface vmbr4): once the probe address is on the sandbox bridge, the node would route 10.100.0.0/24's traffic into the sandbox."
	p := planWithSandbox(t, &SandboxChecks{
		Range:   func(context.Context) error { return nil },
		Network: func(context.Context) (string, error) { return "", errors.New(refusal) },
	})
	step := stepOf(p, "sandbox-network")
	if step == nil || step.Status != StatusFailed || !strings.Contains(step.Detail, refusal) {
		t.Fatalf("sandbox-network step = %+v", step)
	}
	if got := stepOf(p, "sandbox-range"); got == nil || got.Status != StatusOK {
		t.Errorf("sandbox-range step = %+v, want ok", got)
	}
	if len(p.Refusals) != 1 || p.Refusals[0] != refusal {
		t.Errorf("refusals = %v", p.Refusals)
	}
	if zone := stepOf(p, "sdn-zone"); zone == nil || zone.Status != StatusNotReached {
		t.Errorf("sdn-zone step = %+v, want not reached", zone)
	}
}

// Both refusals are listed: planning goes on past a refusal, so an operator
// fixes the range once.
func TestPlanListsBothSandboxRefusals(t *testing.T) {
	p := planWithSandbox(t, &SandboxChecks{
		Range:   func(context.Context) error { return errors.New("range refusal") },
		Network: func(context.Context) (string, error) { return "", errors.New("network refusal") },
	})
	if len(p.Refusals) != 2 || p.Refusals[0] != "range refusal" || p.Refusals[1] != "network refusal" {
		t.Fatalf("refusals = %v", p.Refusals)
	}
}

// Routes the node would not give are not a pass and not a refusal: the step
// says so, with a warning, and the plan goes on.
func TestPlanWarnsWhenTheNodesRoutesCannotBeRead(t *testing.T) {
	const warning = "could not check the node's routes (open /proc/net/route: permission denied): network.ip_range 10.100.0.0/24 was not compared with the networks the node really uses."
	p := planWithSandbox(t, &SandboxChecks{
		Network: func(context.Context) (string, error) { return warning, nil },
	})
	step := stepOf(p, "sandbox-network")
	if step == nil || step.Status != StatusWarning || !strings.Contains(step.Detail, "could not check the node's routes") {
		t.Fatalf("sandbox-network step = %+v", step)
	}
	if len(p.Refusals) != 0 {
		t.Errorf("refusals = %v", p.Refusals)
	}
	found := false
	for _, w := range p.Warnings {
		found = found || strings.Contains(w, "could not check the node's routes")
	}
	if !found {
		t.Errorf("warnings = %v", p.Warnings)
	}
	if zone := stepOf(p, "sdn-zone"); zone == nil || zone.Status == StatusNotReached {
		t.Errorf("a warning stopped the plan: sdn-zone step = %+v", zone)
	}
}

// Without checks there is nothing to list.
func TestPlanWithoutSandboxChecksListsNone(t *testing.T) {
	p := planWithSandbox(t, nil)
	if stepOf(p, "sandbox-range") != nil || stepOf(p, "sandbox-network") != nil {
		t.Fatalf("steps = %+v", p.Steps)
	}
}
