// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A caller that embeds the engine (the Enterprise daemon) holds a plan to limits that depend on what
// the plan finally says. A plan that inherits its backup's hardware says nothing about cores,
// sockets or CPU weight until the backups are read, so the limits have to be judged after that:
// Options.CheckResolvedPlan is called with the plan as the engine will run it, before anything is
// created, and a refusal stops the run (or the preview) there.

func resolvedPlanFixture() *config.Plan {
	return &config.Plan{PlanID: "resolved-check", Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Tiers:            []config.Tier{{Level: 1, VMs: []config.VM{{VMID: 9001}}}},
	}
}

// inheritFromTheBackup stands in for applyBackupConfig: the engine fills what the plan left unset.
func inheritFromTheBackup(t *testing.T) {
	t.Helper()
	previousPrepare := prepareRunFn
	t.Cleanup(func() { prepareRunFn = previousPrepare })
	prepareRunFn = func(_ context.Context, p *config.Plan, _ Options, _ string) (*pve.Client, *pbs.Client, error) {
		vm := &p.Tiers[0].VMs[0]
		vm.HardwareOverrides.Cores, vm.HardwareOverrides.Sockets, vm.HardwareOverrides.CPUWeight = 64, 2, 200
		return pve.NewClient(pve.Config{}), pbs.New(pbs.Config{}), nil
	}
}

func resolvedRunOptions(root string, check func(*config.Plan) error) Options {
	return Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports"), CheckResolvedPlan: check}
}

func TestRunRefusesAPlanTheResolvedPlanCheckRejectsBeforeAnythingIsCreated(t *testing.T) {
	inheritFromTheBackup(t)
	previousOrchestrate := orchestrate
	t.Cleanup(func() { orchestrate = previousOrchestrate })
	orchestrated := false
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		orchestrated = true
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	var seen config.HardwareOverrides
	calls := 0
	root := t.TempDir()
	_, err := run(context.Background(), resolvedPlanFixture(), resolvedRunOptions(root, func(p *config.Plan) error {
		calls++
		seen = p.Tiers[0].VMs[0].HardwareOverrides
		return errors.New("the backup's 64 cores x 2 sockets is more than this node allows")
	}))
	if err == nil || !strings.Contains(err.Error(), "64 cores x 2 sockets") {
		t.Fatalf("run err = %v, want the check's refusal", err)
	}
	if calls != 1 {
		t.Fatalf("the check was called %d times, want once", calls)
	}
	if seen.Cores != 64 || seen.Sockets != 2 || seen.CPUWeight != 200 {
		t.Fatalf("the check saw %+v, want the plan after the backup's hardware was inherited", seen)
	}
	if orchestrated {
		t.Fatal("the orchestrator ran after the check refused the plan")
	}
	if _, statErr := os.Stat(filepath.Join(root, "state", "active.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a recovery journal was begun for a refused plan: %v", statErr)
	}
}

func TestRunGoesOnWhenTheResolvedPlanCheckAccepts(t *testing.T) {
	inheritFromTheBackup(t)
	previousOrchestrate := orchestrate
	t.Cleanup(func() { orchestrate = previousOrchestrate })
	orchestrated := false
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		orchestrated = true
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	calls := 0
	if _, err := run(context.Background(), resolvedPlanFixture(), resolvedRunOptions(t.TempDir(), func(*config.Plan) error { calls++; return nil })); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !orchestrated {
		t.Fatalf("check calls = %d, orchestrated = %v; want one call and a run", calls, orchestrated)
	}
}

func TestRunWithoutAResolvedPlanCheckBehavesAsBefore(t *testing.T) {
	inheritFromTheBackup(t)
	previousOrchestrate := orchestrate
	t.Cleanup(func() { orchestrate = previousOrchestrate })
	orchestrated := false
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		orchestrated = true
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	if _, err := run(context.Background(), resolvedPlanFixture(), resolvedRunOptions(t.TempDir(), nil)); err != nil {
		t.Fatalf("a run with no check failed: %v", err)
	}
	if !orchestrated {
		t.Fatal("a run with no check did not reach the orchestrator")
	}
}

func TestPlanRunRefusesAPlanTheResolvedPlanCheckRejects(t *testing.T) {
	inheritFromTheBackup(t)
	calls := 0
	runPlan, err := PlanRun(context.Background(), resolvedPlanFixture(), Options{NodeName: "pve1", CheckResolvedPlan: func(p *config.Plan) error {
		calls++
		if got := p.Tiers[0].VMs[0].HardwareOverrides.CPUWeight; got != 200 {
			t.Errorf("the check saw cpu weight %d, want the backup's 200", got)
		}
		return errors.New("cpu_weight 200 is more than 100")
	}})
	if err == nil || !strings.Contains(err.Error(), "cpu_weight 200") {
		t.Fatalf("PlanRun err = %v, want the check's refusal", err)
	}
	if runPlan != nil || calls != 1 {
		t.Fatalf("PlanRun returned a plan (%v) or called the check %d times; want no plan and one call", runPlan != nil, calls)
	}
}
