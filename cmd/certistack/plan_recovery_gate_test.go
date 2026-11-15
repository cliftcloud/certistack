// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// plannedAsIfItReached stands in for the run's own plan on a node whose
// every check passes: a check, what the run creates, and what teardown does.
func plannedAsIfItReached(t *testing.T) {
	t.Helper()
	previous := runnerPlanRun
	t.Cleanup(func() { runnerPlanRun = previous })
	runnerPlanRun = func(_ context.Context, plan *config.Plan, opts runner.Options) (*orchestrator.RunPlan, error) {
		return &orchestrator.RunPlan{PlanID: plan.PlanID, Node: opts.NodeName, Mode: "release", Steps: []orchestrator.PlanStep{
			{Phase: "checks", Action: orchestrator.PlanCheck, Kind: "token-privileges", Target: "PVE token", Status: orchestrator.StatusOK},
			{Phase: "sandbox network", Action: orchestrator.PlanCreate, Kind: "sdn-zone", Target: "csSb01"},
			{Phase: "VM 9001 (web01)", Action: orchestrator.PlanStart, Kind: "pve-vm", Target: "VM 9001"},
			{Phase: "teardown", Action: orchestrator.PlanDelete, Kind: "pve-vm", Target: "VM 9001"},
			{Phase: "evidence", Action: orchestrator.PlanKeep, Kind: "report", Target: "report.json"},
		}}, nil
	}
}

// planCommand runs `certistack plan --json` against stateDir and returns the
// document and the command's error.
func planCommand(t *testing.T, stateDir string) (orchestrator.RunPlan, error) {
	t.Helper()
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_OVERLAY_STORAGE", "CERTISTACK_NODE"} {
		t.Setenv(name, "")
	}
	planPath := planWithScratch(t, t.TempDir(), "")
	var out bytes.Buffer
	err := runRoot(t, &out, "plan", planPath, "--node", "pve1", "--state-dir", stateDir, "--json")
	var document orchestrator.RunPlan
	if decodeErr := json.Unmarshal(out.Bytes(), &document); decodeErr != nil {
		t.Fatalf("plan --json printed no document (%v) for error %v:\n%s", decodeErr, err, out.String())
	}
	return document, err
}

func statuses(steps []orchestrator.PlanStep) []string {
	var out []string
	for _, step := range steps {
		out = append(out, step.Kind+"="+step.Status)
	}
	return out
}

// A run recovers an earlier run's journal before anything else, and stops
// when it cannot (node-run: "recover previous node worker"). The preview
// printed the unreadable journal as a step with no status, listed everything
// after it as reached, and exited zero.
func TestPlanStopsAtAJournalRecoveryCannotRead(t *testing.T) {
	plannedAsIfItReached(t)
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "active.json"), []byte("{this is not a journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := planCommand(t, stateDir)
	if err == nil || exitCodeForError(err) != exitCodeValidationFailed {
		t.Fatalf("plan error = %v (exit %d), want the validation-failed exit a refused run gets", err, exitCodeForError(err))
	}
	if len(document.Refusals) == 0 || !strings.Contains(document.Refusals[0], filepath.Join(stateDir, "active.json")) || !strings.Contains(document.Refusals[0], "cannot be read") {
		t.Fatalf("refusals = %q, want the unreadable journal first", document.Refusals)
	}
	if len(document.Steps) == 0 || document.Steps[0].Kind != "journal" || document.Steps[0].Status != orchestrator.StatusFailed {
		t.Fatalf("steps = %v, want the journal step failed and first", statuses(document.Steps))
	}
	for _, step := range document.Steps[1:] {
		if step.Status != orchestrator.StatusNotReached {
			t.Errorf("step %s %s %q is %q, want not reached after recovery stops the run", step.Action, step.Kind, step.Target, step.Status)
		}
	}
	var printed bytes.Buffer
	writePlan(&printed, &document)
	if !strings.Contains(printed.String(), "✗") || !strings.Contains(printed.String(), "A run would refuse this plan") || !strings.Contains(printed.String(), "[not reached]") {
		t.Errorf("plan output does not show the stop:\n%s", printed.String())
	}
}

// An allocation recovery cannot settle (not a host address, not an SDN
// object) stops the run for an operator: "cannot safely reconcile unconfirmed
// allocation". Recovery does what it can first, so what it removes is listed
// as reached, then the stop, then nothing.
func TestPlanStopsAtAnAllocationThatNeedsAnOperator(t *testing.T) {
	plannedAsIfItReached(t)
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-old", Phase: "running", VMs: []journal.TrackedVM{{VMID: 9001, Node: "pve1"}}, AllocationPending: "VM 9123 creation"}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	document, err := planCommand(t, stateDir)
	if err == nil || exitCodeForError(err) != exitCodeValidationFailed {
		t.Fatalf("plan error = %v (exit %d), want the validation-failed exit", err, exitCodeForError(err))
	}
	if len(document.Refusals) == 0 || !strings.Contains(document.Refusals[0], "unconfirmed allocation") || !strings.Contains(document.Refusals[0], "VM 9123 creation") {
		t.Fatalf("refusals = %q, want the allocation first", document.Refusals)
	}
	var sawStop bool
	for _, step := range document.Steps {
		switch {
		case step.Kind == "pve-vm" && step.Phase == "before the run":
			if step.Status != "" {
				t.Errorf("what recovery removes first is %q, want it reached", step.Status)
			}
		case step.Kind == "journal" && step.Target == "VM 9123 creation":
			sawStop = true
			if step.Status != orchestrator.StatusFailed {
				t.Errorf("the allocation step is %q, want failed", step.Status)
			}
		case step.Phase != "before the run":
			if step.Status != orchestrator.StatusNotReached {
				t.Errorf("step %s %s %q is %q, want not reached", step.Action, step.Kind, step.Target, step.Status)
			}
		}
	}
	if !sawStop {
		t.Fatalf("no step for the allocation: %v", statuses(document.Steps))
	}
}

// The controls: a journal recovery can settle, or none, leaves the run's own
// plan as it was worked out, and the command succeeds.
func TestPlanIsNotStoppedByARecoverableJournal(t *testing.T) {
	for name, record := range map[string]*journal.Record{
		"no journal":   nil,
		"clean":        {RunID: "run-old", Phase: "cleaned"},
		"interrupted":  {RunID: "run-old", Phase: "running", VMs: []journal.TrackedVM{{VMID: 9001, Node: "pve1"}}},
		"host address": {RunID: "run-old", Phase: "running", AllocationPending: journal.HostAddressPending("10.100.0.1/24", "csVn01")},
	} {
		t.Run(name, func(t *testing.T) {
			plannedAsIfItReached(t)
			stateDir := t.TempDir()
			if record != nil {
				if err := journal.Write(filepath.Join(stateDir, "active.json"), *record); err != nil {
					t.Fatal(err)
				}
			}
			document, err := planCommand(t, stateDir)
			if err != nil || len(document.Refusals) != 0 {
				t.Fatalf("plan error = %v, refusals = %q; want a plan that a run would carry out", err, document.Refusals)
			}
			for _, step := range document.Steps {
				if step.Status == orchestrator.StatusFailed || step.Status == orchestrator.StatusNotReached {
					t.Errorf("step %s %s %q is %q", step.Action, step.Kind, step.Target, step.Status)
				}
			}
		})
	}
}

// A plan the run cannot even work out (its own refusal) still says what stops
// the run first when recovery does.
func TestPlanThatCannotBeWorkedOutStillNamesTheRecoveryStop(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "active.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	runPlan, err := computePlan(cmd, &config.Plan{PlanID: "invalid"}, "pve1", t.TempDir(), stateDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runPlan.Refusals) < 2 || !strings.Contains(runPlan.Refusals[0], "cannot be read") {
		t.Fatalf("refusals = %q, want the recovery stop first and the plan's own refusal after it", runPlan.Refusals)
	}
}

// The plan checks a recorded VM's markers against the run that recorded it,
// on the node it recorded it on, before it counts the ID as freed; and the
// step that says recovery deletes the VM says it does so only on those markers.
func TestPlanBeforeNamesTheRunAndNodeOfEachRecordedVM(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-old", Phase: "running", VMs: []journal.TrackedVM{{VMID: 9001, Node: "pve1"}, {VMID: 9002, Node: "pve2"}}}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	steps, recovered, stops := planBeforeChecked(stateDir, "", time.Now())
	if len(stops) != 0 || recovered.RunID != "run-old" || recovered.VMNodes[9001] != "pve1" || recovered.VMNodes[9002] != "pve2" {
		t.Fatalf("recovered = %+v, stops = %q", recovered, stops)
	}
	for _, step := range steps {
		if step.Kind == "pve-vm" && !strings.Contains(step.Detail, "only while it still carries this run's ownership markers") {
			t.Errorf("step %+v does not say recovery destroys the VM only on its markers", step)
		}
	}
}
