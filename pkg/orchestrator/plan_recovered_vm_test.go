// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"
)

// Recovery destroys a recorded VM only while its own markers say it is the
// unfinished run's (a replacement at a reused ID is left alone, and the run
// then meets it). The plan counts a VM as freed by recovery on the same
// evidence, and otherwise says recovery will refuse it.
func TestPlanCountsARecordedVMAsFreedOnlyWhileItIsTheUnfinishedRuns(t *testing.T) {
	defer func() { plannedVMConfig = "" }()
	const inUse = `{"vmid":9001,"type":"qemu"}`
	recorded := Recovered{VMIDs: []int{9001}, RunID: "run-old", VMNodes: map[int]string{9001: "pve1"}}
	owned := `{"tags":"certistack;run-old","description":"owner=certistack; run_id=run-old"}`
	for _, tc := range []struct {
		name      string
		config    string
		recovered Recovered
		inUse     string
		wantFree  string // the check's detail, when the VMID is counted as freed
		wantStop  string // the refusal, when it is not
	}{
		{"its own markers", owned, recorded, inUse, "recovery destroys that VM first", ""},
		{"a replacement without markers", `{"tags":"production","description":"billing database"}`, recorded, inUse, "", "does not carry the unfinished run's (run-old) ownership markers"},
		{"another run's markers", `{"tags":"certistack;run-other","description":"owner=certistack; run_id=run-other"}`, recorded, inUse, "", "does not carry the unfinished run's (run-old) ownership markers"},
		{"markers that cannot be read", "refused", recorded, inUse, "", "could not be read"},
		{"in the cluster but not on the recorded node", "missing", recorded, inUse, "", "not on node pve1"},
		{"a journal that names no run", owned, Recovered{VMIDs: []int{9001}, VMNodes: map[int]string{9001: "pve1"}}, inUse, "", "cannot be established"},
		{"a journal that names no node", owned, Recovered{VMIDs: []int{9001}, RunID: "run-old"}, inUse, "", "cannot be established"},
		// Nothing at the ID: nothing to destroy, nothing read of it.
		{"already gone", "refused", recorded, "", "unused in the cluster", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plannedVMConfig = tc.config
			o := planOrchestrator(t, planTestPlan(), planPVE(t, tc.inUse))
			o.opts.Recovered = tc.recovered
			p, err := o.Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var check *PlanStep
			for i := range p.Steps {
				if p.Steps[i].Kind == "vmid-free" {
					check = &p.Steps[i]
				}
			}
			if check == nil {
				t.Fatal("no vmid-free step in the plan")
			}
			if tc.wantStop == "" {
				if len(p.Refusals) != 0 || check.Status != StatusOK || !strings.Contains(check.Detail, tc.wantFree) {
					t.Fatalf("refusals %q, check %+v; want the VMID counted as free: %q", p.Refusals, *check, tc.wantFree)
				}
				return
			}
			if len(p.Refusals) != 1 || !strings.Contains(p.Refusals[0], tc.wantStop) || check.Status != StatusFailed || !strings.Contains(check.Detail, tc.wantStop) {
				t.Fatalf("refusals %q, check %+v; want the VM refused: %q", p.Refusals, *check, tc.wantStop)
			}
		})
	}
}
