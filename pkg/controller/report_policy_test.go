// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// grantedAdmission is the admission evidence of a worker whose single check
// admitted the plan's run on a node of 1 000 000 MiB with 900 000 MiB free:
// the policy and the reservation are the plan's, and the measurements add up.
func grantedAdmission(plan *config.Plan) *attest.AdmissionEvidence {
	evidence := attest.NewAdmissionEvidence(plan)
	const total, available = 1_000_000.0, 900_000.0
	return evidence.WithEvaluation(admission.Evaluation{
		Checks: 1, Decision: admission.DecisionGranted,
		HostTotalMiB: total, HostAvailableMiB: available,
		HostRAMPercent: (total - available) / total * 100, HostIOWaitPercent: 0.5,
		ProjectedRAMPercent: (total - available + float64(evidence.RecoveryReservationMiB)) / total * 100,
	})
}

// policyOptions are the completed-worker options with the testdata plan's
// compliance block given a recovery time objective of 60 seconds, so the report
// the worker returns has an objective to state.
func policyOptions(t *testing.T) RunOptions {
	t.Helper()
	opts := completedWorkerTeardownOptions(t)
	plan, err := os.ReadFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	withObjective := strings.Replace(string(plan), "compliance:\n", "compliance:\n  rto_target_seconds: 60\n", 1)
	if withObjective == string(plan) {
		t.Fatal("test bug: the plan has no compliance block")
	}
	opts.PlanPath = filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(opts.PlanPath, []byte(withObjective), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

// The controller signs the objective and the admission evidence of the plan it
// ran, and refuses a worker's report that states another objective, other
// limits or an admission that contradicts itself.
func TestControllerSignsThePolicyTheRunWasHeldTo(t *testing.T) {
	opts := policyOptions(t)
	report := workerReportFor(t, opts)
	if report.RTOTargetSeconds == nil || *report.RTOTargetSeconds != 60 {
		t.Fatalf("test bug: the worker's report states objective %v", report.RTOTargetSeconds)
	}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("a report that states the plan's policy: %v", err)
	}
	signed := result.Report
	if signed.ReportSchemaVersion != attest.CurrentReportSchemaVersion || signed.RTOTargetSeconds == nil || *signed.RTOTargetSeconds != 60 ||
		signed.Admission == nil || signed.Admission.Evaluation == nil || signed.Admission.Evaluation.Decision != admission.DecisionGranted {
		t.Fatalf("the signed report lacks the policy: schema %s objective %v admission %+v", signed.ReportSchemaVersion, signed.RTOTargetSeconds, signed.Admission)
	}
	if !signatureVerifies(t, signed, opts.Signer) {
		t.Fatal("the signed report does not verify")
	}
}

func TestControllerRefusesAReportWhosePolicyIsNotThePlans(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"an objective the plan does not hold it to", func(r *attest.Report) { *r.RTOTargetSeconds = 600 }, "objective of 600s, and the plan's is 60s"},
		{"no objective for a plan that sets one", func(r *attest.Report) { r.RTOTargetSeconds = nil }, "records no recovery time objective, and the plan's is 60s"},
		{"a pass over its own objective", func(r *attest.Report) { r.RTOSeconds = 61 }, "over its own objective of 60.0s"},
		{"no admission policy", func(r *attest.Report) { r.Admission = nil }, "records no host admission policy"},
		{"a looser RAM limit than the plan's", func(r *attest.Report) { r.Admission.MaxHostRAMPercent = 99 }, "admission max_host_ram_percent is 99"},
		{"a looser I/O wait limit", func(r *attest.Report) { r.Admission.MaxHostIOWaitPercent = 99 }, "admission max_host_iowait_percent is 99"},
		{"another reservation", func(r *attest.Report) { r.Admission.RecoveryReservationMiB = 1 }, "admission recovery_reservation_mib is 1"},
		{"a pass no admission check let start", func(r *attest.Report) { r.Admission.Evaluation = nil }, "no admission check that let the run start"},
		{"an admission granted over its own limit", func(r *attest.Report) {
			r.Admission.Evaluation.HostRAMPercent = r.Admission.MaxHostRAMPercent + 1
		}, "admission was granted with host RAM at"},
		{"an admission refused and a pass", func(r *attest.Report) { r.Admission.Evaluation.Decision = admission.DecisionDeniedIOWait }, "decided denied_iowait, and the report records VMs or claims a pass"},
		{"a projection that does not follow", func(r *attest.Report) { r.Admission.Evaluation.ProjectedRAMPercent = 1 }, "its memory figures and reservation give"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := policyOptions(t)
			report := workerReportFor(t, opts)
			tc.mutate(report)
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the report refused for %q", err, tc.want)
			}
			if result != nil || reportsSaved(t, opts.OutputDir) != 0 {
				t.Fatalf("a refused report was signed or saved: result %+v", result)
			}
		})
	}
}

// A plan with no objective: the worker's report names none, and one that names
// an objective is not that plan's.
func TestControllerRefusesAnObjectiveThePlanDoesNotSet(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	if report.RTOTargetSeconds != nil {
		t.Fatalf("test bug: the testdata plan sets objective %v", *report.RTOTargetSeconds)
	}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatalf("a report without an objective for a plan without one: %v", err)
	}
	opts = completedWorkerTeardownOptions(t)
	report = workerReportFor(t, opts)
	objective := 60.0
	report.RTOTargetSeconds = &objective
	fake = &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "objective of 60s, and the plan sets none") {
		t.Fatalf("err = %v, want an objective the plan does not set refused", err)
	}
}
