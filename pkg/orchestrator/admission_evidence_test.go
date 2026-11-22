// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Through the real orchestrator and the node's real counters: the
// result carries the policy the run was held to and what the last admission
// check measured and decided, whether it granted the run or refused it, and a
// report built from it satisfies the rules the controller and the verifier
// hold a report to.
func TestAdmissionEvidenceOfARefusedAndOfAGrantedRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("admission reads the node's /proc counters")
	}

	// Refused: a limit no running system is under. Two checks (one retry), the
	// last one's numbers, the decision, and the limits the plan set.
	refusedPlan := networkOnlyPlan()
	refusedPlan.PlanID = "admission-evidence-refused"
	refusedPlan.AdmissionControl.MaxHostRAMPercent = 0.00001
	refusedPlan.AdmissionControl.MaxDeferRetries = 1
	refused := New(refusedPlan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()},
		pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := refused.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "admission control guardrail triggered") {
		t.Fatalf("run = %v, want the admission refusal", err)
	}
	evidence := result.Admission
	if evidence == nil || evidence.Evaluation == nil {
		t.Fatalf("a refused run records no admission evaluation: %+v", evidence)
	}
	if evidence.MaxHostRAMPercent != 0.00001 || evidence.MaxHostIOWaitPercent != 100 || evidence.MaxDeferRetries != 1 {
		t.Errorf("the evidence records limits %+v, not the plan's", evidence)
	}
	if got := evidence.Evaluation; got.Checks != 2 || got.Decision != admission.DecisionDeniedRAM || got.HostRAMPercent <= 0.00001 || got.HostRAMPercent > 100 {
		t.Errorf("evaluation = %+v, want 2 checks refused for RAM with the use the node had", got)
	}
	refusedReport := attest.BuildReport(refusedPlan, "pve1", result.RTO, false, result.VMRecords, "")
	refusedReport.Admission = result.Admission
	if problems := attest.PolicyEvidenceProblems(refusedReport, refusedPlan); len(problems) != 0 {
		t.Errorf("the evidence of a refused run contradicts itself or the plan: %v", problems)
	}

	// Granted, then stopped by the SDN setup: the grant and its numbers are
	// recorded although the run failed afterwards.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"data":null,"message":"synthetic SDN refusal"}`, http.StatusBadRequest)
	}))
	defer server.Close()
	grantedPlan := networkOnlyPlan()
	grantedPlan.PlanID = "admission-evidence-granted"
	granted := New(grantedPlan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()},
		pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	granted.hostAddresses = &fakeHostAddressManager{}
	result, err = granted.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SDN sandbox setup failed") {
		t.Fatalf("run = %v, want the SDN setup failure", err)
	}
	if got := result.Admission; got == nil || got.Evaluation == nil || got.Evaluation.Checks != 1 || got.Evaluation.Decision != admission.DecisionGranted ||
		got.Evaluation.HostRAMPercent <= 0 || got.Evaluation.HostRAMPercent > 100 {
		t.Fatalf("a granted run's evidence is %+v, want one granted check with the node's use", got)
	}
	grantedReport := attest.BuildReport(grantedPlan, "pve1", result.RTO, false, result.VMRecords, "")
	grantedReport.Admission = result.Admission
	if problems := attest.PolicyEvidenceProblems(grantedReport, grantedPlan); len(problems) != 0 {
		t.Errorf("the evidence of a granted run contradicts itself or the plan: %v", problems)
	}
}

// A run that stops before admission is evaluated records no evaluation: the
// report then carries the policy alone (BuildReport), which says the node was
// never measured.
func TestARunThatEndsBeforeAdmissionRecordsNoEvaluation(t *testing.T) {
	plan := networkOnlyPlan()
	o := New(plan, Options{NodeName: "pve1,pve2", ScratchDir: t.TempDir(), StateDir: t.TempDir()},
		pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	result, err := o.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid node") {
		t.Fatalf("run = %v, want the node refused", err)
	}
	if result.Admission != nil {
		t.Errorf("a run refused before admission records %+v", result.Admission)
	}
}

// A run that admission refused restored nothing: it has no recovery time (the
// time it spent is in its phases), and its teardown destroyed no sandbox VM,
// which leaves the cleanup clean.
func TestARunRefusedAtAdmissionHasNoRTOAndDestroyedNoVM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("admission reads the node's /proc counters")
	}
	plan := networkOnlyPlan()
	plan.PlanID = "admission-refused-no-rto"
	plan.AdmissionControl.MaxHostRAMPercent = 0.00001
	plan.AdmissionControl.MaxDeferRetries = 0
	o := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()},
		pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := o.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "admission control guardrail triggered") {
		t.Fatalf("run = %v, want the admission refusal", err)
	}
	if len(result.VMRecords) != 0 || result.RTO != 0 || result.PhaseTimings.TotalRTOSec != 0 {
		t.Errorf("a run that restored nothing has %d VM record(s), RTO %v, total %v s", len(result.VMRecords), result.RTO, result.PhaseTimings.TotalRTOSec)
	}
	if result.PhaseTimings.AdmissionCheckSec <= 0 {
		t.Errorf("the time admission took is not recorded: %+v", result.PhaseTimings)
	}
	evidence := result.TeardownEvidence
	if evidence == nil || evidence.VMStoppedAndDestroyed || !evidence.AllCleaned || !evidence.OrphanSweepClean {
		t.Errorf("teardown evidence = %+v, want no VM destroyed and the cleanup clean", evidence)
	}
}
