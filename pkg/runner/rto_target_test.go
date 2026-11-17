// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// planWithRTOTarget loads the reported plan through the real loader
// (which validates it), with the given rto_target_seconds line or none.
func planWithRTOTarget(t *testing.T, target string) (*config.Plan, error) {
	t.Helper()
	line := ""
	if target != "" {
		line = "  rto_target_seconds: " + target + "\n"
	}
	return config.LoadFromReader(bytes.NewReader([]byte(fmt.Sprintf(`version: "v1"
plan_id: "audit-rto-target"
name: "Audit RTO Target"
compliance:
  frameworks: ["DORA-Article-12"]
  retention_days: 90
  sign_key_path: "/synthetic/controller-signing.ed25519"
%sadmission_control:
  max_host_ram_percent: 85.0
  max_host_iowait_percent: 12.0
  defer_retry_interval_sec: 30
  max_defer_retries: 10
network:
  mode: "simple"
  zone_id: "csSb01"
  vnet_id: "csVn01"
  ip_range: "10.100.0.0/24"
  probe_ip: "10.100.0.1"
tiers:
  - level: 1
    name: "Audit tier"
    vms:
      - vmid: 9001
        name: "audit-vm"
        source_pbs: {storage_id: "pbs", snapshot: "vm/100/2026-03-30T02:00:00Z", drive: "drive-scsi0"}
        probes:
          - {type: "tcp", target_ip: "10.100.0.10", port: 443, timeout_sec: 1, description: "Audit TCP probe"}
`, line))))
}

// At the enforcement function: the same 42-second
// result passes an omitted objective and a larger one, fails a smaller one and
// records the missed objective, and an objective of zero never reaches it,
// because the loader refuses the plan.
func TestAnExplicitZeroObjectiveNeverReachesEnforcement(t *testing.T) {
	for _, tc := range []struct {
		target string
		passes bool
	}{
		{target: "", passes: true},
		{target: "300", passes: true},
		{target: "42", passes: true},
		{target: "41.9", passes: false},
		{target: "30", passes: false},
		{target: "0.5", passes: false},
	} {
		plan, err := planWithRTOTarget(t, tc.target)
		if err != nil {
			t.Fatalf("rto_target_seconds %q: %v", tc.target, err)
		}
		report := &attest.Report{AllPassed: true, RTOSeconds: 42}
		err = enforceRTOTarget(report, plan)
		if tc.passes && (err != nil || !report.AllPassed || report.FailureReason != "") {
			t.Errorf("rto_target_seconds %q: err=%v all_passed=%v reason=%q, want a pass", tc.target, err, report.AllPassed, report.FailureReason)
		}
		if !tc.passes && (err == nil || report.AllPassed || !strings.Contains(report.FailureReason, "recovery time objective exceeded")) {
			t.Errorf("rto_target_seconds %q: err=%v all_passed=%v reason=%q, want the missed objective recorded", tc.target, err, report.AllPassed, report.FailureReason)
		}
	}
	if _, err := planWithRTOTarget(t, "0"); err == nil || !strings.Contains(err.Error(), "compliance.rto_target_seconds") {
		t.Fatalf("a plan with rto_target_seconds: 0 loaded (err %v); every run would pass it as if no objective were set", err)
	}
}

// At the call site: the report run signs carries the objective the plan sets
// and the admission evidence the orchestrator produced, and a report of a run
// that never reached admission carries the policy alone. The orchestrator is a
// stub, as in TestRunSignsAgainTheReportItCouldNotSave.
func TestRunSignsTheObjectiveAndTheAdmissionCheckItWasHeldTo(t *testing.T) {
	origPrepare, origOrchestrate := prepareRunFn, orchestrate
	t.Cleanup(func() { prepareRunFn, orchestrate = origPrepare, origOrchestrate })
	prepareRunFn = func(context.Context, *config.Plan, Options, string) (*pve.Client, *pbs.Client, error) {
		return pve.NewClient(pve.Config{}), pbs.New(pbs.Config{}), nil
	}
	planFor := func(target float64) *config.Plan {
		return &config.Plan{
			PlanID: "policy-at-the-call-site",
			Compliance: config.Compliance{
				Frameworks: []string{"DORA"}, RetentionDays: 90, RTOTargetSeconds: target,
			},
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 72, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers:            []config.Tier{{Level: 1, VMs: []config.VM{{VMID: 9001, Name: "vm"}}}},
		}
	}
	runWith := func(plan *config.Plan, result *orchestrator.ExecutionResult) *attest.Report {
		t.Helper()
		orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
			return result, nil
		}
		dir := t.TempDir()
		report, _ := run(context.Background(), plan, Options{
			NodeName: "pve1", StateDir: filepath.Join(dir, "state"), ScratchDir: filepath.Join(dir, "scratch"),
			OutputDir: filepath.Join(dir, "reports"), Writer: io.Discard,
		})
		if report == nil {
			t.Fatal("run returned no report")
		}
		return report
	}

	plan := planFor(60)
	evidence := attest.NewAdmissionEvidence(plan).WithEvaluation(admission.Evaluation{
		Checks: 2, Decision: admission.DecisionGranted, HostTotalMiB: 200_000, HostAvailableMiB: 150_000,
		HostRAMPercent: 25, HostIOWaitPercent: 1.5, ProjectedRAMPercent: 26.152,
	})
	report := runWith(plan, &orchestrator.ExecutionResult{AllPassed: true, RTO: 42 * time.Second, Admission: evidence})
	if report.RTOTargetSeconds == nil || *report.RTOTargetSeconds != 60 {
		t.Errorf("the report records objective %v, want 60", report.RTOTargetSeconds)
	}
	if report.Admission == nil || report.Admission.MaxHostRAMPercent != 72 || report.Admission.Evaluation == nil ||
		report.Admission.Evaluation.Checks != 2 || report.Admission.Evaluation.HostIOWaitPercent != 1.5 {
		t.Errorf("the report lost the admission evidence the orchestrator produced: %+v", report.Admission)
	}

	// An objective that was missed is still recorded: the report says which it missed.
	missed := runWith(planFor(30), &orchestrator.ExecutionResult{AllPassed: true, RTO: 42 * time.Second, Admission: evidence})
	if missed.AllPassed || missed.RTOTargetSeconds == nil || *missed.RTOTargetSeconds != 30 {
		t.Errorf("a missed objective: all_passed=%v objective=%v", missed.AllPassed, missed.RTOTargetSeconds)
	}

	// No objective in the plan: none in the report. A run that ended before
	// admission was evaluated: the policy and the reservation, no evaluation.
	early := runWith(planFor(0), &orchestrator.ExecutionResult{AllPassed: false, Error: errors.New("invalid node")})
	if early.RTOTargetSeconds != nil {
		t.Errorf("a plan with no objective produced %v", *early.RTOTargetSeconds)
	}
	if early.Admission == nil || early.Admission.Evaluation != nil || early.Admission.MaxHostRAMPercent != 72 || early.Admission.RecoveryReservationMiB != 2304 {
		t.Errorf("a run that ended before admission records %+v, want the policy and the reservation alone", early.Admission)
	}
}
