// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// soakOptions are the controller's options for the standard plan with a 120 s
// soak on its first tier.
func soakOptions(t *testing.T) RunOptions {
	t.Helper()
	opts := completedWorkerTeardownOptions(t)
	text, err := os.ReadFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	const anchor = "    startup_grace_period_sec: 45\n"
	if !strings.Contains(string(text), anchor) {
		t.Fatal("the standard plan no longer has the first tier's grace period this test anchors on")
	}
	changed := strings.Replace(string(text), anchor, anchor+"    soak_time_sec: 120\n", 1)
	opts.PlanPath = filepath.Join(t.TempDir(), "soak-plan.yaml")
	if err := os.WriteFile(opts.PlanPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

// A report that claims a pass for a VM whose tier held it for a soak
// must carry the summary of the service checks the soak ran, and the summary
// must be of that soak. The controller refuses the report before it signs it
// otherwise.
func TestControllerRefusesAPassWhoseSoakDidNotCheckTheServices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"no summary", func(r *attest.Report) { r.VMRecords[0].Soak = nil }, "VM 9001 passed without a record of its services being checked during its tier's 120 s soak"},
		{"a summary of a shorter soak", func(r *attest.Report) { r.VMRecords[0].Soak.ConfiguredSec = 30 }, "records a soak of 30 s; the plan holds the tier for 120 s"},
		{"a failed service check under a pass", func(r *attest.Report) {
			soak := r.VMRecords[0].Soak
			soak.FailedSamples = 1
			soak.Probes[0].Passed--
			soak.Probes[0].Failed, soak.Probes[0].FirstError = 1, "connection refused"
		}, "service check(s) failed"},
		{"a last check before the period was over", func(r *attest.Report) {
			soak := r.VMRecords[0].Soak
			started, _ := time.Parse(time.RFC3339, soak.StartedAt)
			soak.LastSampleAt = started.Add(60 * time.Second).UTC().Format(time.RFC3339)
		}, "before the configured 120 s were over"},
		{"no state read from PVE", func(r *attest.Report) {
			soak := r.VMRecords[0].Soak
			soak.StatusReadFailures, soak.FirstStatusError = soak.StatusReads, "HTTP 401"
		}, "PVE never reported its state during the soak"},
		{"a summary for a tier with no soak", func(r *attest.Report) {
			r.VMRecords[2].Soak = r.VMRecords[0].Soak
		}, "holds its tier for no soak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := soakOptions(t)
			report := workerReportFor(t, opts)
			if report.VMRecords[0].Soak == nil {
				t.Fatal("the honest worker's report carries no soak summary for the tier that has a soak")
			}
			tc.mutate(report)
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the report refused for %q", err, tc.want)
			}
			if result != nil || reportsSaved(t, opts.OutputDir) != 0 {
				t.Fatalf("a refused report was returned or saved: %+v", result)
			}
		})
	}
}

// The control: the honest report of the same plan is signed, soak summary and
// all, and the summary is inside the signature.
func TestControllerSignsAReportWhoseSoakCheckedTheServices(t *testing.T) {
	opts := soakOptions(t)
	report := workerReportFor(t, opts)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if soak := result.Report.VMRecords[0].Soak; soak == nil || soak.ConfiguredSec != 120 || !signatureVerifies(t, result.Report, opts.Signer) {
		t.Fatalf("the signed report's soak = %+v", soak)
	}
	// A VM of a tier with no soak carries none.
	if result.Report.VMRecords[2].Soak != nil {
		t.Errorf("a VM of a tier with no soak carries a summary: %+v", result.Report.VMRecords[2].Soak)
	}
}

// A VM that verified in a run that failed elsewhere may belong to a tier that
// failed before its soak began, so the failed run's evidence is signed without
// one.
func TestControllerSignsAFailedRunWhoseTierNeverReachedItsSoak(t *testing.T) {
	opts := soakOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery tier 1 failed: VM 9001 probes: one or more probes failed"
	report.VMRecords = report.VMRecords[:1]
	record := &report.VMRecords[0]
	record.Soak = nil
	record.AllPassed, record.VerificationStatus = false, "failed"
	record.ProbeResults[0].Passed = false
	record.SourceDisks[0].IntegrityStatus = "map_failed"
	record.SourceDisks[0].ImageDigest = ""
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "the run failed: recovery tier 1 failed") {
		t.Fatalf("err = %v", err)
	}
}
