// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// failedRunReport is what a worker returns for a run that stopped in its first
// VM's restore: the first VM's record lists the disks it was to restore, none
// of them verified, and no later VM has a record.
func failedRunReport(t *testing.T, opts RunOptions, status string) *attest.Report {
	t.Helper()
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery tier 1 failed: VM 9001 restore: PBS map error for scsi0"
	report.VMRecords = report.VMRecords[:1]
	record := &report.VMRecords[0]
	record.AllPassed = false
	record.VerificationStatus = "failed"
	record.ProbeResults = []probe.Result{{Type: "recovery", Target: "vm/9001", Description: "Recovery bootstrap and verification", Error: "PBS map error for scsi0"}}
	record.SourceDisks[0].IntegrityStatus = status
	// A worker writes "verified" together with the image digest (and the
	// manifest reference every disk entry carries); any other status has none.
	if status != probe.DiskVerified {
		record.SourceDisks[0].ImageDigest = ""
	}
	return report
}

func runAgainst(t *testing.T, opts RunOptions, report *attest.Report) (*Result, error) {
	t.Helper()
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
	return (&Executor{runner: fake}).Run(context.Background(), opts)
}

// pinnedPlan is the test plan with its first VM's snapshot pinned.
func pinnedPlan(t *testing.T, opts RunOptions) RunOptions {
	t.Helper()
	text, err := os.ReadFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	pinned := strings.Replace(string(text), `snapshot: "latest"`, `snapshot: "vm/100/2026-09-20T01:00:00Z"`, 1)
	if pinned == string(text) {
		t.Fatal("the plan has no snapshot to pin")
	}
	path := filepath.Join(t.TempDir(), "pinned.yaml")
	if err := os.WriteFile(path, []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.PlanPath = path
	return opts
}

// The controller's half. Every record is held to the backup it names, a
// failed or an incomplete one as well as a pass, so a record that names no
// backup, or another than the one requested, is not certified as this run's.
func TestControllerRefusesAFailedRunWhoseRecordsNameNoCoherentBackup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pinned bool
		mutate func(*attest.Report)
		want   string
	}{
		{"no snapshot", false, func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "" }, "VM 9001 records no source snapshot"},
		{"a snapshot that is no path", false, func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "latest" }, `records source snapshot "latest", which is not a PBS snapshot path`},
		{"a group, not a snapshot", false, func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/100" }, "which is not a PBS snapshot path"},
		{"a snapshot of another VM", false, func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/999/2026-09-27T03:12:59Z" }, "a backup of VM 999, and source VM 100"},
		{"another source VM than the plan's", false, func(r *attest.Report) {
			r.VMRecords[0].SourceVMID = 999
			r.VMRecords[0].SourceSnapshot = "vm/999/2026-09-27T03:12:59Z"
		}, "VM 9001 records source VM 999, and the plan restores source VM 100"},
		{"another snapshot than the one the plan pins", true, func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/100/2026-09-21T01:00:00Z" }, `the plan pins "vm/100/2026-09-20T01:00:00Z"`},
		{"no disks", false, func(r *attest.Report) { r.VMRecords[0].SourceDisks = nil }, `records no integrity evidence for disk "scsi0", which the plan restores`},
		{"a disk from another archive", false, func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].Archive = "drive-scsi9" }, `records disk "scsi0" from archive "drive-scsi9"`},
		{"a disk the plan does not restore", false, func(r *attest.Report) {
			r.VMRecords[0].SourceDisks = append(r.VMRecords[0].SourceDisks, probe.SourceDiskEvidence{Slot: "scsi5", Archive: "drive-scsi5", IntegrityStatus: probe.DiskNotAttempted})
		}, `records disk "scsi5", which the plan does not restore`},
		{"a disk status no worker writes", false, func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].IntegrityStatus = "passed" }, `integrity_status "passed", which no worker of this build writes`},
		{"a disk status with another case", false, func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].IntegrityStatus = "Map_Failed" }, "which no worker of this build writes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			if tc.pinned {
				opts = pinnedPlan(t, opts)
			}
			report := failedRunReport(t, opts, probe.DiskMapFailed)
			tc.mutate(report)
			result, err := runAgainst(t, opts, report)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the failed run's report refused for %q", err, tc.want)
			}
			if result != nil || reportsSaved(t, opts.OutputDir) != 0 {
				t.Fatalf("a refused report was signed or saved: %+v", result)
			}
			requireRefusalKept(t, opts.OutputDir, "", tc.want)
		})
	}
}

// Control: a failed run's record is signed whatever way its restore
// ended, with the pinned snapshot the plan names, and with each disk at any
// status a worker writes.
func TestControllerSignsAFailedRunWithTheBackupItWasGiven(t *testing.T) {
	for _, status := range []string{probe.DiskNotAttempted, probe.DiskMapped, probe.DiskMapFailed, probe.DiskVerificationFailed, probe.DiskRestoreFailed, probe.DiskVerified} {
		for _, pinned := range []bool{false, true} {
			opts := completedWorkerTeardownOptions(t)
			if pinned {
				opts = pinnedPlan(t, opts)
			}
			report := failedRunReport(t, opts, status)
			result, err := runAgainst(t, opts, report)
			if err == nil || !strings.Contains(err.Error(), "the run failed: recovery tier 1 failed") {
				t.Fatalf("status %s pinned %v: err = %v", status, pinned, err)
			}
			if result == nil || !signatureVerifies(t, result.Report, opts.Signer) {
				t.Fatalf("status %s pinned %v: the failed run's evidence was not signed: %+v", status, pinned, result)
			}
			got := result.Report.VMRecords[0]
			if got.SourceSnapshot != report.VMRecords[0].SourceSnapshot || got.SourceDisks[0].IntegrityStatus != status {
				t.Fatalf("status %s: the signed record = %+v", status, got)
			}
		}
	}
}

// A VM the report calls verified is held to its integrity evidence even when
// the run failed elsewhere: a disk that never got past "not_attempted" is no
// verified VM.
func TestAVerifiedVMOfAFailedRunHasVerifiedDisks(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery tier 2 failed: VM 9002 probes: one or more probes failed"
	report.VMRecords = report.VMRecords[:2]
	report.VMRecords[1].AllPassed = false
	report.VMRecords[1].VerificationStatus = "failed"
	report.VMRecords[1].ProbeResults[0].Passed = false
	report.VMRecords[0].SourceDisks[0].IntegrityStatus = probe.DiskNotAttempted
	_, err := runAgainst(t, opts, report)
	if err == nil || !strings.Contains(err.Error(), `VM 9001 disk "scsi0" has integrity_status "not_attempted", which a full_integrity report cannot pass with`) {
		t.Fatalf("err = %v, want the verified VM's unverified disk refused", err)
	}
}

// A report whose probe results ran under another policy than the plan's, which
// verify-report --expect-plan rejects, is not signed: the controller holds a
// worker's report to the same policy rules (planrules.go) before it signs it.
func TestControllerRefusesAPassingReportWhoseProbesRanUnderAnotherPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"another timeout", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].TimeoutSec = 1 }, `VM 9001 probe 1 (tcp "LDAP TCP handshake on domain controller") ran under a timeout of 1 s; the plan configures 30 s`},
		{"no timeout recorded", func(r *attest.Report) { r.VMRecords[0].ProbeResults[1].TimeoutSec = 0 }, "ran under a timeout of 0 s; the plan configures 15 s"},
		{"retries the plan does not set", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].Retries = 3 }, "records retries 3; the plan configures 0"},
		{"a negative attempts count", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].Attempts = -1 }, "records a negative timeout, retries or attempts count"},
		{"a guest-agent probe recorded as required", func(r *attest.Report) { r.VMRecords[0].ProbeResults[2].RequireQGA = true }, "is recorded as requiring the guest agent; the plan makes it optional"},
		{"a virtual host the plan does not set", func(r *attest.Report) { r.VMRecords[2].ProbeResults[0].ServerName = "other.example" }, `asserted virtual host "other.example"; the plan configures ""`},
		{"another source address", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].SourceAddress = "10.9.9.9" }, `was bound to source "10.9.9.9" on interface "csVn01"; the plan's sandbox probes from "192.0.2.1" on "csVn01"`},
		{"another source interface", func(r *attest.Report) { r.VMRecords[1].ProbeResults[0].SourceInterface = "vmbr0" }, `on interface "vmbr0"`},
		{"no source recorded", func(r *attest.Report) {
			r.VMRecords[0].ProbeResults[0].SourceAddress, r.VMRecords[0].ProbeResults[0].SourceInterface = "", ""
		}, `was bound to source "" on interface ""`},
		{"an image digest that is no digest", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].ImageSHA256 = "not-a-digest" }, "records an image_sha256 that is not a SHA-256 digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			report := workerReportFor(t, opts)
			tc.mutate(report)
			result, err := runAgainst(t, opts, report)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the report refused for %q", err, tc.want)
			}
			if result != nil || reportsSaved(t, opts.OutputDir) != 0 {
				t.Fatalf("a refused report was signed or saved: %+v", result)
			}
			requireRefusalKept(t, opts.OutputDir, "", tc.want)
		})
	}
}

// The policy of a VM that failed is not held to the plan: a run that
// stopped partway legitimately has partial results.
func TestControllerLeavesTheProbePolicyOfAFailedVMAlone(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := failedRunReport(t, opts, probe.DiskVerificationFailed)
	report.VMRecords[0].ProbeResults = []probe.Result{{Type: "tcp", Target: "192.0.2.10:389", Description: "LDAP TCP handshake on domain controller", TimeoutSec: 1, Error: "timed out"}}
	if _, err := runAgainst(t, opts, report); err == nil || !strings.Contains(err.Error(), "the run failed: recovery tier 1 failed") {
		t.Fatalf("err = %v, want the failed run signed and reported", err)
	}
}
