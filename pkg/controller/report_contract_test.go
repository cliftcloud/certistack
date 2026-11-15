// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// reportsSaved counts the files under dir that are not a kept refused result:
// what the controller saved as a report. A refused report is kept, unsigned,
// in dir/refused; requireRefusalKept holds that file to account.
func reportsSaved(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && path == filepath.Join(dir, attest.RefusedDirName) {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count
}

// The controller signed any report that named the expected plan and a report
// UUID: another node, a stale timestamp, an unknown schema, a report of another
// run, an empty or altered population, a contradictory pass, and changed plan
// metadata were all signed as the result of this invocation. Each is now
// refused before signing, with the reason, after the run's journal has been
// verified as usual, so that nothing is saved or signed and nothing is left on
// the node.
func TestControllerRefusesAWorkerReportThatContradictsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"another node", func(r *attest.Report) { r.NodeFQDN = "unrelated-node" }, `the report names node "unrelated-node", and the run was on node "pve-01"`},
		// The worker is this build's own executable, which records both
		// worker-plan digests on every path; a report without them is not its
		// report, and PolicyEvidenceProblems lets an absent digest pass.
		{"no validated plan digest", func(r *attest.Report) { r.ValidatedPlanSHA256 = "" }, "the report records no complete validated and resolved worker-plan digests"},
		{"no resolved plan digest", func(r *attest.Report) { r.ResolvedPlanSHA256 = "" }, "the report records no complete validated and resolved worker-plan digests"},
		{"neither plan digest", func(r *attest.Report) { r.ValidatedPlanSHA256, r.ResolvedPlanSHA256 = "", "" }, "the report records no complete validated and resolved worker-plan digests"},
		{"a stale timestamp", func(r *attest.Report) { r.Timestamp = "2001-01-01T00:00:00Z" }, "is not from this run"},
		{"a timestamp in the future", func(r *attest.Report) { r.Timestamp = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339) }, "is not from this run"},
		{"a timestamp that is not a time", func(r *attest.Report) { r.Timestamp = "yesterday" }, "is not an RFC 3339 time"},
		{"an unknown schema", func(r *attest.Report) { r.ReportSchemaVersion = "999.0" }, `report_schema_version "999.0" is not the schema ` + attest.CurrentReportSchemaVersion + ` this controller's worker writes`},
		{"no schema", func(r *attest.Report) { r.ReportSchemaVersion = "" }, "is not the schema " + attest.CurrentReportSchemaVersion + " this controller's worker writes"},
		// The worker is the controller's own executable: an older 1.x schema
		// is not its report, and would be signed as one that never recorded
		// the probe policy or the plan digest a verifier holds a report to.
		{"an older schema", func(r *attest.Report) { r.ReportSchemaVersion = "1.0" }, `report_schema_version "1.0" is not the schema ` + attest.CurrentReportSchemaVersion + ` this controller's worker writes`},
		{"the previous release's schema", func(r *attest.Report) { r.ReportSchemaVersion = "1.6" }, `report_schema_version "1.6" is not the schema ` + attest.CurrentReportSchemaVersion},
		{"a later minor", func(r *attest.Report) { r.ReportSchemaVersion = "1.99" }, `report_schema_version "1.99" is not the schema ` + attest.CurrentReportSchemaVersion},
		{"another run's report", func(r *attest.Report) { r.RunID = "run-00000000-0000-4000-8000-000000000000" }, "the report names run"},
		{"the plan of another", func(r *attest.Report) { r.PlanID = "different-plan" }, `the report is for plan "different-plan"`},
		{"another plan's name", func(r *attest.Report) { r.PlanName = "Another plan" }, "the report names plan"},
		{"test-only mode on a full run", func(r *attest.Report) { r.ValidationMode = attest.ValidationModeTestSkipIntegrity }, `the report's validation mode is "test_skip_integrity", and "full_integrity" was requested`},
		{"no mode", func(r *attest.Report) { r.ValidationMode = "" }, "and \"full_integrity\" was requested"},
		{"a skipped disk under the full mode", func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].IntegrityStatus = "skipped_test_mode" }, `integrity_status "skipped_test_mode", which a full_integrity report cannot pass with`},
		{"a verified disk without a digest", func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].ImageDigest = "" }, "verified without a SHA-256 image digest"},
		{"no disk evidence", func(r *attest.Report) { r.VMRecords[0].SourceDisks = nil }, "passed with no source-disk integrity evidence"},
		// The worker is the controller's own executable and never signs, so a
		// report that carries a signature member is not its report (review R1-01).
		// The Community controller has no signer to overwrite the members.
		{"a signature the worker carried", func(r *attest.Report) { r.Signature = strings.Repeat("ab", 64) }, `carries a signature member ("signature")`},
		{"a public key the worker carried", func(r *attest.Report) { r.PublicKey = strings.Repeat("cd", 32) }, `carries a signature member ("public_key")`},
		{"a signer fingerprint the worker carried", func(r *attest.Report) { r.SignerFingerprint = "SHA256:forged" }, `carries a signature member ("signer_fingerprint")`},
		{"a signature timestamp the worker carried", func(r *attest.Report) {
			r.SignatureTimestamp = &attest.TimestampToken{Authority: "Evil CA", Token: "AAAA"}
		}, `carries a signature member ("signature_timestamp")`},
		{"no VMs", func(r *attest.Report) { r.VMRecords = nil }, "records no VM"},
		{"one VM omitted", func(r *attest.Report) { r.VMRecords = r.VMRecords[:2] }, "planned VM 9003 has no record"},
		{"a foreign VM", func(r *attest.Report) { r.VMRecords[0].VMID = 999999 }, "VM 999999 is recorded, and is not in the plan"},
		{"a duplicated VM", func(r *attest.Report) { r.VMRecords[1] = r.VMRecords[0] }, "VM 9001 is recorded more than once"},
		{"probes removed", func(r *attest.Report) { r.VMRecords[0].ProbeResults = nil }, "VM 9001 records no probe result"},
		{"a failed probe under a pass", func(r *attest.Report) {
			r.VMRecords[0].ProbeResults[0].Passed = false
			r.VMRecords[0].ProbeResults[0].Error = "connection refused"
		}, "VM 9001 probe 1 (tcp \"LDAP TCP handshake on domain controller\") failed"},
		{"a failed VM under a pass", func(r *attest.Report) { r.VMRecords[0].AllPassed = false }, "and VM 9001 does not"},
		{"an unverified VM under a pass", func(r *attest.Report) { r.VMRecords[0].VerificationStatus = "booted" }, `VM 9001's verification_status is "booted"`},
		{"every planned probe replaced by TCP results to another target", func(r *attest.Report) {
			for i := range r.VMRecords {
				for j := range r.VMRecords[i].ProbeResults {
					r.VMRecords[i].ProbeResults[j] = probe.Result{Type: "tcp", Target: "203.0.113.99:80", Description: "not in the plan", Passed: true}
				}
			}
		}, `VM 9001 probe 1 is tcp "not in the plan"; the plan configures tcp "LDAP TCP handshake on domain controller"`},
		{"the right probe against another target", func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].Target = "203.0.113.99:389" }, `targeted "203.0.113.99:389"; the plan configures "192.0.2.10:389"`},
		{"every probe skipped", func(r *attest.Report) {
			for i := range r.VMRecords {
				for j := range r.VMRecords[i].ProbeResults {
					r.VMRecords[i].ProbeResults[j].Skipped = true
				}
			}
		}, "is required but was skipped"},
		{"probes out of order", func(r *attest.Report) {
			results := r.VMRecords[0].ProbeResults
			results[0], results[1] = results[1], results[0]
		}, "the plan configures tcp"},
		{"a disk from another archive", func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].Archive = "drive-scsi9" }, `records disk "scsi0" from archive "drive-scsi9"; the plan restores archive "drive-scsi0"`},
		{"a disk the plan does not restore", func(r *attest.Report) {
			disk := r.VMRecords[0].SourceDisks[0]
			disk.Slot = "scsi5"
			r.VMRecords[0].SourceDisks = append(r.VMRecords[0].SourceDisks, disk)
		}, `records disk "scsi5", which the plan does not restore`},
		{"a planned disk recorded under another slot", func(r *attest.Report) { r.VMRecords[0].SourceDisks[0].Slot = "scsi1" }, `records no integrity evidence for disk "scsi0", which the plan restores`},
		{"a disk recorded twice", func(r *attest.Report) {
			r.VMRecords[0].SourceDisks = append(r.VMRecords[0].SourceDisks, r.VMRecords[0].SourceDisks[0])
		}, `records disk "scsi0" more than once`},
		{"a pass with a failure reason", func(r *attest.Report) { r.FailureReason = "probe failed" }, "claims a pass and also records a failure"},
		{"a wrong source VM", func(r *attest.Report) { r.VMRecords[0].SourceVMID = 999999 }, "VM 9001 records source VM 999999"},
		{"changed compliance metadata", func(r *attest.Report) { r.Frameworks = []string{"unrequested-framework"}; r.RetentionDays = 1 }, "the report's compliance frameworks"},
		{"changed retention", func(r *attest.Report) { r.RetentionDays = 1 }, "the report's retention_days 1 is not the plan's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			var progress bytes.Buffer
			opts.Writer = &progress
			report := workerReportFor(t, opts)
			tc.mutate(report)
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the report refused for %q", err, tc.want)
			}
			if result != nil {
				t.Fatalf("a result was returned for a refused report: %+v", result)
			}
			if saved := reportsSaved(t, opts.OutputDir); saved != 0 {
				t.Fatalf("%d file(s) saved for a refused report", saved)
			}
			// The refused report is not lost with the workspace: its raw result is
			// kept, unsigned, with the reason.
			if kept := requireRefusalKept(t, opts.OutputDir, fake.runID, tc.want); !strings.Contains(string(kept.raw), `"report"`) {
				t.Fatalf("the kept result does not hold the worker's report: %q", kept.raw)
			}
			if !strings.Contains(recordedCommands(fake.calls), "active.json") || fake.workspaceRemoveCalls != 1 {
				t.Fatalf("the journal was checked = %v, workspace removals = %d; want it verified and the workspace removed", strings.Contains(recordedCommands(fake.calls), "active.json"), fake.workspaceRemoveCalls)
			}
			if !strings.Contains(progress.String(), "was refused, and no report was written") {
				t.Fatalf("progress lacks the refusal:\n%s", progress.String())
			}
		})
	}
}

// Control: a report that matches what was requested is signed and
// saved, and verifies under the controller's key.
func TestControllerSignsAWorkerReportThatMatchesTheRequest(t *testing.T) {
	for _, skip := range []bool{false, true} {
		opts := completedWorkerTeardownOptions(t)
		if skip {
			t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")
			opts.SkipIntegrity = true
		}
		report := workerReportFor(t, opts)
		// A node whose clock is minutes off is within the allowed skew.
		report.Timestamp = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
		result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
		if err != nil {
			t.Fatalf("skip=%v: err = %v", skip, err)
		}
		wantMode := attest.ValidationModeFullIntegrity
		if skip {
			wantMode = attest.ValidationModeTestSkipIntegrity
		}
		if result.Report.ValidationMode != wantMode || !signatureVerifies(t, result.Report, opts.Signer) || result.Report.RunID == "" {
			t.Fatalf("skip=%v: mode %q, run %q, signature ok = %v", skip, result.Report.ValidationMode, result.Report.RunID, signatureVerifies(t, result.Report, opts.Signer))
		}
	}
}

// A worker that was asked for test mode and returns a full-integrity
// report contradicts the request as much as the reverse does.
func TestControllerRefusesAFullIntegrityReportForATestRun(t *testing.T) {
	t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")
	opts := completedWorkerTeardownOptions(t)
	opts.SkipIntegrity = true
	report := workerReportFor(t, opts)
	report.ValidationMode = attest.ValidationModeFullIntegrity
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), `and "test_skip_integrity" was requested`) {
		t.Fatalf("err = %v", err)
	}
}

// A run that failed partway has a partial population and failed probes; it
// is checked for identity and consistency, and its failure is signed as the
// worker reported it.
func TestControllerSignsTheEvidenceOfAFailedRun(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery tier 1 failed: VM 9001 probes: one or more probes failed"
	report.VMRecords = report.VMRecords[:1]
	report.VMRecords[0].AllPassed = false
	report.VMRecords[0].VerificationStatus = "failed"
	report.VMRecords[0].ProbeResults[0].Passed = false
	// A VM whose restore stopped early lists the disks it was to restore, none
	// of them verified.
	report.VMRecords[0].SourceDisks[0].IntegrityStatus = probe.DiskMapFailed
	report.VMRecords[0].SourceDisks[0].ImageDigest = ""
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "DR validation failed: recovery tier 1 failed") {
		t.Fatalf("err = %v", err)
	}
	if result == nil || result.ReportPath == "" || !signatureVerifies(t, result.Report, opts.Signer) {
		t.Fatalf("the failed run's evidence was not signed and saved: %+v", result)
	}
}

// A disk the report calls verified carries its SHA-256 digest and its PBS
// manifest reference whatever its VM's own status: a failed VM record is not
// exempt, because report_view and a reader of the signed report take "verified"
// at its word. A failed VM whose disk is verified with its evidence (the
// worker's own shape when a later disk failed) is still signed.
func TestFailedVMRecordCannotKeepAVerifiedDiskWithoutItsEvidence(t *testing.T) {
	failedRun := func(t *testing.T, mutate func(*probe.SourceDiskEvidence)) (*Executor, RunOptions, *fakeCommandRunner) {
		t.Helper()
		opts := completedWorkerTeardownOptions(t)
		report := workerReportFor(t, opts)
		report.AllPassed = false
		report.FailureReason = "recovery tier 1 failed: VM 9001 probes: one or more probes failed"
		report.VMRecords = report.VMRecords[:1]
		report.VMRecords[0].AllPassed = false
		report.VMRecords[0].VerificationStatus = "failed"
		report.VMRecords[0].ProbeResults[0].Passed = false
		mutate(&report.VMRecords[0].SourceDisks[0])
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
		return &Executor{runner: fake}, opts, fake
	}
	for _, tc := range []struct {
		name   string
		mutate func(*probe.SourceDiskEvidence)
		want   string
	}{
		{"no digest", func(d *probe.SourceDiskEvidence) { d.ImageDigest = "" }, `disk "scsi0" is marked verified without a SHA-256 image digest`},
		{"a digest that is not SHA-256", func(d *probe.SourceDiskEvidence) { d.ImageDigest = "abc123" }, `disk "scsi0" is marked verified without a SHA-256 image digest`},
		{"no manifest reference", func(d *probe.SourceDiskEvidence) { d.ManifestReference = "" }, `disk "scsi0" is marked verified without a PBS manifest reference`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, opts, _ := failedRun(t, tc.mutate)
			result, err := executor.Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") || !strings.Contains(err.Error(), "VM 9001") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the failed VM's verified disk refused for %q", err, tc.want)
			}
			if result != nil {
				t.Fatalf("a result was returned for a refused report: %+v", result)
			}
		})
	}
	t.Run("a verified disk with its evidence is signed", func(t *testing.T) {
		executor, opts, _ := failedRun(t, func(*probe.SourceDiskEvidence) {})
		result, err := executor.Run(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "DR validation failed: recovery tier 1 failed") {
			t.Fatalf("err = %v", err)
		}
		if result == nil || result.ReportPath == "" || !signatureVerifies(t, result.Report, opts.Signer) {
			t.Fatalf("the failed run's evidence was not signed and saved: %+v", result)
		}
	})
	t.Run("a disk that is not verified needs no digest", func(t *testing.T) {
		executor, opts, _ := failedRun(t, func(d *probe.SourceDiskEvidence) {
			d.IntegrityStatus, d.ImageDigest, d.ManifestReference = probe.DiskNotAttempted, "", ""
		})
		result, err := executor.Run(context.Background(), opts)
		if err == nil || strings.Contains(err.Error(), "the node worker's report contradicts") {
			t.Fatalf("err = %v, want the failure signed as the worker reported it", err)
		}
		if result == nil || result.ReportPath == "" {
			t.Fatalf("the failed run's evidence was not saved: %+v", result)
		}
	})
}

// A refused report and a journal that cannot be verified are both
// said, in the one error.
func TestControllerReportsARefusedReportAndUnverifiedCleanupTogether(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.NodeFQDN = "unrelated-node"
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalState: "absent"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "the report names node") || !strings.Contains(err.Error(), "cleanup could not be verified either") || !strings.Contains(err.Error(), "the journal is missing") {
		t.Fatalf("err = %v", err)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatalf("the workspace was removed although the cleanup is unverified")
	}
}

// Clock skew is documented and bounded: a report ten minutes or more away
// from the run is refused, one within it accepted.
func TestReportTimestampSkewIsBounded(t *testing.T) {
	now := time.Now()
	want := reportExpectation{plan: &config.Plan{}, startedAt: now.Add(-time.Minute), now: now}
	for offset, ok := range map[time.Duration]bool{
		-reportClockSkew - 2*time.Minute: false,
		-reportClockSkew + time.Minute:   true,
		0:                                true,
		reportClockSkew - time.Minute:    true,
		reportClockSkew + 2*time.Minute:  false,
	} {
		report := &attest.Report{Timestamp: now.Add(offset).UTC().Format(time.RFC3339)}
		err := checkWorkerReport(report, want)
		got := err == nil || !strings.Contains(err.Error(), "is not from this run")
		if got != ok {
			t.Errorf("offset %v: within the skew = %v, want %v", offset, got, ok)
		}
	}
}

// Firmware state the backup adds to the disks a plan names is not a
// disk the plan does not restore.
func TestFirmwareDisksAreNotDisksThePlanDoesNotRestore(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	for _, slot := range []string{"efidisk0", "tpmstate0"} {
		disk := report.VMRecords[0].SourceDisks[0]
		disk.Slot = slot
		report.VMRecords[0].SourceDisks = append(report.VMRecords[0].SourceDisks, disk)
	}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// A VM the report calls verified is held to the plan's probes and
// disks even when the run failed elsewhere; a VM that failed is not.
func TestVerifiedVMOfAFailedRunIsHeldToThePlan(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery tier 2 failed: VM 9002 probes: one or more probes failed"
	report.VMRecords = report.VMRecords[:2]
	report.VMRecords[1].AllPassed = false
	report.VMRecords[1].VerificationStatus = "failed"
	report.VMRecords[1].ProbeResults = report.VMRecords[1].ProbeResults[:1]
	report.VMRecords[1].ProbeResults[0].Passed = false
	report.VMRecords[0].ProbeResults[0].Target = "203.0.113.99:389"
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts") || !strings.Contains(err.Error(), `VM 9001 probe 1 (tcp "LDAP TCP handshake on domain controller") targeted`) || strings.Contains(err.Error(), "VM 9002") {
		t.Fatalf("err = %v, want the verified VM 9001 refused and the failed VM 9002 left alone", err)
	}
}

// A report that claims a pass was signed while the worker's own
// result carried an error, and the run was then reported failed or
// interrupted with a signed pass saved. The two contradict, and nothing is
// signed.
func TestControllerRefusesAPassingReportWhenTheWorkersResultReportsAnError(t *testing.T) {
	for _, workerErr := range []string{"worker says the validation failed", "interrupted: SIGTERM"} {
		opts := completedWorkerTeardownOptions(t)
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts), Error: workerErr}, journalPhase: "cleaned"}
		result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
		var interrupted *NodeInterruptedError
		if err == nil || !strings.Contains(err.Error(), "the report claims a pass, and the worker's result reports an error ("+workerErr+")") || errors.As(err, &interrupted) || result != nil {
			t.Fatalf("worker error %q: err = %v, result = %+v", workerErr, err, result)
		}
		if saved := reportsSaved(t, opts.OutputDir); saved != 0 {
			t.Fatalf("worker error %q: %d file(s) saved", workerErr, saved)
		}
	}
}
