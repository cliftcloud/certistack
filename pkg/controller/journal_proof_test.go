// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/google/uuid"
)

// signatureVerifies reports whether report's signature verifies under the
// key at keyPath, the controller's own.
func signatureVerifies(t *testing.T, report *attest.Report, signer attest.Signer) bool {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	_, valid, err := attest.VerifyReport(encoded, []ed25519.PublicKey{signer.(*attesttest.Signer).Public()})
	if err != nil {
		t.Fatal(err)
	}
	return valid
}

// A passing report from a worker that claims a clean teardown is not signed
// as independently verified (journal_recovery_verified, all_cleaned) when the
// node's journal is missing, which shows nothing of the run. The report is
// still saved and signed, as the controller could establish it: the run's
// cleanup is unverified, the command fails, and the workspace stays.
func TestControllerDoesNotSignAVerifiedTeardownFromAMissingJournal(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalState: "absent"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "unverified temporary resource cleanup") || !strings.Contains(err.Error(), "the journal is missing") {
		t.Fatalf("err = %v, want the unverified cleanup reported with its reason", err)
	}
	if result == nil || result.Report == nil || result.ReportPath == "" {
		t.Fatalf("result = %+v, want the report saved with its cleanup unverified", result)
	}
	evidence := result.Report.TeardownEvidence
	if evidence.AllCleaned || evidence.OrphanSweepClean || evidence.JournalRecoveryVerified || len(evidence.CleanupErrors) != 1 {
		t.Fatalf("evidence = %+v, want no clean claim and one error", evidence)
	}
	if result.Report.AllPassed || result.Report.FailureReason != unverifiedCleanupReason {
		t.Fatalf("all_passed %v, failure_reason %q: a run whose cleanup is unverified did not pass", result.Report.AllPassed, result.Report.FailureReason)
	}
	if !signatureVerifies(t, result.Report, opts.Signer) {
		t.Fatal("the report was not signed as it stands")
	}
	if fake.recoverCalls != 0 {
		t.Fatalf("recover ran %d times against a journal that does not exist", fake.recoverCalls)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatalf("the workspace was removed %d times, want it kept", fake.workspaceRemoveCalls)
	}
	if !strings.Contains(progress.String(), "The controller cannot verify that this run cleaned up after itself") {
		t.Fatalf("progress lacks the notice:\n%s", progress.String())
	}
}

// A passing report whose worker says its own cleanup failed is not signed as
// independently verified clean because the node's journal names a different
// run, in any phase, and the workspace it needs for a retry stays. Another
// run's journal is no proof of this run's cleanup unless the node holds that
// run's own transition record.
func TestControllerDoesNotSignAVerifiedTeardownFromAnotherRunsJournal(t *testing.T) {
	for _, phase := range []string{"running", "cleaned", "cleanup_failed"} {
		t.Run(phase, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			report := workerReportFor(t, opts)
			report.TeardownEvidence = &attest.TeardownEvidence{
				AllCleaned:    false,
				CleanupErrors: []string{"destroy sandbox VM 9001: PVE task failed"},
			}
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalReads: []string{"run-" + uuid.NewString() + " " + phase}}
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "unverified temporary resource cleanup") {
				t.Fatalf("err = %v, want the unverified cleanup reported", err)
			}
			evidence := result.Report.TeardownEvidence
			if evidence.AllCleaned || evidence.OrphanSweepClean || evidence.JournalRecoveryVerified {
				t.Fatalf("evidence = %+v, want no clean claim", evidence)
			}
			// The worker's own failure stays a current cleanup error, next to
			// what the controller could not verify.
			if len(evidence.CleanupErrors) != 2 || evidence.CleanupErrors[0] != "destroy sandbox VM 9001: PVE task failed" || len(evidence.InitialCleanupErrors) != 0 {
				t.Fatalf("cleanup errors = %v, initial = %v", evidence.CleanupErrors, evidence.InitialCleanupErrors)
			}
			if fake.recoverCalls != 0 || fake.workspaceRemoveCalls != 0 {
				t.Fatalf("recover ran %d times, workspace removed %d times; want neither", fake.recoverCalls, fake.workspaceRemoveCalls)
			}
		})
	}
}

// Control: a later run's journal is accepted when the node holds the
// transition record that run kept of this run's clean journal. The worker's
// own cleanup failure is then history, as before.
func TestControllerAcceptsALaterRunsJournalWithOurTransitionRecord(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.TeardownEvidence = &attest.TeardownEvidence{AllCleaned: false, CleanupErrors: []string{"destroy sandbox VM 9001: PVE task failed"}}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalReads: []string{"run-" + uuid.NewString() + " running"}}
	// The node recovered this run's journal for the later run, which kept
	// this run's transition. The fake learns the run ID from the commands.
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if match := workerRunIDExpr.FindStringSubmatch(joined); match != nil && len(fake.transitions) == 0 {
			fake.transitions = []string{"run-" + match[1]}
		}
		return nil, nil, false
	}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	evidence := result.Report.TeardownEvidence
	if !evidence.AllCleaned || !evidence.JournalRecoveryVerified || len(evidence.InitialCleanupErrors) != 1 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if fake.recoverCalls != 0 || fake.workspaceRemoveCalls != 1 {
		t.Fatalf("recover ran %d times, workspace removed %d times", fake.recoverCalls, fake.workspaceRemoveCalls)
	}
}

// A run refused before it allocated anything leaves a clean journal
// that names it, and is verified as any run is.
func TestARefusedRunIsVerifiedFromItsOwnCleanJournal(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "node preflight failed: scratch: not enough free space"
	report.VMRecords = nil
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "node preflight failed") {
		t.Fatalf("err = %v", err)
	}
	if evidence := result.Report.TeardownEvidence; !evidence.AllCleaned || !evidence.JournalRecoveryVerified {
		t.Fatalf("evidence = %+v", evidence)
	}
}
