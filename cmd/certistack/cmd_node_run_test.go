// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

func TestEnsureWorkerDirectoriesCreatesProtectedPaths(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	scratchDir := filepath.Join(root, "scratch")
	if err := ensureWorkerDirectories(stateDir, scratchDir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stateDir, scratchDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Fatalf("%s was not created as a directory", path)
		}
	}
}

func TestSkipIntegrityRequiresExplicitOptInAndIsHidden(t *testing.T) {
	for name := range workerEnvironmentNames {
		t.Setenv(name, "test-value")
	}
	t.Setenv(testModeOptInEnvironment, "")

	controllerCommand := runCmd()
	if flag := controllerCommand.Flags().Lookup("skip-integrity"); flag == nil || !flag.Hidden {
		t.Fatal("controller --skip-integrity flag is not hidden")
	}
	controllerCommand.SetArgs([]string{"--skip-integrity"})
	if err := controllerCommand.Execute(); err == nil || !strings.Contains(err.Error(), "CERTISTACK_ALLOW_TEST_MODE=1") {
		t.Fatalf("controller accepted unapproved --skip-integrity: %v", err)
	}

	workerCommand := nodeRunCmd()
	if flag := workerCommand.Flags().Lookup("skip-integrity"); flag == nil || !flag.Hidden {
		t.Fatal("worker --skip-integrity flag is not hidden")
	}
	envFile := filepath.Join(t.TempDir(), "runtime.env")
	if err := os.WriteFile(envFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	workerCommand.SetArgs([]string{
		"--plan", filepath.Join(t.TempDir(), "missing-plan.yaml"),
		"--node", "node-a",
		"--env-file", envFile,
		"--skip-integrity",
	})
	if err := workerCommand.Execute(); err == nil || !strings.Contains(err.Error(), "CERTISTACK_ALLOW_TEST_MODE=1") {
		t.Fatalf("worker accepted unapproved --skip-integrity: %v", err)
	}
}

func TestEnsureWorkerDirectoriesRejectsFilesystemRoot(t *testing.T) {
	if err := ensureWorkerDirectories("/", "/var/lib/certistack/scratch"); err == nil {
		t.Fatal("filesystem root was accepted as a worker state directory")
	}
}

func TestEnsureWorkerDirectoriesRejectsSharedScratch(t *testing.T) {
	if err := ensureWorkerDirectories(filepath.Join(t.TempDir(), "state"), os.TempDir()); err == nil {
		t.Fatal("shared temporary directory was accepted as worker scratch")
	}
}

func TestEnsureWorkerDirectoriesRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	if err := ensureWorkerDirectories(filepath.Join(link, "state"), filepath.Join(root, "scratch")); err == nil {
		t.Fatal("worker directory beneath a symlinked parent was accepted")
	}
}

func TestPreflightFailureResultPreservesFailedEvidence(t *testing.T) {
	plan := &config.Plan{PlanID: "preflight-refusal", Name: "Preflight refusal"}
	result := preflightFailureResult(plan, "node-a", preflight.Result{
		Ready:  false,
		Checks: []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: "reservation exceeds safe capacity"}},
	}, true)

	if result.Report == nil || result.Report.AllPassed {
		t.Fatalf("preflight refusal did not produce failed evidence: %+v", result)
	}
	if result.Report.ValidationMode != attest.ValidationModeTestSkipIntegrity {
		t.Fatalf("validation mode = %q", result.Report.ValidationMode)
	}
	if !strings.Contains(result.Error, "memory: reservation exceeds safe capacity") || result.Report.FailureReason != result.Error {
		t.Fatalf("preflight failure evidence = result %q report %q", result.Error, result.Report.FailureReason)
	}
}

func TestFailedNodeReportProvesNoResourceCleanupWasRequired(t *testing.T) {
	report := failedNodeReport(&config.Plan{PlanID: "early-runner-failure"}, "node-a", "source metadata unavailable", false)
	if report.AllPassed || report.FailureReason != "source metadata unavailable" {
		t.Fatalf("failed node report = %+v", report)
	}
	if len(report.VMRecords) != 0 {
		t.Fatalf("early failure must not claim a VM run: %+v", report)
	}
	if evidence := report.TeardownEvidence; evidence == nil || !evidence.AllCleaned || !evidence.OrphanSweepClean || evidence.JournalRecoveryVerified || evidence.VerifiedAt == "" {
		t.Fatalf("early failure must prove a verified no-op cleanup: %+v", evidence)
	}
}

// A run refused before it allocated anything names itself in its
// report and in a clean journal of its own, which the controller verifies
// like any run's cleanup; a journal that is not clean is never replaced.
func TestRefusedRunResultNamesTheRunAndLeavesACleanJournal(t *testing.T) {
	stateDir := t.TempDir()
	plan := &config.Plan{PlanID: "refused", Name: "Refused"}
	result := refusedRunResult(stateDir, "run-refused-1", preflightFailureResult(plan, "node-a", preflight.Result{
		Checks: []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: "reservation exceeds safe capacity"}},
	}, false))
	if result.Report == nil || result.Report.RunID != "run-refused-1" || result.Report.AllPassed {
		t.Fatalf("result = %+v", result)
	}
	active, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || active.RunID != "run-refused-1" || active.Phase != "cleaned" {
		t.Fatalf("journal = %+v, %v", active, err)
	}

	// A later refusal replaces the clean journal and keeps the transition.
	refusedRunResult(stateDir, "run-refused-2", nodeapi.RunResult{Report: failedNodeReport(plan, "node-a", "source metadata unavailable", false), Error: "source metadata unavailable"})
	if _, err := journal.LoadTransition(stateDir, "run-refused-1"); err != nil {
		t.Fatalf("the earlier refusal's transition was not kept: %v", err)
	}

	// An interrupted run's journal is left exactly as it is.
	interrupted := filepath.Join(t.TempDir())
	if err := journal.Write(filepath.Join(interrupted, "active.json"), journal.Record{RunID: "run-crashed", Phase: "running", VMs: []journal.TrackedVM{{VMID: 9001}}}); err != nil {
		t.Fatal(err)
	}
	result = refusedRunResult(interrupted, "run-refused-3", nodeapi.RunResult{Report: failedNodeReport(plan, "node-a", "x", false), Error: "x"})
	if result.Report.RunID != "run-refused-3" {
		t.Fatalf("the report does not name the run: %+v", result.Report)
	}
	if active, err := journal.Load(filepath.Join(interrupted, "active.json")); err != nil || active.RunID != "run-crashed" || active.Phase != "running" {
		t.Fatalf("the interrupted run's journal was replaced: %+v, %v", active, err)
	}

	// Without a run ID nothing is recorded.
	empty := t.TempDir()
	refusedRunResult(empty, "", nodeapi.RunResult{Report: failedNodeReport(plan, "node-a", "x", false)})
	if _, err := os.Stat(filepath.Join(empty, "active.json")); !os.IsNotExist(err) {
		t.Fatalf("a journal was written for a run without an ID: %v", err)
	}
}

func TestPreflightFailureRetainsStructuredMemorySample(t *testing.T) {
	plan := &config.Plan{PlanID: "preflight-memory", Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90}}
	evaluation := admission.Evaluation{Checks: 1, Decision: admission.DecisionPreflightDeniedMemory,
		HostTotalMiB: 10000, HostAvailableMiB: 1000, RequiredAvailableMiB: 2000}
	result := preflightFailureResult(plan, "node", preflight.Result{
		Checks: []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: "insufficient available RAM"}}, MemoryEvaluation: &evaluation,
	}, false)
	if result.Report.Admission.Evaluation == nil || result.Report.Admission.Evaluation.HostAvailableMiB != 1000 || result.Report.Admission.Evaluation.RequiredAvailableMiB != 2000 {
		t.Fatalf("memory sample lost in refusal: %+v", result.Report.Admission)
	}
}
