// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// earlierFailedRun is a report as an earlier version (schema 1.5) wrote it for a
// run that failed: no run_id, plan_sha256 or worker_sha256, and the failed VM's
// record, whose restore stopped at a guard, naming neither a source snapshot
// nor its disks (the earlier version filled them in only once the restore had
// got past its guards). named builds the record of a failure after the restore,
// which an earlier version did name.
func earlierFailedRun(named bool) func(*attest.Report) {
	return func(r *attest.Report) {
		r.ReportSchemaVersion = "1.5"
		r.RunID, r.PlanSHA256, r.WorkerSHA256 = "", "", ""
		if !named {
			r.VMRecords[0].SourceSnapshot = ""
			r.VMRecords[0].SourceDisks = nil
		}
	}
}

// A failed run's report from an earlier version whose VM record names no snapshot
// and disk set verifies (its signature is genuine) but is not accepted by the current verifier as
// the evidence of a restore. It is the history of a failed run. A report of the same shape from a
// failure after the restore, which an earlier version did record, is still accepted, so it is the
// missing backup that is refused, not the earlier version.
func TestAnEarlierVersionsFailedRunThatNamesNoBackupIsNotAcceptedAsEvidence(t *testing.T) {
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(public)
	dir := t.TempDir()
	flags := []string{"--format", "json", "--trusted-key", trusted, "--expect-outcome", accept.OutcomeFault, "--expect-plan", fixturePlanPath}

	named := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomeFault, mutate: earlierFailedRun(true)})
	if acceptance := accept.Evaluate(named, accept.Expectations{Outcome: accept.OutcomeFault, Plan: plan}); acceptance.Verdict != accept.Accepted {
		t.Fatalf("the control, an earlier version's failure after the restore, was rejected: %q", acceptance.Reasons)
	}
	output, err := runVerifyReport(append(flags, writeSignedFixture(t, dir, named, private))...)
	var summary reportVerificationSummary
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil || err != nil || summary.Acceptance.Verdict != accept.Accepted {
		t.Fatalf("the control through the CLI: err=%v decode=%v acceptance=%+v", err, decodeErr, summary.Acceptance)
	}

	unnamed := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomeFault, mutate: earlierFailedRun(false)})
	acceptance := accept.Evaluate(unnamed, accept.Expectations{Outcome: accept.OutcomeFault, Plan: plan})
	reasons := strings.Join(acceptance.Reasons, "\n")
	if acceptance.Verdict != accept.Rejected ||
		!strings.Contains(reasons, "VM 9001 records no source snapshot, so it does not say which backup it restored") ||
		!strings.Contains(reasons, "VM 9001 records no source-disk integrity evidence") {
		t.Fatalf("an earlier version's failed run that names no backup: verdict %s, reasons %q", acceptance.Verdict, acceptance.Reasons)
	}

	// Through the CLI: the signature is valid, the verdict is rejected, and the
	// exit status is the validation failure's.
	output, err = runVerifyReport(append(flags, writeSignedFixture(t, dir, unnamed, private))...)
	var coded *exitCodeError
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil || !summary.SignatureValid {
		t.Fatalf("the signature of the earlier version's report is not reported valid: %v: %q", decodeErr, output)
	}
	if err == nil || !errors.As(err, &coded) || coded.code != exitCodeValidationFailed || summary.Acceptance.Verdict != accept.Rejected {
		t.Fatalf("the CLI: err=%v acceptance=%+v, want the rejected verdict and exit status %d", err, summary.Acceptance, exitCodeValidationFailed)
	}
}
