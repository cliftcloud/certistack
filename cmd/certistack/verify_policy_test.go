// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
)

// A pass states the recovery time objective and the host admission limits it
// passed under, the verdict holds them to the plan, and the default view prints
// them. The reporters' collisions (objectives of 60 and 300 seconds, RAM limits
// of 70 and 90 percent, one 42-second pass) were byte-identical signed reports
// a verifier could not tell apart.

// planWithPolicy is the fixture plan with an objective (0 leaves it out) and a
// RAM limit.
func planWithPolicy(target, maxRAM float64) *config.Plan {
	plan := *mustLoadFixturePlan()
	plan.Compliance.RTOTargetSeconds = target
	plan.AdmissionControl.MaxHostRAMPercent = maxRAM
	return &plan
}

// passUnder is a passing 42-second report of the plan, recording the policy
// the plan sets, as the controller signs it.
func passUnder(plan *config.Plan) *attest.Report {
	report := passReport(plan)
	report.RTOSeconds = 42
	report.RTOTargetSeconds = attest.RTOObjective(plan)
	report.Admission = fixtureGrantedAdmission(attest.NewAdmissionEvidence(plan))
	return report
}

func expectsPlan(plan *config.Plan) accept.Expectations {
	exp := fixtureExpectations(plan, accept.OutcomePass)
	exp.PlanSHA256 = "" // the digest is of the fixture file, which these plans only resemble
	return exp
}

func TestVerifierHoldsTheObjectiveAndTheAdmissionLimitsToThePlan(t *testing.T) {
	strict, permissive := planWithPolicy(60, 70), planWithPolicy(300, 90)
	strictReport, permissiveReport := passUnder(strict), passUnder(permissive)

	// Each is accepted against the plan it ran under, and the verdict says the
	// objective and the limits were checked.
	for name, tc := range map[string]struct {
		report *attest.Report
		plan   *config.Plan
	}{"strict": {strictReport, strict}, "permissive": {permissiveReport, permissive}} {
		expectAccepted(t, name+" against its own plan", tc.report, expectsPlan(tc.plan))
		if got := bindingList(tc.report, expectsPlan(tc.plan)); !strings.Contains(got, "rto_objective | admission_policy") || strings.Contains(got, accept.UnboundPrefix+"RTO") {
			t.Errorf("%s: bindings = %s, want the objective and the admission policy bound", name, got)
		}
	}
	// The same pass against the other plan is another assertion: rejected, for
	// the objective and for each limit.
	expectRejected(t, "a pass under 300 s given the plan that asks 60 s", permissiveReport, expectsPlan(strict),
		"the report records a recovery time objective of 300s, and the plan's is 60s")
	expectRejected(t, "a pass under 60 s given the plan that asks 300 s", strictReport, expectsPlan(permissive),
		"the report records a recovery time objective of 60s, and the plan's is 300s")
	expectRejected(t, "a RAM limit of 90% given the plan that holds 70%", permissiveReport, expectsPlan(strict),
		"admission max_host_ram_percent is 90, and the plan's is 70")
	expectRejected(t, "a RAM limit of 70% given the plan that allows 90%", strictReport, expectsPlan(permissive),
		"admission max_host_ram_percent is 70, and the plan's is 90")

	// A plan with no objective: a report that records one is not its pass, and
	// a report that records none is.
	none := planWithPolicy(0, 70)
	expectAccepted(t, "no objective on either side", passUnder(none), expectsPlan(none))
	expectRejected(t, "an objective the plan does not set", strictReport, expectsPlan(none), "and the plan sets none")
	missing := passUnder(strict)
	missing.RTOTargetSeconds = nil
	expectRejected(t, "no objective recorded for a plan that sets one", missing, expectsPlan(strict), "records no recovery time objective, and the plan's is 60s")
}

// Without a plan the report is held to itself.
func TestVerifierHoldsTheReportToItsOwnPolicy(t *testing.T) {
	none := accept.Expectations{}
	plan := planWithPolicy(60, 70)
	expectAccepted(t, "a consistent report", passUnder(plan), none)

	late := passUnder(plan)
	late.RTOSeconds = 61
	expectRejected(t, "a pass over its own objective", late, none, "over its own objective of 60.0s")

	unrecorded := passUnder(plan)
	unrecorded.Admission = nil
	expectRejected(t, "a report with no admission policy", unrecorded, none, "records no host admission policy")

	loose := passUnder(plan)
	loose.Admission.Evaluation.HostRAMPercent = 71
	expectRejected(t, "an admission granted over its own limit", loose, none, "granted with host RAM at 71.00%, over the limit of 70.00%")

	unchecked := passUnder(plan)
	unchecked.Admission.Evaluation = nil
	expectRejected(t, "a pass no admission check let start", unchecked, none, "no admission check that let the run start")

	refused := passUnder(plan)
	refused.Admission.Evaluation.Decision = admission.DecisionDeniedProjectedRAM
	refused.Admission.Evaluation.ProjectedRAMPercent = 71
	expectRejected(t, "VMs recorded for a run whose admission was refused", refused, none, "decided denied_projected_ram, and the report records VMs or claims a pass")
}

// A report of schema 1.6, written before the objective and the limits were
// recorded, is still judged on what it did record, and the verdict says what it
// could not check.
func TestVerifierJudgesASchema16ReportOnWhatItRecorded(t *testing.T) {
	plan := planWithPolicy(60, 70)
	older := passUnder(plan)
	older.ReportSchemaVersion = "1.6"
	older.RTOTargetSeconds, older.Admission = nil, nil
	expectAccepted(t, "a schema 1.6 report", older, expectsPlan(plan))
	got := bindingList(older, expectsPlan(plan))
	if !strings.Contains(got, accept.UnboundPrefix+"RTO objective and admission policy (report schema \"1.6\" predates 1.7") || strings.Contains(got, "rto_objective") {
		t.Errorf("bindings = %s, want the objective and the admission policy listed as not bound", got)
	}
	// With no plan it says nothing of them.
	expectAccepted(t, "a schema 1.6 report without a plan", older, accept.Expectations{})
}

// The default view prints what the pass was a pass of; the JSON summary carries
// it too.
func TestVerifyReportPrintsTheObjectiveAndTheAdmissionPolicy(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(public)
	dir := t.TempDir()
	plan := planWithPolicy(60, 70)
	plan.AdmissionControl.MaxConcurrentBoots = 2
	path := writeSignedFixture(t, dir, passUnder(plan), private)

	text, err := runVerifyReport("--trusted-key", trusted, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"RTO:         42.00 seconds",
		"RTO Target:  60.00 seconds (met)",
		"Admission Policy:",
		"Limits:                RAM 70.0%, I/O wait",
		"a check every",
		"Boot Gate:             2 concurrent boot(s), each counted for 180 s",
		"Recovery Reservation:",
		"Last Check:            granted (check 1)",
		"Measured:              RAM 10.0% in use, I/O wait 0.5%, projected RAM",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text output lacks %q:\n%s", want, text)
		}
	}

	over := passUnder(plan)
	over.AllPassed, over.RTOSeconds, over.FailureReason = false, 90, "recovery time objective exceeded: completed in 90.0s, target was 60.0s"
	overPath := writeSignedFixture(t, dir, over, private)
	if text, err = runVerifyReport("--trusted-key", trusted, overPath); err != nil || !strings.Contains(text, "RTO Target:  60.00 seconds (EXCEEDED)") {
		t.Errorf("a missed objective is not printed as exceeded (err=%v):\n%s", err, text)
	}

	noObjective := planWithPolicy(0, 70)
	if text, err = runVerifyReport("--trusted-key", trusted, writeSignedFixture(t, dir, passUnder(noObjective), private)); err != nil || !strings.Contains(text, "RTO Target:  none set") {
		t.Errorf("a report without an objective does not say so (err=%v):\n%s", err, text)
	}

	older := passUnder(plan)
	older.ReportSchemaVersion, older.RTOTargetSeconds, older.Admission = "1.6", nil, nil
	if text, err = runVerifyReport("--trusted-key", trusted, writeSignedFixture(t, dir, older, private)); err != nil ||
		!strings.Contains(text, "RTO Target:  not recorded (schema 1.6 predates 1.7") || strings.Contains(text, "Admission Policy") {
		t.Errorf("a schema 1.6 report is not described as such (err=%v):\n%s", err, text)
	}

	jsonOut, err := runVerifyReport("--format", "json", "--trusted-key", trusted, path)
	if err != nil {
		t.Fatal(err)
	}
	var summary reportVerificationSummary
	if err := json.Unmarshal([]byte(jsonOut), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.RTOSeconds != 42 || summary.RTOTargetSeconds == nil || *summary.RTOTargetSeconds != 60 ||
		summary.Admission == nil || summary.Admission.MaxHostRAMPercent != 70 || summary.Admission.Evaluation == nil ||
		summary.Admission.Evaluation.Decision != admission.DecisionGranted {
		t.Errorf("the JSON summary lacks the objective or the admission policy: %+v", summary)
	}
}

// A decision a report supplies is printed through the sanitizer, whatever it
// says, and the report is rejected for it.
func TestAnUnknownAdmissionDecisionIsSanitisedAndRejected(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := planWithPolicy(60, 70)
	report := passUnder(plan)
	report.Admission.Evaluation.Decision = "approved\x1b[31m\u202egranted"
	path := writeSignedFixture(t, t.TempDir(), report, private)
	text, err := runVerifyReport("--trusted-key", hex.EncodeToString(public), path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Errorf("a control or bidi character of the decision reached the terminal: %q", text)
	}
	if !strings.Contains(text, "REJECTED") {
		t.Errorf("a report with an unknown decision is not rejected:\n%s", text)
	}
}
