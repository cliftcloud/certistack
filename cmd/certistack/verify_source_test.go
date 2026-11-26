// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// Verify-report holds every VM record to the backup it names, with the
// rules the controller applies before it signs (attest.SourceProblems).
func TestReportAcceptanceHoldsEveryRecordToItsBackup(t *testing.T) {
	const pinned = "vm/100/2026-09-20T01:00:00Z"
	for _, tc := range []struct {
		name   string
		pinned bool
		mutate func(*attest.Report)
		want   string // empty: accepted
	}{
		{name: "the resolved latest of the plan's source VM"},
		{name: "the snapshot the plan pins", pinned: true, mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = pinned }},
		{name: "another snapshot than the one the plan pins", pinned: true,
			mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/100/2026-09-21T01:00:00Z" },
			want:   `VM 9001 records source snapshot "vm/100/2026-09-21T01:00:00Z"; the plan pins "vm/100/2026-09-20T01:00:00Z"`},
		{name: "no snapshot", mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "" },
			want: "VM 9001 records no source snapshot, so it does not say which backup it restored"},
		{name: "a snapshot that is no path", mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "latest" },
			want: `records source snapshot "latest", which is not a PBS snapshot path`},
		{name: "a snapshot of another VM than the record's source", mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/999/2026-09-27T03:12:59Z" },
			want: "a backup of VM 999, and source VM 100"},
		{name: "the latest of another VM than the plan's source", mutate: func(r *attest.Report) {
			r.VMRecords[0].SourceVMID, r.VMRecords[0].SourceSnapshot = 999, "vm/999/2026-09-27T03:12:59Z"
		}, want: "VM 9001 records source VM 999; the plan restores source VM 100"},
		{name: "a disk status no worker writes", mutate: func(r *attest.Report) { r.VMRecords[1].SourceDisks[0].IntegrityStatus = "Verified" },
			want: `disk "scsi0" records integrity_status "Verified", which no worker of this build writes`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := mustLoadFixturePlan()
			if tc.pinned {
				plan.Tiers[0].VMs[0].SourcePBS.Snapshot = pinned
			}
			report := fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
			if tc.mutate != nil {
				tc.mutate(report)
			}
			acceptance := accept.Evaluate(report, accept.Expectations{Outcome: accept.OutcomePass, Plan: plan})
			if tc.want == "" {
				if acceptance.Verdict != accept.Accepted {
					t.Fatalf("rejected: %q", acceptance.Reasons)
				}
				return
			}
			if acceptance.Verdict != accept.Rejected || !strings.Contains(strings.Join(acceptance.Reasons, "\n"), tc.want) {
				t.Fatalf("verdict %s, reasons %q; want a rejection for %q", acceptance.Verdict, acceptance.Reasons, tc.want)
			}
			// The same record is refused without a plan, when it contradicts itself.
			if !tc.pinned && !strings.Contains(tc.want, "plan restores") {
				unbound := accept.Evaluate(report, accept.Expectations{})
				if unbound.Verdict != accept.Rejected {
					t.Fatalf("a record that contradicts itself was accepted without a plan")
				}
			}
		})
	}
}

// A fault drill's failed VM names its backup too: the record is a failed one,
// and the rule is the same.
func TestAFaultDrillsRecordNamesItsBackup(t *testing.T) {
	plan := mustLoadFixturePlan()
	report := fixtureReport(plan, reportFixture{mode: accept.OutcomeFault})
	if acceptance := accept.Evaluate(report, fixtureExpectations(plan, accept.OutcomeFault)); acceptance.Verdict != accept.Accepted {
		t.Fatalf("the control was rejected: %q", acceptance.Reasons)
	}
	report.VMRecords[0].SourceSnapshot = ""
	acceptance := accept.Evaluate(report, fixtureExpectations(plan, accept.OutcomeFault))
	if acceptance.Verdict != accept.Rejected || !strings.Contains(strings.Join(acceptance.Reasons, "\n"), "records no source snapshot") {
		t.Fatalf("verdict %s, reasons %q; want the fault target's missing backup rejected", acceptance.Verdict, acceptance.Reasons)
	}
}

// The probe policy rules are the controller's too. Whatever the shared
// function finds in a record, verify-report rejects in the same words, and a
// report of a schema that never recorded the policy is not held to it.
func TestTheVerifierAppliesTheControllersProbePolicyRules(t *testing.T) {
	plan := mustLoadFixturePlan()
	for name, mutate := range map[string]func(*probe.VMValidationRecord){
		"another timeout":               func(r *probe.VMValidationRecord) { r.ProbeResults[0].TimeoutSec = 1 },
		"retries the plan does not set": func(r *probe.VMValidationRecord) { r.ProbeResults[0].Retries = 2 },
		"a qga probe recorded as required": func(r *probe.VMValidationRecord) {
			r.ProbeResults[2].RequireQGA = true
		},
		"another source address": func(r *probe.VMValidationRecord) { r.ProbeResults[0].SourceAddress = "10.9.9.9" },
		"a negative count":       func(r *probe.VMValidationRecord) { r.ProbeResults[1].Attempts = -1 },
	} {
		report := fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
		mutate(&report.VMRecords[0])
		want := attest.ProbePolicyProblems(report.VMRecords[0], findPlanVM(plan, report.VMRecords[0].VMID), plan)
		if len(want) == 0 {
			t.Fatalf("%s: the shared rules found nothing in the record", name)
		}
		acceptance := accept.Evaluate(report, accept.Expectations{Outcome: accept.OutcomePass, Plan: plan})
		reasons := strings.Join(acceptance.Reasons, "\n")
		for _, message := range want {
			if !strings.Contains(reasons, message) {
				t.Errorf("%s: the verifier does not reject %q; its reasons are %q", name, message, acceptance.Reasons)
			}
		}
		// A report that predates schema 1.6 never recorded the policy.
		report.ReportSchemaVersion = "1.5"
		if older := accept.Evaluate(report, accept.Expectations{Outcome: accept.OutcomePass, Plan: plan}); strings.Contains(strings.Join(older.Reasons, "\n"), want[0]) {
			t.Errorf("%s: a schema 1.5 report was held to a policy it never recorded: %q", name, older.Reasons)
		}
	}
}
