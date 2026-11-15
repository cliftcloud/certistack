// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"
	"time"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
)

// soakPlan is the fixture plan with a 90 s soak on its first tier.
func soakPlan() *config.Plan {
	plan := mustLoadFixturePlan()
	plan.Tiers[0].SoakTimeSec = 90
	return plan
}

// The verdict of a schema 1.7 report holds a VM of a tier with a soak
// to the service checks the soak ran, with a plan, and the same rules apply to
// the arithmetic of a summary without one.
func TestReportAcceptanceHoldsAPassToItsSoakChecks(t *testing.T) {
	plan := soakPlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	first := plan.Tiers[0].VMs[0].VMID

	honest := passReport(plan)
	expectAccepted(t, "an honest soak", honest, exp)
	if got := bindingList(honest, exp); !strings.Contains(got, "soak_checks") || strings.Contains(got, "soak service checks") {
		t.Errorf("bindings = %s, want the soak checks bound", got)
	}

	index := func(report *attest.Report) int {
		for i := range report.VMRecords {
			if report.VMRecords[i].VMID == first {
				return i
			}
		}
		return -1
	}
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"no summary", func(r *attest.Report) { r.VMRecords[index(r)].Soak = nil }, "passed without a record of its services being checked during its tier's 90 s soak"},
		{"a failed check", func(r *attest.Report) {
			soak := r.VMRecords[index(r)].Soak
			soak.FailedSamples = 1
			soak.Probes[0].Passed--
			soak.Probes[0].Failed, soak.Probes[0].FirstError = 1, "connection refused"
		}, "service check(s) failed"},
		{"a soak of another length", func(r *attest.Report) { r.VMRecords[index(r)].Soak.ConfiguredSec = 10 }, "records a soak of 10 s; the plan holds the tier for 90 s"},
		{"a last check before the end", func(r *attest.Report) {
			soak := r.VMRecords[index(r)].Soak
			soak.LastSampleAt = time.Date(2026, 9, 29, 11, 0, 30, 0, time.UTC).Format(time.RFC3339)
		}, "before the configured 90 s were over"},
		{"a probe left out of the summary", func(r *attest.Report) {
			soak := r.VMRecords[index(r)].Soak
			soak.Probes = soak.Probes[:len(soak.Probes)-1]
		}, "service probe(s) to repeat"},
		{"a summary on a tier with no soak", func(r *attest.Report) {
			other := r.VMRecords[len(r.VMRecords)-1]
			other.Soak = r.VMRecords[index(r)].Soak
			r.VMRecords[len(r.VMRecords)-1] = other
		}, "holds its tier for no soak"},
	} {
		report := passReport(plan)
		tc.mutate(report)
		expectRejected(t, tc.name, report, exp, tc.want)
	}

	// Without a plan there is nothing to require, but a summary that does not
	// add up is still refused.
	broken := passReport(plan)
	broken.VMRecords[index(broken)].Soak.FailedSamples = 9
	expectRejected(t, "a summary that does not add up, without a plan", broken, accept.Expectations{}, "records 9 failed check(s) of")
	expectAccepted(t, "an honest soak, without a plan", passReport(plan), accept.Expectations{})
}

// A report of an earlier schema never recorded the checks: it is accepted on
// what it does record, the verdict says the soak was not held to them, and a
// report of that schema that carries a summary anyway is refused.
func TestReportAcceptanceSaysWhenAnEarlierSchemaCouldNotRecordTheSoakChecks(t *testing.T) {
	plan := soakPlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)

	older := passReport(plan)
	older.ReportSchemaVersion = "1.6"
	for i := range older.VMRecords {
		older.VMRecords[i].Soak = nil
	}
	expectAccepted(t, "a schema 1.6 report", older, exp)
	if got := bindingList(older, exp); !strings.Contains(got, accept.UnboundPrefix+`soak service checks (report schema "1.6" predates 1.7`) || strings.Contains(got, "soak_checks") {
		t.Errorf("bindings = %s, want the soak checks listed as not bound", got)
	}

	forged := passReport(plan)
	forged.ReportSchemaVersion = "1.6"
	expectRejected(t, "a schema 1.6 report with a soak summary", forged, exp, "carries a soak summary, which the report's schema does not define")

	// A plan with no soak has nothing to bind or to leave unbound.
	plain := mustLoadFixturePlan()
	plainExp := fixtureExpectations(plain, accept.OutcomePass)
	if got := bindingList(passReport(plain), plainExp); strings.Contains(got, "soak") {
		t.Errorf("bindings = %s, want no mention of a soak the plan does not have", got)
	}
}

// A fault drill stops at its target's tier, before any soak: its VMs need no
// summary.
func TestReportAcceptanceDoesNotRequireASoakSummaryOfAFaultDrill(t *testing.T) {
	plan := soakPlan()
	report := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomeFault})
	for i := range report.VMRecords {
		report.VMRecords[i].Soak = nil
	}
	expectAccepted(t, "a fault drill with no soak summary", report, fixtureExpectations(plan, accept.OutcomeFault))
}

// verify-report shows what a soak checked, and the text it prints from a
// signed report goes through the same sanitiser as the rest.
func TestVerifyReportPrintsTheSoakChecks(t *testing.T) {
	plan := soakPlan()
	report := passReport(plan)
	var out strings.Builder
	writeSoakSummary(&out, report)
	text := out.String()
	for _, want := range []string{"Tier Soak Service Checks:", "VM 9001: 4 check(s) of ", "over 90s (every 30s), 0 failed", "PVE state read 5 time(s), 0 failed"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}

	failed := passReport(plan)
	soak := failed.VMRecords[0].Soak
	soak.FailedSamples, soak.StatusReadFailures, soak.FirstStatusError = 1, 1, "HTTP 401\x1b[2J \u202eevil"
	soak.Probes[0].Failed, soak.Probes[0].FirstError = 1, "refused\nsecond line \u202e"
	out.Reset()
	writeSoakSummary(&out, failed)
	for _, bad := range []string{"\x1b", "\u202e", "\nsecond"} {
		if strings.Contains(out.String(), bad) {
			t.Errorf("output carries %q unsanitised:\n%s", bad, out.String())
		}
	}
	if !strings.Contains(out.String(), "failed 1 time(s): refused") || !strings.Contains(out.String(), "first PVE status error: HTTP 401") {
		t.Errorf("output does not say what failed:\n%s", out.String())
	}

	out.Reset()
	writeSoakSummary(&out, passReport(mustLoadFixturePlan()))
	if out.Len() != 0 {
		t.Errorf("a plan with no soak printed %q", out.String())
	}
}
