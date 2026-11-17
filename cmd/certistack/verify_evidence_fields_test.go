// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The acceptance verdict holds a report of schema 1.6 to the evidence it
// carries: the digest of the plan file (plan_sha256) and, for each probe, the
// policy it ran under. A report of an earlier schema is accepted on what it
// records, and the verdict says which expectations it could not check.

func bindingList(report *attest.Report, exp accept.Expectations) string {
	return strings.Join(accept.Evaluate(report, exp).Bindings, " | ")
}

// The digest binds the report to the exact plan file bytes.
func TestReportAcceptanceBindsThePlanFileDigest(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)

	report := passReport(plan)
	expectAccepted(t, "the plan file's own digest", report, exp)
	if got := bindingList(report, exp); !strings.Contains(got, "plan_sha256") || strings.Contains(got, accept.UnboundPrefix) {
		t.Errorf("bindings = %s, want the digest bound and nothing unbound", got)
	}

	other := passReport(plan)
	other.PlanSHA256 = strings.Repeat("0", 64)
	expectRejected(t, "another plan file with the same plan ID, VMs and probes", other, exp,
		"the report is for a plan file with SHA-256 "+strings.Repeat("0", 64)+", not the expected plan file's "+fixturePlanDigest())

	malformed := passReport(plan)
	malformed.PlanSHA256 = "not-a-digest"
	expectRejected(t, "a malformed digest", malformed, exp, "is not a SHA-256 digest")
	expectRejected(t, "a malformed digest without a plan", malformed, accept.Expectations{}, "is not a SHA-256 digest")

	// A report without the digest (an earlier schema, or none from a direct
	// node run) is accepted on its plan ID, VMs and probes, and the
	// verdict says the digest was not bound.
	older := passReport(plan)
	older.PlanSHA256 = ""
	expectAccepted(t, "a report without a digest", older, exp)
	if got := bindingList(older, exp); !strings.Contains(got, accept.UnboundPrefix+"plan digest (the report carries no plan_sha256") || strings.Contains(got, "plan_sha256 |") {
		t.Errorf("bindings = %s, want the plan digest listed as not bound", got)
	}

	// A caller with no digest of its plan file (a library caller) is told the
	// same, and nothing is bound without an expected plan.
	noFile := exp
	noFile.PlanSHA256 = ""
	if got := bindingList(passReport(plan), noFile); !strings.Contains(got, accept.UnboundPrefix+"plan digest (no digest of the expected plan file was given)") {
		t.Errorf("bindings = %s", got)
	}
	if got := bindingList(passReport(plan), accept.Expectations{}); got != "" {
		t.Errorf("no expectations bind %q", got)
	}
}

// The plan file the CLI reads is digested as it lies on disk: a file that
// loads to the same plan but differs by a byte is another file.
func TestVerifyReportCLIComparesThePlanFileBytes(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	plan := mustLoadFixturePlan()
	path := writeSignedFixture(t, dir, passReport(plan), private)
	trusted := hex.EncodeToString(public)
	run := func(planPath string) (reportVerificationSummary, error) {
		output, err := runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-plan", planPath, path)
		var summary reportVerificationSummary
		if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
			t.Fatalf("decode summary: %v; output=%q", decodeErr, output)
		}
		return summary, err
	}
	if summary, err := run(fixturePlanPath); err != nil || summary.Acceptance.Verdict != accept.Accepted {
		t.Fatalf("the plan file the report names: err=%v acceptance=%+v", err, summary.Acceptance)
	}

	data, err := os.ReadFile(fixturePlanPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(edited, append(data, []byte("\n# a comment\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := run(edited)
	if err == nil || summary.Acceptance.Verdict != accept.Rejected || !strings.Contains(strings.Join(summary.Acceptance.Reasons, "\n"), "the report is for a plan file with SHA-256") {
		t.Fatalf("a plan file that differs by a comment: err=%v acceptance=%+v", err, summary.Acceptance)
	}

	// The text output says which expectation it could not check.
	older := passReport(plan)
	older.PlanSHA256 = ""
	olderPath := writeSignedFixture(t, dir, older, private)
	output, err := runVerifyReport("--trusted-key", trusted, "--expect-plan", fixturePlanPath, olderPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "checked against the expected plan, probe_policy, rto_objective, admission_policy; NOT BOUND: plan digest (the report carries no plan_sha256") {
		t.Fatalf("text output does not say the plan digest was not bound: %q", output)
	}
}

// A report is held to the timeout and retries each probe ran under, the
// guest-agent requirement, the virtual host and the source, when the plan is
// given. The fixture plan's VM 9001 has a tcp probe (30 s) first and an
// optional qga probe third; VM 9003's first probe is http.
func TestReportAcceptanceHoldsProbesToTheirPlannedPolicy(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	expectAccepted(t, "the recorded policy of the plan's own probes", passReport(plan), exp)

	for _, tc := range []struct {
		name   string
		vm     int // index into the report's records
		probe  int
		mutate func(*probe.Result)
		want   string
	}{
		{"a shorter timeout", 0, 0, func(r *probe.Result) { r.TimeoutSec = 29 }, "ran under a timeout of 29 s; the plan configures 30 s"},
		{"a longer timeout", 0, 0, func(r *probe.Result) { r.TimeoutSec = 90 }, "ran under a timeout of 90 s; the plan configures 30 s"},
		{"no timeout recorded", 0, 0, func(r *probe.Result) { r.TimeoutSec = 0 }, "ran under a timeout of 0 s; the plan configures 30 s"},
		{"retries the plan does not set", 0, 0, func(r *probe.Result) { r.Retries = 3 }, "records retries 3; the plan configures 0"},
		{"another source address", 0, 0, func(r *probe.Result) { r.SourceAddress = "192.0.2.99" }, `was bound to source "192.0.2.99" on interface "csVn01"; the plan's sandbox probes from "192.0.2.1" on "csVn01"`},
		{"another source interface", 0, 0, func(r *probe.Result) { r.SourceInterface = "csVn99" }, "was bound to source"},
		{"no source recorded", 0, 0, func(r *probe.Result) { r.SourceAddress, r.SourceInterface = "", "" }, "was bound to source"},
		{"a guest agent recorded as required that the plan makes optional", 0, 2, func(r *probe.Result) { r.RequireQGA = true }, "is recorded as requiring the guest agent; the plan makes it optional"},
		{"a virtual host the plan does not name", 2, 0, func(r *probe.Result) { r.ServerName = "other.example.test" }, `asserted virtual host "other.example.test"; the plan configures ""`},
	} {
		report := passReport(plan)
		tc.mutate(&report.VMRecords[tc.vm].ProbeResults[tc.probe])
		expectRejected(t, tc.name, report, exp, tc.want)
		// The verdict of a report never judged against a plan does not
		// depend on the plan's policy.
		if tc.name != "a guest agent recorded as required that the plan makes optional" {
			expectAccepted(t, tc.name+" (no plan to compare to)", report, accept.Expectations{})
		}
	}

	// A plan that requires the guest agent: a result that does not record it
	// as required is not the probe the plan asked for.
	required := mustLoadFixturePlan()
	required.Tiers[0].VMs[0].Probes[2].RequireQGA = true
	report := passReport(required)
	if !report.VMRecords[0].ProbeResults[2].RequireQGA {
		t.Fatal("the fixture does not record a required probe as required")
	}
	expectAccepted(t, "a required guest-agent probe recorded as required", report, fixtureExpectations(required, accept.OutcomePass))
	report.VMRecords[0].ProbeResults[2].RequireQGA = false
	expectRejected(t, "a required guest-agent probe recorded as optional", report, fixtureExpectations(required, accept.OutcomePass), "is not recorded as requiring the guest agent; the plan sets require_qga")

	// A plan that names a virtual host: the result must assert it.
	named := mustLoadFixturePlan()
	named.Tiers[2].VMs[0].Probes[0].ServerName = "app.example.test"
	report = passReport(named)
	expectAccepted(t, "the named virtual host", report, fixtureExpectations(named, accept.OutcomePass))
	report.VMRecords[2].ProbeResults[0].ServerName = ""
	expectRejected(t, "the bare address where the plan names a host", report, fixtureExpectations(named, accept.OutcomePass), `asserted virtual host ""; the plan configures "app.example.test"`)

	// An mssql probe that names a server: the result must record the name its
	// certificate was verified for, and a result that records one the plan
	// does not name is not that probe.
	sql := mustLoadFixturePlan()
	sql.Tiers[2].VMs[0].Probes[0] = config.Probe{Type: "mssql", TargetIP: sql.Tiers[2].VMs[0].Probes[0].TargetIP, Port: 1433, ServerName: "sql.example.test", TimeoutSec: 30, Description: "SQL Server answers"}
	report = passReport(sql)
	if got := report.VMRecords[2].ProbeResults[0].ServerName; got != "sql.example.test" {
		t.Fatalf("the fixture records server name %q for the mssql probe", got)
	}
	expectAccepted(t, "the named SQL Server", report, fixtureExpectations(sql, accept.OutcomePass))
	report.VMRecords[2].ProbeResults[0].ServerName = ""
	expectRejected(t, "an mssql probe that verified no name where the plan names one", report, fixtureExpectations(sql, accept.OutcomePass), `verified the certificate for server name ""; the plan configures "sql.example.test"`)
	report.VMRecords[2].ProbeResults[0].ServerName = "other.example.test"
	expectRejected(t, "an mssql probe that verified another name", report, fixtureExpectations(sql, accept.OutcomePass), `verified the certificate for server name "other.example.test"; the plan configures "sql.example.test"`)
	unnamed := mustLoadFixturePlan()
	unnamed.Tiers[2].VMs[0].Probes[0] = config.Probe{Type: "mssql", TargetIP: unnamed.Tiers[2].VMs[0].Probes[0].TargetIP, Port: 1433, TimeoutSec: 30, Description: "SQL Server answers"}
	report = passReport(unnamed)
	expectAccepted(t, "an mssql probe with no server name", report, fixtureExpectations(unnamed, accept.OutcomePass))
	report.VMRecords[2].ProbeResults[0].ServerName = "sql.example.test"
	expectRejected(t, "an mssql result that claims a verified name the plan does not set", report, fixtureExpectations(unnamed, accept.OutcomePass), `verified the certificate for server name "sql.example.test"; the plan configures ""`)

	// More attempts than a positive retries value allows is impossible.
	capped := mustLoadFixturePlan()
	capped.Tiers[0].VMs[0].Probes[0].Retries = 2
	report = passReport(capped)
	report.VMRecords[0].ProbeResults[0].Attempts = 4
	expectRejected(t, "four attempts under retries: 2", report, fixtureExpectations(capped, accept.OutcomePass), "records 4 attempts, more than the plan's retries 2 allow (3)")
	report.VMRecords[0].ProbeResults[0].Attempts = 3
	expectAccepted(t, "three attempts under retries: 2", report, fixtureExpectations(capped, accept.OutcomePass))
}

// A report of schema 1.5 or earlier does not record the policy, so it cannot
// be held to it; it is accepted on what it records and the verdict says so.
func TestReportAcceptanceDoesNotHoldAnEarlierSchemaToPolicyItNeverRecorded(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	for _, version := range []string{"1.0", "1.4", "1.5"} {
		report := passReport(plan)
		report.ReportSchemaVersion = version
		report.PlanSHA256 = ""
		for vmIndex := range report.VMRecords {
			for probeIndex := range report.VMRecords[vmIndex].ProbeResults {
				result := &report.VMRecords[vmIndex].ProbeResults[probeIndex]
				result.TimeoutSec, result.Retries, result.Attempts, result.RequireQGA = 0, 0, 0, false
				result.ServerName, result.SourceAddress, result.SourceInterface, result.ImageSHA256 = "", "", "", ""
			}
		}
		expectAccepted(t, "schema "+version+" with no policy recorded", report, exp)
		got := bindingList(report, exp)
		if !strings.Contains(got, accept.UnboundPrefix+"probe policy (report schema \""+version+"\" predates 1.6") || !strings.Contains(got, accept.UnboundPrefix+"plan digest") {
			t.Errorf("schema %s: bindings = %s, want the probe policy and the plan digest listed as not bound", version, got)
		}
	}
}

// A guest-agent probe the report records as required cannot be a skip,
// with a plan or without one; before schema 1.6 a required probe that was
// skipped could be told from an optional one only through the plan.
func TestReportAcceptanceRejectsASkippedProbeItRecordsAsRequired(t *testing.T) {
	plan := mustLoadFixturePlan()
	report := passReport(plan)
	var qga *probe.Result
	for vmIndex, record := range report.VMRecords {
		for probeIndex, result := range record.ProbeResults {
			if result.Type == "qga" && qga == nil {
				qga = &report.VMRecords[vmIndex].ProbeResults[probeIndex]
			}
		}
	}
	if qga == nil {
		t.Fatal("the fixture plan has no qga probe")
	}
	qga.Skipped, qga.RequireQGA = true, true
	expectRejected(t, "a skipped probe recorded as required, no plan", report, accept.Expectations{}, "is required but was skipped")
	qga.RequireQGA = false
	expectAccepted(t, "the same skip recorded as optional", report, accept.Expectations{})
}

// A screendump that passed must say which image it captured, since
// the image is not kept, and the digest must be one.
func TestReportAcceptanceRequiresTheScreendumpDigest(t *testing.T) {
	plan := mustLoadFixturePlan()
	plan.Tiers[0].VMs[0].Probes = append(plan.Tiers[0].VMs[0].Probes, config.Probe{Type: "screendump", Description: "Console screenshot", TimeoutSec: 10})
	exp := fixtureExpectations(plan, accept.OutcomePass)
	report := passReport(plan)
	screenshot := &report.VMRecords[0].ProbeResults[len(report.VMRecords[0].ProbeResults)-1]
	if screenshot.ImageSHA256 == "" {
		t.Fatal("the fixture's screendump result records no digest")
	}
	expectAccepted(t, "a screendump with its digest", report, exp)
	screenshot.ImageSHA256 = ""
	expectRejected(t, "a passed screendump without a digest", report, exp, "passed without recording the SHA-256 of the image it captured")
	expectRejected(t, "a passed screendump without a digest, no plan", report, accept.Expectations{}, "passed without recording the SHA-256 of the image it captured")
	screenshot.ImageSHA256 = "abc"
	expectRejected(t, "a screendump digest that is not one", report, exp, "records an image_sha256 that is not a SHA-256 digest")
	// A report that predates the digest never recorded one.
	report.ReportSchemaVersion = "1.5"
	screenshot.ImageSHA256 = ""
	expectAccepted(t, "a schema 1.5 screendump", report, exp)
}

func TestReportAcceptanceRejectsNegativeEvidenceCounts(t *testing.T) {
	plan := mustLoadFixturePlan()
	report := passReport(plan)
	report.VMRecords[0].ProbeResults[0].Attempts = -1
	expectRejected(t, "a negative attempt count", report, accept.Expectations{}, "records a negative timeout, retries or attempts count")
}
