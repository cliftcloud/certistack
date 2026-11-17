// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// withSupport is the plan fixture's passing report with the Proxmox members a
// run records; support "" leaves them all out, as a build that did not record
// them does.
func withSupport(support string) *attest.Report {
	report := passReport(mustLoadFixturePlan())
	switch support {
	case "":
	case "unknown":
		report.PVEVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.5", support
	default:
		report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.7", "4.2.5", support
	}
	return report
}

// A release lane asks for tested evidence: --expect-version-support binds the
// verdict to the report's signed version_support, exactly. A report without
// the member cannot be held to it, and is not accepted.
func TestReportAcceptanceBindsTheVersionSupport(t *testing.T) {
	plan := mustLoadFixturePlan()
	for _, c := range []struct {
		recorded, expected string
		accepted           bool
		reason             string
	}{
		{"tested", "tested", true, ""},
		{"untested", "untested", true, ""},
		{"untested", "tested", false, `records version_support "untested", not the expected "tested"`},
		{"tested", "untested", false, `records version_support "tested", not the expected "untested"`},
		{"unknown", "tested", false, `records version_support "unknown", not the expected "tested"`},
		{"unknown", "untested", false, `records version_support "unknown", not the expected "untested"`},
		{"", "tested", false, `records no version_support`},
		{"", "untested", false, `records no version_support`},
		{"tested", "", true, ""},
		{"untested", "", true, ""},
		{"", "", true, ""},
	} {
		name := "recorded " + c.recorded + ", expected " + c.expected
		exp := fixtureExpectations(plan, accept.OutcomePass)
		if c.expected != "" {
			expected := c.expected
			exp.VersionSupport = &expected
		}
		acceptance := accept.Evaluate(withSupport(c.recorded), exp)
		if got := acceptance.Verdict == accept.Accepted; got != c.accepted {
			t.Errorf("%s: verdict %s, want accepted=%v (%q)", name, acceptance.Verdict, c.accepted, acceptance.Reasons)
		}
		if c.reason != "" && !strings.Contains(strings.Join(acceptance.Reasons, "\n"), c.reason) {
			t.Errorf("%s: reasons %q lack %q", name, acceptance.Reasons, c.reason)
		}
		bindings := strings.Join(acceptance.Bindings, ",")
		if bound := strings.HasSuffix(bindings, ",version_support"); bound != (c.expected != "") {
			t.Errorf("%s: bindings %q; version_support is bound only when it is expected", name, bindings)
		}
	}
}

// A hostile version_support in a signed report is shown bounded, never raw.
func TestReportAcceptanceVersionSupportMismatchIsBounded(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	expected := "tested"
	exp.VersionSupport = &expected
	report := withSupport("tested")
	report.VersionSupport = "tested\x1b[31m" + strings.Repeat("x", 4000)
	accepted, reasons := verdictReasons(t, report, exp)
	if accepted || strings.Contains(reasons, "\x1b") || len(reasons) > 2000 {
		t.Errorf("accepted=%v, reasons carry %d bytes with a raw escape %v", accepted, len(reasons), strings.Contains(reasons, "\x1b"))
	}
}

// The command takes the flag: it accepts the one value that matches the signed
// report, rejects (exit status 1) the other, rejects a report without the
// member, and refuses any value but tested and untested as a usage error.
func TestVerifyReportExpectVersionSupport(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	signed := map[string]string{}
	for _, support := range []string{"tested", "untested", "unknown", ""} {
		report := withSupport(support)
		report.ReportID = "report-support-" + support
		signed[support] = writeSignedFixture(t, dir, report, private)
	}
	args := func(expect, path string) []string {
		return []string{
			"--format", "json", "--trusted-key", hex.EncodeToString(public),
			"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode, "--expect-version", fixtureVersion,
			"--expect-commit", fixtureCommit, "--expect-build-date", fixtureBuildDate,
			"--expect-validation-mode", attest.ValidationModeFullIntegrity, "--expect-version-support", expect, path,
		}
	}
	for _, c := range []struct {
		recorded, expected string
		accepted           bool
		reason             string
	}{
		{"tested", "tested", true, ""},
		{"untested", "untested", true, ""},
		{"untested", "tested", false, "not the expected"},
		{"tested", "untested", false, "not the expected"},
		{"unknown", "tested", false, "not the expected"},
		{"", "tested", false, "records no version_support"},
		{"", "untested", false, "records no version_support"},
	} {
		name := "recorded " + c.recorded + ", expected " + c.expected
		output, err := runVerifyReport(args(c.expected, signed[c.recorded])...)
		var summary reportVerificationSummary
		if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
			t.Fatalf("%s: decode summary: %v; output=%q", name, decodeErr, output)
		}
		if got := err == nil && summary.Acceptance.Verdict == accept.Accepted; got != c.accepted {
			t.Errorf("%s: err=%v acceptance=%+v, want accepted=%v", name, err, summary.Acceptance, c.accepted)
		}
		if c.reason != "" && !strings.Contains(strings.Join(summary.Acceptance.Reasons, "\n"), c.reason) {
			t.Errorf("%s: reasons %q lack %q", name, summary.Acceptance.Reasons, c.reason)
		}
		if !c.accepted && err == nil {
			t.Errorf("%s: a rejected report exited 0; an --expect-* flag makes the exit status follow the verdict", name)
		}
	}

	// The flag alone asks for the verdict to bind, too.
	output, err := runVerifyReport("--format", "json", "--trusted-key", hex.EncodeToString(public), "--expect-version-support", "tested", signed["untested"])
	if err == nil || !strings.Contains(output, "not the expected") {
		t.Errorf("--expect-version-support alone did not reject an untested report: err=%v output=%q", err, output)
	}

	for _, bad := range []string{"", " ", "unknown", "unsupported", "Tested", "TESTED", "tested ", "pass", "true"} {
		if _, err := runVerifyReport(args(bad, signed["tested"])...); err == nil {
			t.Errorf("--expect-version-support %q was accepted", bad)
		}
	}
}

// The usage text names the flag, with the two values it takes.
func TestVerifyReportDeclaresExpectVersionSupport(t *testing.T) {
	flag := verifyReportCmd().Flags().Lookup("expect-version-support")
	if flag == nil {
		t.Fatal("verify-report has no --expect-version-support")
	}
	for _, want := range []string{"tested", "untested", "version_support"} {
		if !strings.Contains(flag.Usage, want) {
			t.Errorf("usage %q lacks %q", flag.Usage, want)
		}
	}
	found := false
	for _, name := range expectationFlags {
		if name == "expect-version-support" {
			found = true
		}
	}
	if !found {
		t.Error("expect-version-support is not one of the expectation flags that make the exit status follow the verdict")
	}
}
