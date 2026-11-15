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

// The signed worker_sha256 can be checked against the digest
// published for a release. A report bound to another executable, or one
// written before the digest was recorded, is not accepted; without the flag
// the verdict is as before.
func TestReportAcceptanceBindsTheWorkerExecutableDigest(t *testing.T) {
	plan := mustLoadFixturePlan()
	digest := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	fixture := campaignFixture{name: "matching_control", mode: accept.OutcomePass}
	for _, c := range []struct {
		name     string
		recorded string
		expected *string
		accepted bool
		reason   string
	}{
		{"the expected executable", digest, &digest, true, ""},
		{"another executable", other, &digest, false, "not the expected"},
		{"no digest recorded", "", &digest, false, "records no worker executable digest"},
		{"no expectation stated", other, nil, true, ""},
	} {
		report := campaignFixtureReport(plan, fixture)
		report.WorkerSHA256 = c.recorded
		exp := fixtureExpectations(plan, accept.OutcomePass)
		exp.WorkerSHA256 = c.expected
		acceptance := accept.Evaluate(report, exp)
		if got := acceptance.Verdict == accept.Accepted; got != c.accepted {
			t.Errorf("%s: verdict %s, want accepted=%v (%q)", c.name, acceptance.Verdict, c.accepted, acceptance.Reasons)
		}
		if c.reason != "" && !strings.Contains(strings.Join(acceptance.Reasons, "\n"), c.reason) {
			t.Errorf("%s: reasons %q lack %q", c.name, acceptance.Reasons, c.reason)
		}
		if strings.Join(acceptance.Bindings, ",") != "plan,plan_sha256,probe_policy,rto_objective,admission_policy,node,build,validation_mode" {
			t.Errorf("%s: bindings %q", c.name, acceptance.Bindings)
		}
	}
}

// The command takes the flag, refuses a value that is not a SHA-256, and
// verifies the digest a controller-signed report carries.
func TestVerifyReportExpectWorkerSHA256(t *testing.T) {
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	digest := strings.Repeat("ab", 32)
	report := campaignFixtureReport(plan, campaignFixture{name: "matching_control", mode: accept.OutcomePass})
	report.WorkerSHA256 = digest
	path := writeSignedFixture(t, dir, report, private)
	args := func(expect string) []string {
		return []string{
			"--format", "json", "--trusted-key", hex.EncodeToString(public),
			"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode, "--expect-version", fixtureVersion,
			"--expect-commit", fixtureCommit, "--expect-build-date", fixtureBuildDate,
			"--expect-validation-mode", attest.ValidationModeFullIntegrity, "--expect-worker-sha256", expect, path,
		}
	}

	output, err := runVerifyReport(args(digest)...)
	var summary reportVerificationSummary
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
		t.Fatalf("decode summary: %v; output=%q", decodeErr, output)
	}
	if err != nil || summary.Acceptance.Verdict != accept.Accepted {
		t.Fatalf("the signed digest was refused: err=%v acceptance=%+v", err, summary.Acceptance)
	}

	output, err = runVerifyReport(args(strings.Repeat("cd", 32))...)
	if err == nil || !strings.Contains(output, "not the expected") {
		t.Errorf("another executable was accepted: err=%v output=%q", err, output)
	}

	for _, bad := range []string{"", "ABCD", strings.ToUpper(digest), "sha256:" + digest, digest + "00"} {
		if _, err := runVerifyReport(args(bad)...); err == nil {
			t.Errorf("--expect-worker-sha256 %q was accepted", bad)
		}
	}
}
