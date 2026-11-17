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

// sharedTargetReport is a passing run whose VM 9002 records
// its first probe at the very target VM 9001 recorded, so the one answer is
// credited to both records.
func sharedTargetReport() *attest.Report {
	return campaignFixtureReport(mustLoadFixturePlan(), campaignFixture{mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[1].ProbeResults[0].Target = r.VMRecords[0].ProbeResults[0].Target
	}})
}

// A signed report whose two distinct passing VM records share one wire target,
// with all_passed=true: the signature is valid (it proves who signed what, not
// that the content is evidence), and verify-report refuses the pass, with a
// plan or without one, naming both VMs and the address.
func TestVerifyReportRefusesOneWireTargetOnTwoVMRecords(t *testing.T) {
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(public)
	target := sharedTargetReport().VMRecords[0].ProbeResults[0].Target
	host := strings.Split(target, ":")[0]

	// The control: the plan's own targets are distinct and accepted.
	control := accept.Evaluate(campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass}), fixtureExpectations(plan, accept.OutcomePass))
	if control.Verdict != accept.Accepted {
		t.Fatalf("control rejected: %q", control.Reasons)
	}

	for name, expectations := range map[string]accept.Expectations{
		"no expectations": {},
		"with the plan":   fixtureExpectations(plan, accept.OutcomePass),
	} {
		acceptance := accept.Evaluate(sharedTargetReport(), expectations)
		joined := strings.Join(acceptance.Reasons, "\n")
		if acceptance.Verdict != accept.Rejected || !strings.Contains(joined, "VMs 9001, 9002 each record a passing wire probe of "+host) {
			t.Errorf("%s: verdict %s, reasons %q", name, acceptance.Verdict, acceptance.Reasons)
		}
	}

	// Through the command, signed by a trusted key: valid signature, rejected pass.
	path := writeSignedFixture(t, t.TempDir(), sharedTargetReport(), private)
	output, err := runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-outcome", "pass", path)
	var coded *exitCodeError
	if err == nil || !errors.As(err, &coded) || coded.code != exitCodeValidationFailed {
		t.Fatalf("err = %v, want a validation failure", err)
	}
	var summary reportVerificationSummary
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
		t.Fatalf("decode summary: %v; output=%q", decodeErr, output)
	}
	if !summary.SignatureValid || summary.Acceptance.Verdict != accept.Rejected {
		t.Fatalf("signature valid %v, acceptance %+v", summary.SignatureValid, summary.Acceptance)
	}
}

// A fault drill is held to the same rule: two passing records of one address
// are named, whatever else the verdict says about the drill.
func TestFaultDrillRefusesOneWireTargetOnTwoVMRecords(t *testing.T) {
	plan := mustLoadFixturePlan()
	report := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomeFault, mutate: func(r *attest.Report) {
		second, third := passedRecordFor(plan, 9002), passedRecordFor(plan, 9003)
		third.ProbeResults[0].Target = second.ProbeResults[0].Target
		r.VMRecords = append(r.VMRecords, second, third)
	}})
	acceptance := accept.Evaluate(report, fixtureExpectations(plan, accept.OutcomeFault))
	if joined := strings.Join(acceptance.Reasons, "; "); !strings.Contains(joined, "VMs 9002, 9003 each record a passing wire probe of") {
		t.Fatalf("verdict %s, reasons %q", acceptance.Verdict, acceptance.Reasons)
	}
}
