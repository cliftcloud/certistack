// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package acceptance_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// The rules are exercised end to end, with signed and unsigned reports of the
// campaign fixtures, by the verify-report tests in cmd/certistack. These tests
// pin the exported surface the Enterprise Edition builds on.

// A report is judged by its contents. Whether it carries a signature is none of
// the rules' business: a report the Community Edition wrote unsigned and the
// same report signed get the same verdict, reasons and bindings.
func TestEvaluateDoesNotLookAtTheSignature(t *testing.T) {
	unsigned := &attest.Report{ReportSchemaVersion: attest.CurrentReportSchemaVersion, ReportID: "r", PlanID: "p", ValidationMode: attest.ValidationModeFullIntegrity, AllPassed: true}
	signed := *unsigned
	signed.Signature = strings.Repeat("ab", 64)
	signed.PublicKey = strings.Repeat("cd", 32)
	signed.SignerFingerprint = "SHA256:" + strings.Repeat("ef", 32)

	want := acceptance.Evaluate(unsigned, acceptance.Expectations{})
	got := acceptance.Evaluate(&signed, acceptance.Expectations{})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the signed report was judged differently:\nsigned:   %+v\nunsigned: %+v", got, want)
	}
	if want.Verdict != acceptance.Rejected || len(want.Reasons) == 0 {
		t.Fatalf("a report with no VM and no teardown evidence was not rejected: %+v", want)
	}
}

func TestEvaluateRejectsAnUnknownOutcomeAndKeepsItsJSONShape(t *testing.T) {
	report := &attest.Report{ReportSchemaVersion: attest.CurrentReportSchemaVersion, ValidationMode: attest.ValidationModeFullIntegrity}
	result := acceptance.Evaluate(report, acceptance.Expectations{Outcome: "passed"})
	if result.Verdict != acceptance.Rejected || !strings.Contains(strings.Join(result.Reasons, "\n"), `unsupported expected outcome "passed"`) {
		t.Fatalf("an unknown outcome: %+v", result)
	}
	if result.Outcome != "passed" {
		t.Errorf("Outcome = %q, want the outcome asked for", result.Outcome)
	}
	// An empty outcome is a pass; the bindings are an empty list, never null.
	empty := acceptance.Evaluate(report, acceptance.Expectations{})
	if empty.Outcome != acceptance.OutcomePass {
		t.Errorf("an empty outcome = %q, want %q", empty.Outcome, acceptance.OutcomePass)
	}
	data, err := json.Marshal(acceptance.Result{Verdict: acceptance.Accepted, Outcome: acceptance.OutcomePass, Bindings: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	// The authenticated member is the last, so what a consumer
	// matches at the start of the object is unchanged.
	if string(data) != `{"verdict":"accepted","expected_outcome":"pass","bindings":[],"authenticated":false}` {
		t.Errorf("verify-report's JSON shape changed: %s", data)
	}
	if empty.Bindings == nil {
		t.Error("Bindings is nil; it is an empty list")
	}
}

func TestValidationModeProblem(t *testing.T) {
	for _, test := range []struct {
		mode  string
		allow bool
		want  string // a fragment of the problem, "" for none
	}{
		{attest.ValidationModeFullIntegrity, false, ""},
		{attest.ValidationModeFullIntegrity, true, ""},
		{attest.ValidationModeTestSkipIntegrity, true, ""},
		{attest.ValidationModeTestSkipIntegrity, false, "test mode"},
		{"", false, "no supported validation mode"},
		{"Full_Integrity", true, "no supported validation mode"},
		{"full_integrity ", true, "no supported validation mode"},
	} {
		got := acceptance.ValidationModeProblem(test.mode, test.allow)
		if (test.want == "") != (got == "") || !strings.Contains(got, test.want) {
			t.Errorf("ValidationModeProblem(%q, %v) = %q, want %q", test.mode, test.allow, got, test.want)
		}
	}
}

func TestSchemaVersions(t *testing.T) {
	known := acceptance.SchemaMinor(attest.CurrentReportSchemaVersion)
	if known < acceptance.PolicyEvidenceSchemaMinor {
		t.Fatalf("the current schema 1.%d predates PolicyEvidenceSchemaMinor %d", known, acceptance.PolicyEvidenceSchemaMinor)
	}
	for version, want := range map[string]int{"1.0": 0, "1.7": 7, "1.10": 10, "1.9999": 9999, "1.05": -1, "1.": -1, "1.5.1": -1, "1.x": -1, "2.0": -1, "": -1, "1": -1, "1.-1": -1, "1.12345": -1} {
		if got := acceptance.SchemaMinor(version); got != want {
			t.Errorf("SchemaMinor(%q) = %d, want %d", version, got, want)
		}
	}
	for _, version := range []string{"1.0", "1.6", attest.CurrentReportSchemaVersion} {
		if problem := acceptance.SchemaProblem(version); problem != "" {
			t.Errorf("SchemaProblem(%q) = %q, want none", version, problem)
		}
	}
	newer := fmt.Sprintf("1.%d", known+1)
	if problem := acceptance.SchemaProblem(newer); !strings.Contains(problem, "newer than this verifier understands") {
		t.Errorf("SchemaProblem(%q) = %q", newer, problem)
	}
	if problem := acceptance.SchemaProblem("2.0"); !strings.Contains(problem, "is not a supported 1.x schema") {
		t.Errorf("SchemaProblem(2.0) = %q", problem)
	}
}

func TestCapacityDenial(t *testing.T) {
	denied := fmt.Errorf("%w: RAM usage 91.20%% exceeds max 5.00%%", admission.ErrAdmissionDenied)
	for reason, want := range map[string]bool{
		acceptance.AdmissionDenialPrefix + denied.Error():                                                   true,
		acceptance.AdmissionDenialPrefix + admission.ErrMaxRetriesExceeded.Error():                          true,
		acceptance.AdmissionDenialPrefix + admission.ErrNeverAdmissible.Error() + ": 200 GiB":               true,
		acceptance.PreflightFailurePrefix + "memory: available RAM 512 MB is below required 4096 MB":        true,
		acceptance.PreflightFailurePrefix + "memory: " + admission.ErrNeverAdmissible.Error() + ": 200 GiB": true,
		// Anchored at the start of the reason: nothing further in can satisfy it.
		"validation failed: " + acceptance.PreflightFailurePrefix + "memory: available RAM 512 MB is below required 4096 MB": false,
		// A broken node is not a full one.
		acceptance.PreflightFailurePrefix + "kvm: open /dev/kvm: no such file or directory; memory: available RAM 512 MB is below required 4096 MB": false,
		acceptance.AdmissionDenialPrefix + "failed to read host metrics":                                                                            false,
		"": false,
	} {
		if got := acceptance.CapacityDenial(reason); got != want {
			t.Errorf("CapacityDenial(%q) = %v, want %v", reason, got, want)
		}
	}
}

func TestBoundedReasonCutsAtAReadableLength(t *testing.T) {
	short := strings.Repeat("a", 240)
	if got := acceptance.BoundedReason(short); got != short {
		t.Errorf("a reason of exactly 240 characters was changed")
	}
	long := strings.Repeat("é", 300)
	got := acceptance.BoundedReason(long)
	if runes := []rune(got); len(runes) != 241 || runes[240] != '…' {
		t.Errorf("a reason of 300 characters became %d characters: %q", len(runes), got)
	}
}

// A report of the Community Edition is unsigned, so no reason may say a build
// "signed" a value or that a run is "not signed".
func TestRejectionReasonsDoNotTalkOfSigning(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	noDigest := &attest.Report{ReportSchemaVersion: attest.CurrentReportSchemaVersion, ValidationMode: attest.ValidationModeFullIntegrity}
	badSupport := &attest.Report{ReportSchemaVersion: attest.CurrentReportSchemaVersion, ValidationMode: attest.ValidationModeFullIntegrity, VersionSupport: "supported"}
	for name, result := range map[string]acceptance.Result{
		"no worker digest recorded": acceptance.Evaluate(noDigest, acceptance.Expectations{WorkerSHA256: &digest}),
		"unknown version support":   acceptance.Evaluate(badSupport, acceptance.Expectations{}),
	} {
		reasons := strings.Join(result.Reasons, "\n")
		if !strings.Contains(reasons, "worker executable digest") && !strings.Contains(reasons, "version_support") {
			t.Fatalf("%s: the case did not produce its reason: %+v", name, result)
		}
		if strings.Contains(reasons, " sign") {
			t.Errorf("%s: a reason talks of signing:\n%s", name, reasons)
		}
	}
}
