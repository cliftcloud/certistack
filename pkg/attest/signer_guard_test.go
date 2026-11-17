// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// The signer attests the content the controller checked;
// it does not rewrite it. And whoever calls ApplySigner is not brought down by a
// signer that panics or by a nil one in a typed interface.

type mutatingSigner struct {
	key    ed25519.PrivateKey
	mutate func(*attest.Report)
}

func (m mutatingSigner) SignReport(report *attest.Report) error {
	m.mutate(report)
	return attesttest.SignReport(report, m.key)
}

func TestApplySignerRefusesASignerThatChangesTheEvidenceItWasAskedToAttest(t *testing.T) {
	_, private := testKeys(t)
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
	}{
		{"a verdict", func(r *attest.Report) { r.AllPassed = !r.AllPassed; r.FailureReason = "changed by the signer" }},
		{"a value inside a list the report already held", func(r *attest.Report) { r.Frameworks[0] = "CHANGED" }},
		{"a plan digest", func(r *attest.Report) { r.PlanSHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := unsignedTestReport()
			report.Frameworks = []string{"DORA-Article-12", "SOC2-Type2-CC7.4"}
			before, err := report.CanonicalForm()
			if err != nil {
				t.Fatal(err)
			}
			err = attest.ApplySigner(report, mutatingSigner{private, tc.mutate})
			if err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("ApplySigner = %v, want a refusal that says the signer changed the report", err)
			}
			if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
				t.Errorf("the report was left with signature members: %+v", report)
			}
			after, err := report.CanonicalForm()
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Errorf("the report was left as the signer changed it, not as it was:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// A signer that adds only the signature members (and a timestamp of its own, an
// unsigned member too) is the case the function exists for.
func TestApplySignerStillAcceptsASignerThatOnlyAddsTheSignatureMembers(t *testing.T) {
	public, private := testKeys(t)
	report := unsignedTestReport()
	if err := attest.ApplySigner(report, attesttest.NewSigner(private)); err != nil {
		t.Fatal(err)
	}
	if report.Signature == "" || report.PublicKey == "" || report.SignerFingerprint != attest.Fingerprint(public) {
		t.Errorf("the report is not signed: %+v", report)
	}
}

type panickingSigner struct{}

func (panickingSigner) SignReport(*attest.Report) error { panic("the key store crashed") }

func TestApplySignerContainsASignerThatPanics(t *testing.T) {
	report := unsignedTestReport()
	err := attest.ApplySigner(report, panickingSigner{})
	if err == nil || !strings.Contains(err.Error(), "panicked") || !strings.Contains(err.Error(), "the key store crashed") {
		t.Fatalf("ApplySigner = %v, want an error that says the signer panicked", err)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" {
		t.Errorf("the report was left with signature members: %+v", report)
	}
}

// An Enterprise controller whose key is missing could pass a nil *Signer in the
// interface. That is a signer that was meant to sign and cannot, not "no
// signer": the run must fail, not finish unsigned (the Enterprise Edition's
// signer test pins the same rule).
func TestApplySignerRefusesATypedNilSignerAndLeavesTheReportUnsigned(t *testing.T) {
	var signer *attesttest.Signer
	report := reportCarryingSignatureMembers()
	if err := attest.ApplySigner(report, signer); err == nil {
		t.Fatal("ApplySigner with a nil *Signer succeeded, want a refusal: a signer was supplied but holds nothing to sign with")
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
		t.Errorf("a typed-nil signer left signature members: %+v", report)
	}
}

// A nil interface is the Community Edition: no signer, no error, no signature.
func TestApplySignerWithANilInterfaceSignsNothingAndSucceeds(t *testing.T) {
	report := reportCarryingSignatureMembers()
	if err := attest.ApplySigner(report, nil); err != nil {
		t.Fatalf("ApplySigner with no signer = %v", err)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" {
		t.Errorf("no signer, yet signature members remain: %+v", report)
	}
}
