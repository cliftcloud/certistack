// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// A Community run has no Signer, and its report is unsigned, always. The node
// worker's report is decoded into the same type, so a signature member it
// carries would survive to the saved file: a file that reads as a signed
// report nobody has verified, and that verify-report --unsigned refuses. With
// no signer the members are cleared.

func reportCarryingSignatureMembers() *attest.Report {
	report := unsignedTestReport()
	report.Signature = strings.Repeat("ab", 64)
	report.PublicKey = strings.Repeat("cd", 32)
	report.SignerFingerprint = "SHA256:forged"
	report.SignatureTimestamp = &attest.TimestampToken{Authority: "Evil CA", Time: "2026-01-01T00:00:00Z", Token: "AAAA", HashAlgorithm: "sha256"}
	return report
}

func TestApplySignerWithNoSignerClearsTheSignatureMembersTheReportCarried(t *testing.T) {
	report := reportCarryingSignatureMembers()
	if err := attest.ApplySigner(report, nil); err != nil {
		t.Fatal(err)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
		t.Errorf("the report still carries signature members: %+v", report)
	}
	// What is saved after it carries none either.
	path := filepath.Join(t.TempDir(), "report.json")
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	for _, name := range attest.UnsignedReportMembers() {
		if _, present := members[name]; present {
			t.Errorf("the saved report has a %q member", name)
		}
	}
}
