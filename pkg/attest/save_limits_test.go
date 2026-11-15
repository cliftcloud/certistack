// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// Review R1-02. The structure and number limits of the verifier were enforced on
// the save path only as a side effect of signing, so with no signer a run could
// write a report its own verifier refuses (verify-report --unsigned and report
// show then cannot read what the run just wrote, and the run said it passed).
// Save holds the report to the same checks.
func TestSaveRefusesAReportItsOwnVerifierCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attest.Report)
		want   string
	}{
		{"an array of more than 65536 elements", func(r *attest.Report) {
			r.TeardownEvidence = &attest.TeardownEvidence{LoopDevicesUnmapped: make([]string, attest.MaxReportElements+1)}
		}, "more than 65536 elements"},
		{"a number a signature could not cover exactly", func(r *attest.Report) {
			r.RTOSeconds = 1e300
		}, "2^53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := unsignedTestReport()
			tc.mutate(report)
			path := filepath.Join(t.TempDir(), "report.json")
			err := report.Save(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Save = %v, want a refusal that says %q", err, tc.want)
			}
			if _, statErr := os.Stat(path); statErr == nil {
				t.Error("a report the verifier cannot read was written")
			}
		})
	}
	// A report within the limits is saved and read back by the unsigned decoder.
	report := unsignedTestReport()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attest.DecodeUnsignedReport(data); err != nil {
		t.Errorf("the saved report cannot be read back: %v", err)
	}
}
