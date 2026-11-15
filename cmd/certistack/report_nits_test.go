// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review R1-13, the small ones.

// The refusal of a signed report under --unsigned read
// "the report carries a signature (report carries a signature (member "signature")): ...",
// the sentence twice.
func TestTheUnsignedRefusalNamesTheSignatureOnce(t *testing.T) {
	m := newUnsignedMatrix(t)
	_, _, err := runVerifyStreams("--unsigned", m.signed)
	if err == nil {
		t.Fatal("--unsigned accepted a signed report")
	}
	if got := strings.Count(err.Error(), "carries a signature"); got != 1 {
		t.Errorf("the refusal says the report carries a signature %d times: %v", got, err)
	}
	for _, want := range []string{`member "signature"`, "not an unsigned report", "--keyring"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q lacks %q", err, want)
		}
	}
}

// A report the Community Edition writes is a report, not a certificate: the
// flag that says where a run writes it does not call it one.
func TestRunDescribesWhatItWritesAsReports(t *testing.T) {
	cmd := runCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("run has no --output flag")
	}
	if strings.Contains(strings.ToLower(flag.Usage), "certificate") || !strings.Contains(flag.Usage, "report") {
		t.Errorf("--output is described as %q; the run writes reports (unsigned in the Community Edition)", flag.Usage)
	}
}

// A file that holds JSON null is not a report. It decoded to an empty report
// with no error, so `verify-report --unsigned` printed a full empty summary and
// failed only on the validation mode.
func TestAFileOfJSONNullIsNotAReport(t *testing.T) {
	m := newUnsignedMatrix(t)
	path := filepath.Join(m.dir, "null.json")
	if err := os.WriteFile(path, []byte("null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runVerifyStreams("--unsigned", path)
	if err == nil || exitOf(err) != exitCodeInfrastructure {
		t.Fatalf("verify-report --unsigned of null: exit %d (%v), want the file refused with %d", exitOf(err), err, exitCodeInfrastructure)
	}
	if !strings.Contains(err.Error(), "not a CertiStack report") || !strings.Contains(err.Error(), "null") {
		t.Errorf("the refusal %q does not say the file holds JSON null and is not a report", err)
	}
	if stdout != "" {
		t.Errorf("a file that is not a report printed a summary: %q", stdout)
	}
}
